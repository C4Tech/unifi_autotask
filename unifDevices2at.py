#!/usr/bin/python3.9

# Description:
# This syncs UniFi Devices to Autotask and syncs Autotask Configureation Items as "Configured Clients" in Unifi

# Reuirements
# Autotask Requirements  - Must add a User Defind Field called UniFi Site ID
# API User has to have "edit Protected Data" permissions to edit UDFs

# Functions needed
# Make sure all UniFi sites have entries in Autotask (UDF)

# Ideas
# Send alerts from Unifi to AT as tickets
# See if we can pull the icons for Unifi devices and send that to AT

# TODO check for UniFi devices in AT that are not in the UniFi controller and deactivate them.


import requests
import json
import sys
import time
from pyunifi.controller import Controller
#config file within the same directory
import config
#link to my working library
from atsite import atSite

c = Controller(config.UnifiHost, config.UnifiUsername, config.UnifiPassword, config.UnifiPort, "v5")
at = atSite(config.atHost, config.atUsername, config.atPassword, config.atAPIInterationcode)

atCIType4network = config.atCIType4network
atCICategory = config.atCICategory
atProductID = config.atProductID

# Names in Unifi to ignore. Maybe switch this over to Site ID, so if the name changes, they don't pop out of this list.
unifi_ignore = config.unifi_ignore


def get_unifi_devices():
	""" Return a list of all devices """
	return c._api_read("stat/device/")

def unifi2at():
	for site in c.get_sites():
		if site['desc'] not in unifi_ignore:
			# TODO allow the pulling of more than 1 unifi site id from Autotask
			filter_field = at.create_filter("eq", "UniFi Site ID", site['name'], 1)
			company = at.get_companies(filter_field)
			if not company:

				print(site['desc'] + " doesn't have a UniFi Site ID. Please add " + site['name'] + " to the Autotask Company's UDF field to allow syncing")
			else:
#				print(site['desc'] + " in syncing")
				c.site_id = site['name']
				c.devices = get_unifi_devices()

				# TODO we will use a UDF in AT with a lable for unifi site ID. We should output a list of sites with no lable in AT. Unifi Site Name and Unifi Site ID.

				# loop through devices and check if it exsit in AT. If it does update AT's information with Unifi. If not, create a new CI in AT
				for device in c.devices:
					# TODO Currently using a default product. We should add a fuction to check if the unifi model is a product in AT, if not add it
					# TODO Skip devices with pending aduption as a status. Maybe create a ticket
					ci_cat = atCICategory # "Unifi Controller Devices" CI Catagory in AT
					ci_type = atCIType4network # "Networking Devices" CI Type in AT
					pid = atProductID # Generic Unifi Product in AT
					cid = company[0]['id']
					if 'name' in device.keys():
						name = device['name']
					else:
						name = "Unnamed UniFi Device"
#					print("--Syncing device: " + name)
					ip = device['ip']
					if 'serial' in device.keys():
						serial = device['serial']
					else:
						serial = None
					did = device['_id']
					model = device['model']
					mac = device['mac']
					# Currently udf is not working.
					# TODO change udfs to be defined in the conf file, since there is no way in advanced to know what UDFs different MSPs are using. 
					# Maybe have this layout in the config file and have them define it by the UniFi key
					udf = [
						    {'name': 'Name', 'value': name},
						    {'name': 'AEM_Description', 'value': "name"},
						    {'name': 'AEM_DeviceID', 'value': did},
						    {'name': 'AEM_Manufacturer', 'value': "UniFi"},
						    {'name': 'AEM_Model', 'value': model},
						    {'name': 'IP Address', 'value': ip},
						    {'name': 'Mac Address', 'value': mac},
						    {'name': 'Make & Model', 'value': "UniFi " + model},

					]
					if serial is not None:
						return_value = at.add_ci(ci_cat, cid, ci_type, pid, name, ip, serial, udf)
						time.sleep(1) # trying to be a little friendlier to Autotask
#					else:
#						print("--  NOT SYNCING no serial")
#					print("    Device synced " + name + " " + model + " " + ip + " " + mac)
#					print(return_value)
				time.sleep(1) # trying to be a little friendlier to my UniFi Controller

unifi2at()

