#!/usr/bin/python3

# Description:
# This syncs UniFi Devices to Autotask and syncs Autotask Configureation Items as "Configured Clients" in Unifi

# Requirements
# Autotask Requirements  - Must add a User Defind Field called UniFi Site ID
# API User has to have "edit Protected Data" permissions to edit UDFs

# Functions needed
# Make sure all UniFi sites have entries in Autotask (UDF)

# Ideas
# Send alerts from Unifi to AT as tickets
# See if we can pull the icons for Unifi devices and send that to AT

# TODO check for UniFi devices in AT that are not in the UniFi controller and deactivate them.
# TODO check if the device is added to the correct company.


import requests
import json
import sys
import time
import re
from datetime import datetime, timedelta
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
atUnifiIssueType = "24"  # Need to move to the conf file
atUnifiLTESubscriptionUnknown = 261
atUnifiLTEWeak = 262
atUnifiMultiAlert = 263
unifiAlertThreashold = 5




# Names in Unifi to ignore. Maybe switch this over to Site ID, so if the name changes, they don't pop out of this list.
unifi_ignore = config.unifi_ignore


def get_unifi_devices():
	""" Return a list of all devices """
	return c._api_read("stat/device/")
	
def add_ticket_note(ticket_id):
	print("function")	

# This is from unifiAlert2at.py We should make a common lib
def send_unifi_alert_ticket(ticket_title, description, sub_issue, company_id, ci_id):
	# TODO Check for other tickets open for the same device. Add those ticket numbers in the description of the new ticket. Update the otehr ticket with a note about the creation of this new ticket

	filter_fields1 = at.create_filter("eq", "configurationItemID", str(ci_id))
	filter_fields2 = at.create_filter("eq", "subIssueType", sub_issue)
	filter_fields = filter_fields1 + "," + filter_fields2
	ticket = at.create_query("tickets", filter_fields)
	date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000000Z")
	due_date = datetime.utcnow()
	due_date += timedelta(hours = 2)
	# TODO Check if other devices are on within the same network. Add that detail to the ticket
	if not ticket: # checks to see if there are already a ticket and doesn't create one
		params = {
			'companyID': company_id,
			'configurationItemID': ci_id,
			'createDate': date,
			'dueDateTime': due_date,
			'description': description,
			'issueType': atUnifiIssueType,
			'subIssueType': sub_issue,
			'priority': "1",
			'source': "8",
			'status': "1",
			'queueID': "8",
			'title': ticket_title
		}
		return at._api_write("Tickets", params)
	else:
		# There is a ticket already created
		# TODO Add the new information to the ticekt once a day.
		last_activity = datetime.strptime(ticket['lastActivityDate'],'%Y-%m-%dT%H:%M:%SZ')
		if last_activity <= (date - timedelta(days = 1)):
			print("no activity yesterday")
		else:
			print("There was activity yesterday")
		return ticket

def remove_old_alerts(alerts):
	date = datetime.utcnow()
	date -= timedelta(days = 1)
	old_alerts = []
	for alert in alerts:
		alert_date = datetime.strptime(alert['datetime'],'%Y-%m-%dT%H:%M:%SZ')
		if alert_date < date:
			old_alerts.append(alert)
	for old_alert in old_alerts:
		alerts.remove(old_alert)
	return alerts


def check_alerts(alerts, mac, cid, ci_id):
	x = 0
	date = datetime.utcnow()
	date -= timedelta(days = 1)
	description = ""
	unifi_mac = ""

	for alert in alerts:
		if alert['key'] == "EVT_GW_Lost_Contact":
			unifi_mac = alert['gw']
		elif alert['key'] == "EVT_AP_Lost_Contact":
			unifi_mac = alert['ap']
		elif alert['key'] == "EVT_SW_Lost_Contact":
			unifi_mac = alert['sw']
		elif alert['key'] == "EVT_LTE_Lost_Contact":
			unifi_mac = alert['dev']
		elif alert['key'] == "EVT_GW_CommitError":
			unifi_mac = alert['gw']
		elif alert['key'] == "EVT_GW_RestartedUnknown":
			unifi_mac = alert['gw']
		elif alert['key'] == "EVT_GW_WANTransition":
			unifi_mac = alert['gw']
		elif alert['key'] == "EVT_AP_DetectRogueAP": # We don't want to track this
			break
		elif alert['key'] == "EVT_AP_RadarDetected": # We don't want to track this
			break
		elif alert['key'] == "EVT_SW_StpPortBlocking":
			unifi_mac = alert['sw']
		elif alert['key'] == "EVT_SW_RestartedUnknown":
			unifi_mac = alert['sw']
		elif alert['key'] == "EVT_LTE_HardLimitUsed":
			unifi_mac = alert['dev']
		elif alert['key'] == "EVT_LTE_Threshold":
			unifi_mac = alert['dev']
		else:
			# TODO Create ticket with Information on the new alert so I can update the script
			print(alert)
		if mac == unifi_mac:
			description = description + alert['datetime'] + " - alert: " + alert['msg'] + "\n\n"
			x += 1
			
	if x > int(unifiAlertThreashold):
		ticket_title = "UniFi Alert: Device had  " + str(x) + " alerts within a 24 hour period"
		print("          - Creating ticket for " + unifi_mac)
		sub_issue = str(atUnifiMultiAlert)
		send_unifi_alert_ticket(ticket_title, description, sub_issue, cid, ci_id)

def remove_admin(expect):
	for site in c.get_sites():
		if site['name'] != expect:
			c.site_id = site["name"]
#			params = ({"cmd": "get-admins"})
#			print(c._api_write("cmd/sitemgr", params=params))
			params = {"admin":"61e9a517f1dce207e4c7b501","cmd":"revoke-admin"}
			print(site['desc'])
			print(c._api_write("cmd/sitemgr", params=params))


def unifi2at():
	for site in c.get_sites():
		if site['desc'] not in unifi_ignore:
			# TODO allow the pulling of more than 1 unifi site id from Autotask
			filter_field = at.create_filter("eq", "UniFi Site ID", site['name'], 1)
			company = at.get_companies(filter_field)
			if not company:

				print(site['desc'] + " doesn't have a UniFi Site ID. Please add " + site['name'] + " to the Autotask Company's UDF field to allow syncing")
			else:
				print(site['desc'] + " is syncing")
				c.site_id = site['name']
				c.devices = get_unifi_devices()
				alerts = remove_old_alerts(c.get_alerts())
				print("     Number of alerts: " + str(len(alerts)))
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
					ip = device['ip']
					if 'serial' in device.keys():
						serial = device['serial']
					else:
						serial = None
					model = device['model']
					mac = device['mac']
					if device['state'] == 1:
						last_seen = datetime.utcnow().strftime("%Y-%m-%d")

					#last_seen doesn't appear to be reliable. Check later
#					last_seen = datetime.fromtimestamp(device['last_seen']).strftime("%Y-%m-%d")

					udf = [
						    {'name': 'Name', 'value': name},
						    {'name': 'AEM_Description', 'value': name},
						    {'name': 'AEM_Manufacturer', 'value': "UniFi"},
						    {'name': 'AEM_Model', 'value': model},
						    {'name': 'IP Address', 'value': ip},
						    {'name': 'Mac Address', 'value': mac},
						    {'name': 'Make & Model', 'value': "UniFi " + model},
# Need to append or something if first_seen as a value
 #  						    {'name': 'UniFi First Seen', 'value': first_seen},
  						    {'name': 'UniFi Last Seen', 'value': last_seen},
					]
					if serial is not None:
						return_value = at.add_ci(ci_cat, cid, ci_type, pid, name, ip, serial, udf)
						if len(alerts) > 0 :
							check_alerts(alerts, mac, cid, return_value['itemId'])
						ulte = ['ULTE','ULTEPUS','ULTEPEU']
						if device['model'] in ulte:
							if device['lte_subscription_status'] == 'unknown':
								ticket_title = "UniFi Alert: LTE subscription Issue"
								description = "LTE device reports that it's subscription status is unknown" 
								sub_issue = atUnifiLTESubscriptionUnknown
								send_unifi_alert_ticket(ticket_title, description, str(sub_issue), cid, return_value['itemId'])
							signal = re.findall('[0-9]+', device['lte_signal'])
							if int(signal[0]) <= 2:
								ticket_title = "UniFi Alert: LTE Signal is weak"
								description = "LTE device reports that it's signal is weak - " + device['lte_signal']
								sub_issue = str(atUnifiLTEWeak)
								send_unifi_alert_ticket(ticket_title, description, sub_issue, cid, return_value['itemId'])



#'Good signal strength (3)'
#Very strong signal strength (5)



#						# If router is offline, send alert to AT			
#						routers = ['UGW3','UGW4','UGWHD4','UGWXG','UXGPRO']
#						if device['model'] in routers:
#							if device['state'] != 1:
#								at.send_alert_ticket(cid, return_value['itemId'])

unifi2at()



