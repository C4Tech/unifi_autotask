#!/usr/bin/python3

# Description:
# This pushes Autotask Configuration Items Hostname and Descriptions to Unifi as an alias based on Mac Address

# Reuirements
# Autotask Requirements: API User, must add a User Defind Field called UniFi Site ID
# Unifi Requirements: 

# Functions needed
# Make sure all UniFi sites have entries in Autotask (UDF)
# From Autotask, pull in all CI with Mac Address and sync to UniFi

import requests
import json
import sys
import time
import datetime
import csv
import macaddress
from pyunifi.controller import Controller
#config file within the same directory
import config
#link to my working library
from atsite import atSite

c = Controller(config.UnifiHost, config.UnifiUsername, config.UnifiPassword, config.UnifiPort, "v5")
at = atSite(config.atHost, config.atUsername, config.atPassword, config.atAPIInterationcode)

# TODO change this to a list so we can loop thorugh them
# TODO create site overdirves. Need to be able to sync Oak Alley Restaurant Devices in the Oak Alley Unifi site. Currently the Unifi Site is set to sync with the foundation or both. 
ignoreProduct = config.atProductID

# Had to rewrite part of the way that pyunifi.controller did queries
# To look to see if Unifi knew of a mac address would raise an error and stop the script.
# This fuction wiill look up the mac, but iqnore errors if it is not in UniFi


def updateUnifiDevice(mac, alias, ci):
	url = c._api_url() + "stat/user/" + mac
	response = c.session.get(url, params=None, headers=c.headers)
	if response.headers.get("X-CSRF-Token"):
		self.headers = {"X-CSRF-Token": response.headers["X-CSRF-Token"]}

	obj = json.loads(response.text)
	if "meta" in obj:
		if obj["meta"]["rc"] != "ok":
			if obj['meta']['msg'] != "api.err.UnknownUser":
#				raise APIError(obj["meta"]["msg"])
				print("Unknown Error: " + obj['meta']['msg'])
	if "data" in obj:
		result = obj["data"]
	else:
		result = obj

	if result:
		# TODO check if each value is NULL
		print("     - Adding " + alias + "   mac: " + mac + " ", end = '')
		c.set_client_alias(mac, alias)
		print("     - finished adding")
		updateATCI(result, ci)
	return result

def updateATCI(result, ci):
	last_seen = str(datetime.datetime.fromtimestamp(int(result[0]['last_seen'])).isoformat()) + ".0000000"
	udf = [{'name': 'UniFi Last Seen', 'value': last_seen}]

	if 'first_seen' in result[0]:
		first_seen = str(datetime.datetime.fromtimestamp(int(result[0]['first_seen'])).isoformat()) + ".0000000"
		udf.append({'name': 'UniFi First Seen', 'value': first_seen},)

	return at.update_ci_udf(ci['id'], ci['productID'], udf)


def main():
	# TODO allow the pulling of more than 1 unifi site id from Autotask
	company_filter_field = "{'op':'eq','field':'isActive','value': '1'},{'op':'noteq','field':'UniFi Site ID','udf': 'true','value': 'None' }"
	for company in at.get_companies(company_filter_field):
		print(company['companyName'])
		for x in company['userDefinedFields']:
			if x['name'] == 'UniFi Site ID':
				c.site_id = x['value']
				break
		ci_filter_field = "{'op': 'and','items': [{'op':'eq','field':'isActive','value': '1'},	{'op':'eq','field':'companyID','value': '" + str(company['id']) + "' },   {'op':'noteq','field':'productID','value': '" + str(ignoreProduct) + "'} ] }"
		cis = at.get_cis(ci_filter_field)

		for ci in cis:
			mac = None
			alias = None
			# Check RMM Fields first
			
			if ci['rmmDeviceAuditMacAddress'] is not None:
				macs = []
				macs_str = str(ci['rmmDeviceAuditMacAddress'])[1:-1]

				if len(macs_str) == 17: 
					macs.append(macs_str)
				else:
					for value in macs_str.split(", "):
						macs.append(value)
				count = 0
				for address in macs:
					try: 
						# TODO need to loop though all mac addresses
						macaddress.MAC(address)
						mac = address
						if ci['rmmDeviceAuditHostname'] is not None:
							if ci['rmmDeviceAuditDescription'] is not None:
								if len(macs) == 1: 
									alias = ci['rmmDeviceAuditHostname'] + " - " + ci['rmmDeviceAuditDescription']
								else:
									alias = ci['rmmDeviceAuditHostname'] + "(" + str(count) + ") - " + ci['rmmDeviceAuditDescription']
							else:
								alias = ci['rmmDeviceAuditHostname'] + "(" + str(count) + ")"
						updateUnifiDevice(mac, alias, ci)

					except ValueError as error:
						pass
					count += 1

			# Check User Defined Fields for Mac Address
			else:
				# Look for "Mac Address" in User Defined Fields
				for i in ci['userDefinedFields']:
					if i['name'] == 'Mac Address':
						if i['value'] is not None:
							try:
								macaddress.MAC(i['value'])
								mac = i['value']
								alias = ci['referenceTitle']
								if ci['referenceTitle'] is not None:
									updateUnifiDevice(mac, alias, ci)
							except ValueError as error:
								pass

main()
