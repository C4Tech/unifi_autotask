#!/usr/bin/python3

# Description:
# Deal with UniFi alerts

# Reuirements
# Autotask Requirements  - Must add a User Defind Field called UniFi Site ID
# API User has to have "edit Protected Data" permissions to edit UDFs

# TODO check for UniFi devices in AT that are not in the UniFi controller and deactivate them.


import requests
import json
import sys
import time
from datetime import datetime
import dateutil.parser
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

def check_get_device_stat(mac):
	url = c._api_url() + "stat/device/" + mac
	response = c.session.get(url, params=None, headers=c.headers)
	if response.headers.get("X-CSRF-Token"):
		self.headers = {"X-CSRF-Token": response.headers["X-CSRF-Token"]}

	obj = json.loads(response.text)
	if "meta" in obj:
		if obj["meta"]["rc"] != "ok":
			if obj['meta']['msg'] != "api.err.UnknownDevice":
#				raise APIError(obj["meta"]["msg"])
				print("Unknown Device: " + obj['meta']['msg'])
	if "data" in obj:
		result = obj["data"]
	else:
		result = obj

	return result



def archive_alert(alert_id):
	params = {'_id': alert_id}
	return c._run_command('archive-alarm', params, mgr="evtmgr")
	
def main():
	for site in c.get_sites():
		if site['desc'] not in unifi_ignore:
			# TODO allow the pulling of more than 1 unifi site id from Autotask
			filter_field = at.create_filter("eq", "UniFi Site ID", site['name'], 1)
			company = at.get_companies(filter_field)
			if not company:
				print(site['desc'] + " doesn't have a UniFi Site ID. Please add " + site['name'] + " to the Autotask Company's UDF field")
			else:
				# TODO Probably a better way is the pull in all devices from the  unifi site and compare, instead of looking up the device for each alert.
				# TODO Probably want to check if I created a ticket once, instead of for ever alert
				c.site_id = site['name']
				alerts = c.get_alerts_unarchived()
				print(site['desc'])
				for alert in alerts:
					# Gateway Down
					if alert['key'] == "EVT_GW_Lost_Contact":
						device = check_get_device_stat(alert['gw'])
						if device:
							if device[0]['state'] != 1:
								ci = at.get_ci_by_serial(device[0]['serial]'])[0]
								at.send_alert_ticket(ci['companyID'], ci['id'])
								print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
						archive_alert(alert['_id'])
					elif alert['key'] == "EVT_GW_CommitError":
						print(" - Router Commit Error")
					elif alert['key'] == "EVT_GW_RestartedUnknown":
						# create ticket if X number of this alert is over X period of time
						print(" - Router restart Unknown")
					#WAN Failover event
					elif alert['key'] == "EVT_GW_WANTransition":
						device = check_get_device_stat(alert['gw'])
						# I think I can match uplink to wan1 ip
						alert_date = dateutil.parser.isoparse(alert['datetime'])
						if alert_date.strftime("%Y-%m-%d") == datetime.today().strftime("%Y-%m-%d"):
							if device:
								if device[0]['wan1']['ip'] != device[0]['uplink']['ip']:
									ci = at.get_ci_by_serial(device[0]['serial'])[0]
									ticket_title = "Gateway failover event"
									description = "Message from UniFi Controller is: " + alert['msg']
									at.send_generic_alert_ticket(ticket_title, description, ci['companyID'], ci['id'])
									print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
									archive_alert(alert['_id'])				
								else:
									archive_alert(alert['_id'])
							else:
								print("EVT_GW_WANTransition - not device was returned")
						else:
							archive_alert(alert['_id'])
					# AP Down
					elif alert['key'] == "EVT_AP_Lost_Contact":
						device = check_get_device_stat(alert['ap'])
						if device:
							if device[0]['state'] != 1:
								# TODO One possible fix is to power cycle the switch port if the WAP is on a POE switch.
								ci = at.get_ci_by_serial(device[0]['serial'])[0]
								at.send_alert_ticket(ci['companyID'], ci['id'])
								print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
						archive_alert(alert['_id'])
					elif alert['key'] == "EVT_AP_DetectRogueAP":
						# TODO Need to create an ignore list
						print(" - Rouge AP Detected")
#						device = check_get_device_stat(alert['ap'])
#						alert_date = dateutil.parser.isoparse(alert['datetime'])
#						if alert_date.strftime("%Y-%m-%d") == datetime.today().strftime("%Y-%m-%d"):
#							if device:
#								ci = at.get_ci_by_serial(device[0]['serial'])[0]
#								ticket_title = "Rouge AP detected"
#								description = "Message from UniFi Controller is: " + alert['msg']
#								at.send_generic_alert_ticket(ticket_title, description, ci['companyID'], ci['id'])
#								print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
#								archive_alert(alert['_id'])
#						else:
#							archive_alert(alert['_id'])
					elif alert['key'] == "EVT_AP_RadarDetected":
						print(" - AP - Radar Detected")
					# Switch Down
					elif alert['key'] == "EVT_SW_Lost_Contact":
						device = check_get_device_stat(alert['sw'])
						if device:
							if device[0]['state'] != 1:
								ci = at.get_ci_by_serial(device[0]['serial'])[0]
								at.send_alert_ticket(ci['companyID'], ci['id'])
								print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
						archive_alert(alert['_id'])
					elif alert['key'] == "EVT_SW_StpPortBlocking":
						device = check_get_device_stat(alert['sw'])
						port = int(alert['port']) -1
						if device[0]['port_table'][port]['stp_state'] != 'forwarding':
							ci = at.get_ci_by_serial(device[0]['serial'])[0]
							ticket_title = "Switch has an STP Event"
							description = "Message from UniFi Controller is: " + alert['msg']
							at.send_generic_alert_ticket(ticket_title, description, ci['companyID'], ci['id'])
							print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
							archive_alert(alert['_id'])
						elif device[0]['port_table'][port]['stp_state'] != 'disabled':
							archive_alert(alert['_id'])
						else:
							archive_alert(alert['_id'])
					elif alert['key'] == "EVT_SW_RestartedUnknown":
						print(" - Switch - restarted Unknown")
					elif alert['key'] == "EVT_LTE_HardLimitUsed":
						# Link this to the Threshold ticket, but change status to new and prioirty to Crital
						device = check_get_device_stat(alert['dev'])
						alert_date = dateutil.parser.isoparse(alert['datetime'])
						if alert_date.month == datetime.now().month:
							# TODO check if there is a ticket and append the ticket with this new information. Change Title to mention the hard limit.
							# Change Priority Critical amd status to new
							device = check_get_device_stat(alert['dev'])
							ci = at.get_ci_by_serial(device[0]['serial'])[0]
							ticket_title = "LTE Hard Limit reached"
							description = "Message from UniFi Controller is: " + alert['msg']
							at.send_generic_alert_ticket(ticket_title, description, ci['companyID'], ci['id'])
							print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
							archive_alert(alert['_id'])				
					elif alert['key'] == "EVT_LTE_Threshold":
						alert_date = dateutil.parser.isoparse(alert['datetime'])
						if alert_date.month == datetime.now().month:
							# TODO check if there is a ticket and updat the ticket if it's a new Threshold
							# create ticket for first threshold. Append ticket for the next thresholds. Change status to "new"
							device = check_get_device_stat(alert['dev'])
							ci = at.get_ci_by_serial(device[0]['serial'])[0]
							ticket_title = "LTE Threshold reached"
							description = "Message from UniFi Controller is: " + alert['msg']
							at.send_generic_alert_ticket(ticket_title, description, ci['companyID'], ci['id'])
							print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
							archive_alert(alert['_id'])					
						else:
							archive_alert(alert['_id'])
					elif alert['key'] == "EVT_IPS_IpsAlert":
						print(" - IPS Alert")
					else:
						print(" - Something else: " + alert['key'])
						sys.exit()

main()

#c.site_id = 'fie3nkrs'
#print(check_get_device_stat("f0:9f:c2:c3:68:24"))

# Troubleshooting ticket creation
#ticket = at.send_alert_ticket(313, 1596)
#print(ticket)

#filter_fields = at.create_filter("eq", "ticketNumber", "T20220410.0007", udf = None)
#ticket = at.create_query("tickets", filter_fields)
#print(ticket)
