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
from datetime import datetime, timedelta
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
# Create an Issue Type UniFi Alerts
atUnifiIssueType = "24"  # Need to move to the conf file
# Create a Sub-Issue Type called Lost Contact
atLostContact = "252"
atCommitError = "259"

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
	
	
def send_unifi_alert_ticket(ticket_title, description, sub_issue, company_id, ci_id):
	filter_fields1 = at.create_filter("eq", "configurationItemID", str(ci_id))
	filter_fields2 = at.create_filter("eq", "subIssueType", sub_issue)
	filter_fields = filter_fields1 + "," + filter_fields2
	ticket = at.create_query("tickets", filter_fields)
	date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000000Z")
	due_date = datetime.utcnow()
	due_date += timedelta(hours = 2)
	# TODO Check if other devices are on within the same network. Add that detail to the ticket
	if not ticket: # checks to see if there are already a ticket and doesn't create one
		# TODO add Due date. Currently expiring tickets by 2 horus before creation date.
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
		return ticket

def lost_contact(alert, unifi_type):
	# TODO for each "Lost_Contact" event, we should check if the router is up. If the router is down, then it's the site that is down
	# and we shouldn't make multiple tickets. 
	# On the other hand, it the Gateway looses contact for some reason other than internet and other devices actually go down, we wouldn't get alerted.

	device = check_get_device_stat(alert[unifi_type])
	if device:
		if device[0]['state'] != 1:
			# TODO One possible fix is to power cycle the switch port if the devices is on a POE switch and powered by that switch.
			# TODO Most of these are solved by sending a set inform. Need to work on that.
			ci = at.get_ci_by_serial(device[0]['serial'])[0]
			if unifi_type == 'gw':
				ticket_title = "UniFi Alert: Lost contact with the gateway"
			else:
				ticket_title = "UniFi Alert: Lost contact with the UniFi device"
			description = "Message from the UniFi Controller is: " + alert['msg'] + "\n\nThis message will auto clear if the device checks back in"

			send_unifi_alert_ticket(ticket_title, description, atLostContact, ci['companyID'], ci['id'])
	archive_alert(alert['_id'])

def commit_error(alert, unifi_type):
	device = check_get_device_stat(alert[unifi_type])
	ci = at.get_ci_by_serial(device[0]['serial'])[0]
	ticket_title = "UniFi Alert: Commit Error"
	description = "Message from the UniFi Controller is: " + alert['msg'] + "\n\nMore Information - Commit Error was: " + alert['commit_errors'] + "\n\nPlease not this message will not auto clear"
	send_unifi_alert_ticket(ticket_title, description, atCommitError, ci['companyID'], ci['id'])
	print("sent in a ticket for " + ci['referenceTitle'])

	
def check_alerts(site):
	# TODO Probably a better way is the pull in all devices from the unifi site and compare, instead of looking up the device for each alert.
	alerts = c.get_alerts_unarchived()
	print(site['desc'])
	for alert in alerts:
		if alert['key'] == "EVT_GW_Lost_Contact":
			lost_contact(alert, 'gw')
		elif alert['key'] == "EVT_AP_Lost_Contact":
			lost_contact(alert, 'ap')
		elif alert['key'] == "EVT_SW_Lost_Contact":
			lost_contact(alert, 'sw')
		elif alert['key'] == "EVT_LTE_Lost_Contact":
			lost_contact(alert, 'dev')

		elif alert['key'] == "EVT_GW_CommitError":
			commit_error(alert, 'gw')
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
					print(alert['msg'])
			else:
				archive_alert(alert['_id'])
		elif alert['key'] == "EVT_AP_DetectRogueAP":
			# TODO Need to create an ignore list
			print(" - Rouge AP Detected")
			print(alert['msg'])
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
			print(alert['msg'])
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
			print(alert['msg'])
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
				# TODO check if there is a ticket and update the ticket if it's a new Threshold
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
			print(alert['msg'])
		else:
			print(" - Something else: " + alert['key'])
			print(alert)

def close_ticket(ticket):
	# TODO add a note to the ticket	

    params = {
        'id': ticket['id'],
        'status': "5",
    }
    return at._api_update("Tickets", params)

def clear_fixed_tickets(site, company):
	filter_fields = at.create_filter("noteq", "status", "5") # Not equial Closed ticket
	filter_fields = filter_fields + "," + at.create_filter("eq", "subIssueType", "252") # UniFi subisseu Lost Contact
	filter_fields = filter_fields + "," + at.create_filter("eq", "companyID", str(company[0]['id'])) # Autotask Company
	tickets = at.create_query("tickets", filter_fields)
	for ticket in tickets:
		if ticket['configurationItemID'] is not None:
			at_device = at.get_ci_by_id(str(ticket['configurationItemID']))
			unifi_device = check_get_device_stat(at_device[0]['serialNumber'])
			if unifi_device:
				if unifi_device[0]['state'] == 1:
					close_ticket(ticket)

def main():
	for site in c.get_sites():
		if site['desc'] not in unifi_ignore:
			# TODO allow the pulling of more than 1 unifi site id from Autotask
			c.site_id = site['name']
			filter_field = at.create_filter("eq", "UniFi Site ID", site['name'], 1)
			company = at.get_companies(filter_field)
			if not company:
				print(site['desc'] + " doesn't have a UniFi Site ID. Please add " + site['name'] + " to the Autotask Company's UDF field")
			else:
				check_alerts(site)
				clear_fixed_tickets(site, company)

main()

#print(at.get_ticket_by_number("T20220427.0045"))

