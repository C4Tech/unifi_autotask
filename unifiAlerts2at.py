#!/usr/bin/python3

# Description:
# Creates Autotask Tickets for UniFi alerts

# Reuirements
# API User has to have "edit Protected Data" permissions to edit UDFs
# TODO create an onboarding script
# Needed to create the Following Autotask UDFs for these scripts use
# Companies
#  Name         			| Type					| Sort Oder	|
#  UniFi Site ID			| Text (Multi Line)		| 2			| This is where the primary company where the site goes. CIs for UniFi devices will go here.
#  UniFi Subsite ID			| Text (Multi Line)		| 2			| This is where a seconardy site will go. If you want these CIs to show up as a configured client in a site, put that UniFi ID here
#
# Configuration Items
#  Name						| Type					| Sort Oder
#  UniFi Alerts Ignore list	| Text (Multi Line)		| 3
#  UniFi First Seen			| Date					| 2
#  UniFi Last Seen			| Date					| 2
#
# Needed Service Desk Issue Types
# Issue Type Name: UniFi Alerts
# All Subissues are associated with the "Monitoring Alert" Queue
#  Issue Type Name:
#  Commit Error
#  Detect Rogue AP
#  IPS Alert
#  Lost Contact
#  LTE Hard Limit Used
#  LTE Subscription Unknown
#  LTE Threshold
#  LTE Weak Signal
#  LTE Muliple Alerts
#  Radar Detected
#  STP Port Blocking
#  WAN Transition
#  ZZZ Unknown Event


# TODO Create a report on all site-devices that have entries in the ignroe
# TODO check for UniFi devices in AT that are not in the UniFi controller and deactivate them.
# TODO It looks like someone setup a device to the wrong client in Autotask and this confused the script. It was able to create an alert ticket, but not close it because it was on the wrong client.
# TODO create a search for device script and maybe connect it to slack
# TODO Alert in Slack or as a ticket if the script cannot log into the controller

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
atWANTransition = "264"
atRougeAp = "254"
atStpBlocking = "260"
atLteHardLimitUsed = "251"
atLteThreshold = "253"
atUnknownAlert = "258"

# Names in Unifi to ignore. Maybe switch this over to Site ID, so if the name changes, they don't pop out of this list.
unifi_ignore = config.unifi_ignore

def check_get_device_stat(mac):
	url = c._api_url() + "stat/device/" + mac
	response = c.session.get(url, params=None, headers=c.headers)
	if response.headers.get("X-CSRF-Token"):
		c.headers = {"X-CSRF-Token": response.headers["X-CSRF-Token"]}

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
			description = "Message from the UniFi Controller is: \n" + alert['datetime'] + " - " + alert['msg'] + "\n\nThis message will auto clear if the device checks back in.\n\n If we susspect that this issue can be resolved by sending a set inform, please assign the ticket to Jeff so he can attempt an autoheal script on it"

			send_unifi_alert_ticket(ticket_title, description, atLostContact, ci['companyID'], ci['id'])
	archive_alert(alert['_id'])

def commit_error(alert, unifi_type):
	device = check_get_device_stat(alert[unifi_type])
	ci = at.get_ci_by_serial(device[0]['serial'])[0]
	ticket_title = "UniFi Alert: Commit Error"
	description = "Message from the UniFi Controller is: " + alert['msg'] + "\n\nMore Information - Commit Error was: " + alert['commit_errors'] + "\n\nPlease not this message will not auto clear"
	send_unifi_alert_ticket(ticket_title, description, atCommitError, ci['companyID'], ci['id'])
	print("sent in a ticket for " + ci['referenceTitle'])
	archive_alert(alert['_id'])

def wan_transition(alert):
	device = check_get_device_stat(alert['gw'])
	# I think I can match uplink to wan1 ip
	alert_date = dateutil.parser.isoparse(alert['datetime'])
	if alert_date.strftime("%Y-%m-%d") == datetime.today().strftime("%Y-%m-%d"):
		if device:
			if device[0]['wan1']['ip'] != device[0]['uplink']['ip']:
				ci = at.get_ci_by_serial(device[0]['serial'])[0]
				ticket_title = "Gateway failover event"
				description = "Message from the UniFi Controller is: \n" + alert['datetime'] + " - " + alert['msg']
				send_unifi_alert_ticket(ticket_title, description, atWANTransition, ci['companyID'], ci['id'])
				print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
				archive_alert(alert['_id'])				
			else:
				archive_alert(alert['_id'])
		else:
			print("EVT_GW_WANTransition - no device was returned")
			print(alert['msg'])
	else:
		archive_alert(alert['_id'])

def rouge_ap(alert):
	device = check_get_device_stat(alert['ap'])
	alert_date = dateutil.parser.isoparse(alert['datetime'])
	if alert_date.strftime("%Y-%m-%d") == datetime.today().strftime("%Y-%m-%d"):
		if device:
			ci = at.get_ci_by_serial(device[0]['serial'])[0]
			ticket_title = "Rogue AP Detected"
			description = "Message from UniFi Controller is: \n" + alert['datetime'] + " - " + alert['msg'] + "\n\n\n\nPlease Note: This message will not autoclear.\nIf this is a know Access Point and you wish to stop getting these alerts.\n * Consult with a senior tech!\n * Log into the UniFi Controller. \n * Make sure you are using 'Legacy Mode'. \n * Under 'Insight' on the left \n * pick 'Neighboring Access Point' in the upper right hand drop down list\n * Look for a AP that has a red dot in the 'Rouge' Column \n * On the far right of that row, when you hoover over it, the words 'Mark as known' will appear. Pick it. \n * Archive all Rogue AP alerts under 'Alerts'"

			send_unifi_alert_ticket(ticket_title, description, atRougeAp, ci['companyID'], ci['id'])
			print("sent in a ticket for " + ci['referenceTitle'])
			archive_alert(alert['_id'])

	else:
		archive_alert(alert['_id'])

# TODO Figure out what to do with these
def radar_detected(alert):
	print(" - AP - Radar Detected")
	print(alert['msg'])

def stp_blocking(alert):
	device = check_get_device_stat(alert['sw'])
	port = int(alert['port']) -1
	if device[0]['port_table'][port]['stp_state'] != 'forwarding':
		ci = at.get_ci_by_serial(device[0]['serial'])[0]
		ticket_title = "Switch has an STP Event"
		description = "Message from UniFi Controller is: " + alert['msg']
		send_unifi_alert_ticket(ticket_title, description, atStpBlocking, ci['companyID'], ci['id'])
		print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
		archive_alert(alert['_id'])
	elif device[0]['port_table'][port]['stp_state'] != 'disabled':
		archive_alert(alert['_id'])
	else:
		archive_alert(alert['_id'])

def lte_hard_limit_used(alert):
	# TODO Link this to the Threshold ticket, but change status to new and prioirty to Crital
	device = check_get_device_stat(alert['dev'])
	alert_date = dateutil.parser.isoparse(alert['datetime'])
	if alert_date.month == datetime.now().month:
		device = check_get_device_stat(alert['dev'])
		ci = at.get_ci_by_serial(device[0]['serial'])[0]
		ticket_title = "LTE Hard Limit reached"
		description = "Message from UniFi Controller is: " + alert['msg']
		send_unifi_alert_ticket(ticket_title, description, atLteHardLimitUsed, ci['companyID'], ci['id'])
		print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
		archive_alert(alert['_id'])				

def lte_threshold():
	alert_date = dateutil.parser.isoparse(alert['datetime'])
	if alert_date.month == datetime.now().month:
		# TODO check if there is a ticket and update the ticket if it's a new Threshold
		# create ticket for first threshold. Append ticket for the next thresholds. Change status to "new"
		device = check_get_device_stat(alert['dev'])
		ci = at.get_ci_by_serial(device[0]['serial'])[0]
		ticket_title = "LTE Threshold reached"
		description = "Message from UniFi Controller is: " + alert['msg']
		send_unifi_alert_ticket(ticket_title, description, atLteThreshold, ci['companyID'], ci['id'])
		print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])
		archive_alert(alert['_id'])					
	else:
		archive_alert(alert['_id'])

def ipsAlert(alert):
	# TODO Create ticket for jeff to do something
	print(" - IPS Alert")
	print(alert['msg'])


def unknown_alert(alert):
	alert_date = dateutil.parser.isoparse(alert['datetime'])
	if alert_date.month == datetime.now().month:
		device = check_get_device_stat(alert['dev'])
		ci = at.get_ci_by_serial(device[0]['serial'])[0]
		ticket_title = "Unknown UniFi Alert"
		description = "Since this is an alert that I have not seen before, a tech will have to assess how urgent this is. IF it is not urgent, please assign to Jeff, so he can update the script to detect these alerts in the furture. Please no not archive the alert!\n\n\nMessage from UniFi Controller is: " + alert['msg'] + "\nAlert Key is: " + alert['key'] + "\n\nAlert was not Archived."
		send_unifi_alert_ticket(ticket_title, description, atUnknownAlert, ci['companyID'], ci['id'])
		print("sent in a ticket for " + site['desc'] + " " + ci['referenceTitle'])

def check_unarchived_alerts(site):
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
		elif alert['key'] == "EVT_GW_RestartedUnknown": # we run a different script to detect if there are multiple alerts for the same device.
			archive_alert(alert['_id'])	
		elif alert['key'] == "EVT_GW_WANTransition": # WAN Failover event
			wan_transition(alert)
		elif alert['key'] == "EVT_AP_DetectRogueAP":
			rouge_ap(alert)
		elif alert['key'] == "EVT_AP_RadarDetected":
			radar_detected(alert)
		elif alert['key'] == "EVT_SW_StpPortBlocking":
			stp_blocking(alert)
		elif alert['key'] == "EVT_SW_RestartedUnknown":
			archive_alert(alert['_id'])	
		elif alert['key'] == "EVT_LTE_HardLimitUsed":
			lte_hard_limit_used(alert)
		elif alert['key'] == "EVT_LTE_Threshold":
			lte_threshold(alert)
		elif alert['key'] == "EVT_IPS_IpsAlert":
			ipsAlert(alert)
		else:
			unknown_alert(alert)


def close_ticket(ticket):
	# TODO add a note to the ticket	

    params = {
        'id': ticket['id'],
        'status': "5",
    }
    return at._api_update("Tickets", params)

def clear_fixed_tickets(site, company):
	# Fix Lost Contact tickets if device comes back on
	filter_fields = at.create_filter("noteq", "status", "5") # Not equial Closed ticket
	filter_fields = filter_fields + "," + at.create_filter("eq", "subIssueType", atLostContact) # UniFi subisseu Lost Contact
	filter_fields = filter_fields + "," + at.create_filter("eq", "companyID", str(company[0]['id'])) # Autotask Company
	tickets = at.create_query("tickets", filter_fields)
	for ticket in tickets:
		if ticket['configurationItemID'] is not None:
			at_device = at.get_ci_by_id(str(ticket['configurationItemID']))
			unifi_device = check_get_device_stat(at_device[0]['serialNumber'])
			if unifi_device:
				if unifi_device[0]['state'] == 1:
					close_ticket(ticket)
	# Fix WAN Transition tickets if Primary WAN comes back up
	filter_fields = at.create_filter("noteq", "status", "5") # Not equial Closed ticket
	filter_fields = filter_fields + "," + at.create_filter("eq", "subIssueType", atWANTransition) # UniFi subisseu Lost Contact
	filter_fields = filter_fields + "," + at.create_filter("eq", "companyID", str(company[0]['id'])) # Autotask Company
	tickets = at.create_query("tickets", filter_fields)
	for ticket in tickets:
		if ticket['configurationItemID'] is not None:
			at_device = at.get_ci_by_id(str(ticket['configurationItemID']))
			unifi_device = check_get_device_stat(at_device[0]['serialNumber'])
			if unifi_device:
				if unifi_device[0]['wan1']['ip'] == unifi_device[0]['uplink']['ip']:
					close_ticket(ticket)
def main():
	# Loop through all sites in the UniFi Controller
	for site in c.get_sites():
		if site['desc'] not in unifi_ignore:
			c.site_id = site['name']
			filter_field = at.create_filter("contains", "UniFi Site ID", site['name'], 1)
			company = at.get_companies(filter_field)
	
			if not company:
				print(site['desc'] + " doesn't have a UniFi Site ID. Please add " + site['name'] + " to the Autotask Company's UDF field")
			else:
				check_unarchived_alerts(site) 
				clear_fixed_tickets(site, company)

main()
#c.site_id = "n5jpgiba"
#print(check_get_device_stat("fc:ec:da:49:e4:8f"))
#print(c.get_sysinfo())
#print(c.get_healthinfo())
#print(c.get_setting())

#print(at.get_ticket_by_number("T20220504.0039"))

