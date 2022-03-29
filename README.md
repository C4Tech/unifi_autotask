# unifi_autotask
Collection of scripts to interact with Unifi and Autotask.

Requirements
	Create a User Defind Field called "UniFi Site ID". Add the UniFi Site
	ID to that field to link that Autotask Company to that UniFi site.



atCI2Unifi.py - 
	Description:
	Is a script that will take Configuration Items from Autotask and create
	a client alias within site in your Unifi Controller. This makes it 
	easier to identify clients in the controller.

	Assumtions:
	ignoreProduct: This is the Product ID within Autotask that the scrip 
	will ignore. I use it to ignore UniFi gear. I will change this to an 
	array at some point.

	The script trys to pull data from RMM fields in Autotask. It will 
	concatanate the Hostname - Description. If these fields are empty, it 
	trys to pull the "ReferenceName" field for the hostname and pull the Mac 
	Address from a UDF Field called "Mac Address" If there are more than 1 
	Mac Addresses in, it will put a number in parentheses after the hostname.
	
unifDevices2at.py - 
	Description:
	Takes UniFi network devices and adds them as Configuration Items within 
	Autotask. 
	Assumtions:
	atCIType4network: This is the CI Type that UniFi devices will be set to 
	within Autotask
	atCICategory: This is the CI Catagory UniFi devices will be set to. 
	atProductID: My plan is to create new product in Autotask for each Unifi 
	model, but currently it's assigned to just one. You have to create the 
	product in Autotask and assign the product id here
	unifi_ignore: These are a list of UniFi sites to ignore.
