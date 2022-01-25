import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta
from time import sleep
import json
from urllib.request import urlopen, URLError, HTTPError, Request

from config import HOOK_URL, ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE

APPROVAL_HOOK_URL = HOOK_URL

time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
delta = (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S") # AWS CloudWatch Event is triggered every 10 mins, where as here the delta looks back 11 minutes to have some overlap so that no event is missed due to time differences in 'seconds'

print("Current = {}\nDelta = {}".format(time, delta))

def assume_role(session, aws_account_number, role_name):
	resp = session.client('sts').assume_role(
		RoleArn='arn:aws:iam::{}:role/security/{}'.format(aws_account_number,role_name),
		RoleSessionName='Defensive.Works')

	# Storing STS credentials
	creds = boto3.Session(
		aws_access_key_id = resp['Credentials']['AccessKeyId'],
		aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
		aws_session_token = resp['Credentials']['SessionToken']
	)

	print("Assumed session for {}.".format(
		aws_account_number
	))

	return creds

def json_builder(item, field1_input, field1_output, field2_input, field2_output, session, region):
	
	hasAddDescription = True
	IpRanges = []
	attachment = []
	protocol = str(item["ipProtocol"])
	
	for ipranges in item[field1_input]["items"]:
		description = ""
		
		if "description" in ipranges:
			IpRanges.append({field2_output: str(
				ipranges[field2_input]), "Description": str(ipranges["description"])})
			description = str(ipranges["description"])
		else:
			IpRanges.append({field2_output: str(ipranges[field2_input])})
		
		if field1_input == "groups":
		
			ec2 = session.client('ec2', region_name = region)
			try:
				secGroupDetails = ec2.describe_security_groups(
					GroupIds=[
						str(ipranges[field2_input]),
					]
				)
				groupName = secGroupDetails["SecurityGroups"][0]["GroupName"]
				source = str(ipranges[field2_input]) + " (" + groupName + ")"
			except:
				source = str(ipranges[field2_input]) + " (Security group is in a peer VPC)"
		else:
			source = str(ipranges[field2_input])
		
		if description == "":
			hasAddDescription = False
	
	if protocol == "tcp":
		permissions = {
			"IpProtocol": protocol,
			"ToPort": item["toPort"], 
			"FromPort": item["fromPort"], 
			field1_output: IpRanges
			}
		
		if item["fromPort"] == item["toPort"]:
			portRange = str(item["fromPort"])
		else:
			portRange = str(item["fromPort"]) + ' - ' + str(item["toPort"])
		
		if description == "":
			attachment = {
				"fields": 
					[{"title": "Protocol", "value": str(protocol), "short": True}, 
					{"title": "Port", "value": portRange, "short": True}, 
					{"title": "Source", "value": source, "short": True}], "color": "#f98c3e"}
		else:
			attachment = {
				"fields": 
					[{"title": "Protocol", "value": str(protocol), "short": True}, 
					{"title": "Port", "value": portRange, "short": True}, 
					{"title": "Source", "value": source, "short": True}, 
					{"title": "Description", "value": description, "short": True}], "color": "#f98c3e"}
	
	response = []
	response.append(attachment)
	response.append(permissions)
	response.append({"hasAddDescription": hasAddDescription})
	return response


def send_slack_message(attachment, event):
	
	userType = event['userIdentity']['type']
	if userType == "AssumedRole":
		userName = (event['userIdentity']['arn']).split('/')[2]
	else: # This means its an IAM User
		userName = event['userIdentity']['userName']

	group = event["requestParameters"]["groupId"]
	account = event['userIdentity']["accountId"]
	region = event["awsRegion"]

	attachment.append(
		{
			"fallback": "You were unable to choose", "callback_id": str(event["requestID"]), 
			"color": "#f98c3e",
			"attachment_type": "default",
			"actions": [
				{ "name": "Approve Change", "text": "Ignore", "type": "button", "value": "approve", "style": "danger" },
				{ "name": "Deny Change", "text": "Deny", "type": "button", "value": "deny", "style": "primary" }
				]
		}
	)

	slack_message = {
		'text': 'Request ID: ' + str(event["requestID"]) + '\n*' + str(userName) + '* requested to *' + 'add' + '* inbound rule to *' + str(group) + '* in account *' + str(account) + '*' + ' in region *' + region + '*', "attachments": attachment
	}		

	try:
		request = Request(APPROVAL_HOOK_URL, method='POST')
		request.add_header('Content-Type', 'application/json')
		data = json.dumps(slack_message)
		data = data.encode()
		response = urlopen(request, data)
		if response.status == 200:
			print("Message posted to approval channel")
			return('200')

	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed: " + e.reason) 


def add_to_dynamodb(json_data, requestid):
	event = json.loads(json_data)

	dynamodbr = boto3.resource('dynamodb', region_name = 'us-east-1')
	table = dynamodbr.Table('secgrouprequests')

	try:
		response = table.put_item(
			Item = {
				"requestid": requestid,
				"event_json": event
				},
			ConditionExpression='attribute_not_exists(requestid)'
		)

		account = event['userIdentity']["accountId"]
		region = event["awsRegion"]

		#security_account = boto3.client('sts').get_caller_identity()['Account'] # Technically this is the automation account
		#hub_session = assume_role(boto3.Session(), AUTOMATION_ACCOUNT, 'hub-001') # This role is hardcoded considering you have the existing Role Trust relationship setup in place. https://github.com/raajheshkannaa/fleet-access

		session = assume_role(boto3.Session(), account, 'spoke-001') # Again this role is hardcoded considering you have the existing Role Trust relationship setup in place. https://github.com/raajheshkannaa/fleet-access

		if ("ipPermissions" in event["requestParameters"]):
			permissions = []
			attachment = []
			for item in event["requestParameters"]["ipPermissions"]["items"]:
				if item["ipRanges"] != {}:
					field1_input = "ipRanges"
					field1_output = "IpRanges"
					field2_input = "cidrIp"
					field2_output = "CidrIp"
				if item["ipv6Ranges"] != {}:
					field1_input = "ipv6Ranges"
					field1_output = "Ipv6Ranges"
					field2_input = "cidrIpv6"
					field2_output = "CidrIpv6"
				if item["prefixListIds"] != {}:
					field1_input = "prefixListIds"
					field1_output = "PrefixListIds"
					field2_input = "prefixListId"
					field2_output = "PrefixListId"
				if item["groups"] !={}:
					field1_input = "groups"
					field1_output = "UserIdGroupPairs"
					field2_input = "groupId"
					field2_output = "GroupId"
				response=json_builder(item,field1_input,field1_output,field2_input,field2_output, session, region)
				attachment.append(response[0])
				permissions.append(response[1])
				if response[2]["hasAddDescription"] == False:
					hasAddDescription = False
		else:
			print("An ingress rule change was detected, but not in the expected format. You should debug and find out why. Probably an EC2-Classic call.") 

		send_slack_message(attachment, event)
	
	except ClientError as e:
		print(e)
		pass


def main(event, context):

	session = assume_role(boto3.Session(), ORG_ACCOUNT, CLOUDTRAIL_LAKE_READ_ROLE)

	client = session.client('cloudtrail', region_name = 'us-east-1')

	event_data_stores = client.list_event_data_stores()['EventDataStores']
	
	for data_store in event_data_stores:
		Name = data_store['Name']
		database = data_store['EventDataStoreArn'].split('/')[1]
	
	event_name = 'AuthorizeSecurityGroupIngress'

	query = "SELECT requestId, eventTime, recipientAccountId, awsRegion, eventJson, eventName FROM {} WHERE eventName = '{}' AND eventTime > '{}' AND eventTime < '{}'".format(database, event_name, delta, time)

	run_query = client.start_query(
		QueryStatement = query
	)

	queryid = run_query['QueryId']

	sleep(3)

	query_results = client.get_query_results(
	EventDataStore=database,
	QueryId=queryid
	)

	
	for results in query_results['QueryResultRows']:
		for result in results:
			for k,v in result.items():
				if k == 'eventJson':			
					json_event = v
				if k == 'requestId':
					requestid = v
				
		add_to_dynamodb(json_event, requestid)
