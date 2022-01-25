import json
import urllib
import boto3
from sys import exit
import os
from urllib.parse import unquote, unquote_plus
import hmac
import hashlib
import time
from urllib.request import HTTPError, URLError, urlopen, Request

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

	#print("Assumed session for {}.".format(
	#	aws_account_number
	#))

	return creds


def json_builder(item, field1_input, field1_output, field2_input, field2_output):
	
	protocol = str(item["ipProtocol"])
	IpRanges = []

	for ipranges in item[field1_input]["items"]:
		description = ""
		
		if "description" in ipranges:
			IpRanges.append({field2_output: str(ipranges[field2_input]), "Description": str(ipranges["description"])})
			description = str(ipranges["description"])
		
		else:
			IpRanges.append({field2_output: str(ipranges[field2_input])})
			
	if protocol == "tcp":
		permissions = {
			"IpProtocol": protocol,
			"ToPort": int(item["toPort"]), 
			"FromPort": int(item["fromPort"]), 
			field1_output: IpRanges
			
		}
		
	return(permissions)


def slack_response(event_data, action):
	response_url = event_data['response_url']
	print(response_url)
	user = event_data['user']['name']
	original_attachements = event_data['original_message']['attachments']
	original_attachements.pop()
	original_text = unquote_plus(event_data['original_message']['text'])

	attachment = []
	for original_attachment_item in original_attachements:
		color = original_attachment_item['color']
		fields = original_attachment_item['fields']
		for i in range(len(fields)):
			if (fields[i]['title']) == 'Description':
				fields[i]['value'] = unquote_plus(fields[i]['value'])
			
		attachment_item = {
			"color": color,
			"fields": fields,
		}
		attachment.append(attachment_item)
	
	actions = ['Denied', 'Ignored']
	if action in actions:
		attachment.append({'text': action + ' by ' + user, "color": color })
	else:
		attachment.append({'text': 'Security Group change was already reverted', "color": color })
		
	message = {
		"text": original_text,
		"attachments": attachment
	}
	
	try:
		request = Request(response_url, method='POST')
		request.add_header('Content-Type', 'application/json')
		data = json.dumps(message)
		data = data.encode()
		response = urlopen(request, data)
		print(response.status)
		if response.status == 200:
			print("Response posted to approval channel")
			return('200')

	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed: " + e.reason) 


def main(event, context):
	
	try:
		# Verifying requests from slack app
		SIGNING_SECRET = os.environ['signingsecret']
		slack_signing_secret = bytes(SIGNING_SECRET, "utf-8")
		slack_timestamp = event['headers']['X-Slack-Request-Timestamp']
		slack_signature = event['headers']['X-Slack-Signature']
		if (int(time.time()) - int(slack_timestamp)) > 60:
			print("Verification failed. Request is out of date.")
			exit()
		
		body = event['body']
		basestring = f"v0:{slack_timestamp}:{body}".encode("utf-8")
		my_signature = ("v0=" + hmac.new(slack_signing_secret, basestring, hashlib.sha256).hexdigest())
		
		# Compare the resulting signature with the signature on the request to verify the request
		if hmac.compare_digest(my_signature, slack_signature):
			print("Verification is good!")
		else:
			print("Verification failed. Signature invalid.")
			exit()		
		
		# Program begins 
		payload = unquote(event['body'])
		event_data = json.loads(payload[8:])
		requestid = event_data['callback_id']

		dynamodbr = boto3.resource('dynamodb', region_name = 'us-east-1')
	
		table = dynamodbr.Table('secgrouprequests')
		
		response = table.get_item(
			Key = {
				'requestid': requestid,
			}
		)
		
		event_json = response['Item']['event_json']

		account = event_json['userIdentity']['accountId']
		group = event_json['requestParameters']['groupId']
		region = event_json['awsRegion']

		action = event_data['actions'][0]['value']

		if 'approve' in action:
			slack_response(event_data, 'Ignored')

		if 'deny' in action:
			permissions = []
			for item in event_json["requestParameters"]["ipPermissions"]["items"]:
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
				response=json_builder(item,field1_input,field1_output,field2_input,field2_output)
				permissions.append(response)
				
			session = assume_role(boto3.Session(), account, 'spoke-001')
			
			ec2 = session.client('ec2', region_name=region)
			revert_change = ec2.revoke_security_group_ingress(
				GroupId=group,
				IpPermissions=permissions
				)

			if 'UnknownIpPermissions' not in revert_change.keys(): # This means the Security Group change was already reverted, meaning those IP Permissions are not there now.
				slack_response(event_data, 'Denied')
			else:
				slack_response(event_data, 'Already Removed')
				

	except Exception as e:
		print(e)
