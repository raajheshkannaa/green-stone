

## Introduction
Get notified of Security Group Changes across all AWS Accounts & Regions in an AWS Organization, with the ability to respond/revert those changes with a single button click from a Slack Channel.
This is made easy and possible with the recent announcement of CloudTrail Lake, which helps aggregate CloudTrail logs from all accounts/regions in a queryable(if that's a word :P) format.

The infrastructure needed for this project is deployed as a CDK Application, which deploys a `CodeCommit` repository and a `CodeBuild` stage which synthesizes the cdk app to cloudformation template and deploys in the target environment.

***NOTE*** Security Group Rule Changes are allowed by default. Meaning changes are reverted only when explicitly denied by user interaction through slack channel interactive `Deny` button.

![How it works on the high level](SecurityGroupRevertChatOps.gif)

## Prerequisites
* Appropriate IAM Roles and trust relationships within the AWS Organization and member accounts. [FleetAccess](https://github.com/raajheshkannaa/fleet-access).
	![An ideal setup would be like this](SecurityGroupRevertIAMRoleStructure.png)
* CloudTrail Lake setup - [Tutorial to enable cloudtrail lake](https://aws.amazon.com/blogs/mt/announcing-aws-cloudtrail-lake-a-managed-audit-and-security-lake/)
* A role in the Organization account with the ability to invoke `start_query` and `get_query_results` and trusted by the `hub-001` role in the `Security account`, where the lambda functions run from.
* Slack App setup with the API Gateway endpoint updated. The Signing secret from the app should be updated in the config file to be used by the lambda function to verify requests from slack.
* Usage of the latest available boto3 library as API calls related to `cloudtrail lake` is new and only available on very recent versions, thus boto3 is packaged along with lambda functions.

## Components
* Lambda Functions
	* `revertsg-1` - Triggered every 10 mins by cloudwatch event rule.
	* `revertsg-2` - Invoked by API Gateway.
* API Gateway to receive requests from Slack and proxy to `revertsg-2`
* Dynamodb to hold security group rule change details.
* CloudWatch Event Rule time based to trigger `revertsg-1` every 10 mins.



## Workflow
![Security Group Change Detection & Response](SecurityGroupRevertChatOps.drawio.png)
* CloudWatch Event Time based rule will trigger lambda `revertsg-1`, every 10 mins.
* Lambda function `revertsg-1` will assume role `cloudtrail-lake-read-role` in the organization account and run query to fetch events with event name `AuthorizeSecurityGroupIngress` in the last 20 mins. There is an over lap so that events which were 
* Query results are gathered and new security group rule changes are added to a dynamodb table `secgrouprequests` and also details are sent to a slack channel in an interactive message with the ability to either ignore or deny this change.
* Slack interaction invokes API Gateway which in turn invokes `revertsg-2` with all the headers and body proxied.
* Security group rule changes are allowed by default, so, 
	* If the user clicks on `Approve`_(well technicaly it's already approved :P)_, `revertsg-2` does the same and responds back with the user name who ignored this change event.
	* If the user clicks `Deny`, meaning to revert the change, `revertsg-2` will,
		* Read dynamodb table with the cloudtrail `requestid`, get that specific event details, assume `spoke-001` role on that account from the security account as `hub-001`, invokes the `revoke_security_group_ingress` API call, responds with the messaged as `denied` with the user name.

## Usage



## Considerations
* CloudTrail events are delayed by up to 2-3 mins sometimes before it gets delivered to the cloudtrail lake. Timings are adjusted accordingly for this project, with the CloudWatch Rule and also the event times` for the cloudtrail lake query.
* 


### 'Hub' IAM Role Trust Relationship
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<AUTOMATION_ACCOUNT_ID>:role/security/hub-001",
        "Service": [
          "lambda.amazonaws.com",
          "ec2.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
