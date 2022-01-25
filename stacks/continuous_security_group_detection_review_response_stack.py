from constructs import Construct
from aws_cdk import (
	Duration,
	Stack,
	aws_lambda as lmb,
	aws_apigateway as apigateway,
	aws_events as events,
	aws_events_targets as targets,
	aws_iam as iam,
	aws_ec2 as ec2,
	aws_dynamodb as dynamodb
)

from .config import AUTOMATION_ACCOUNT, SIGNINGSECRET

class ContinuousSecurityGroupDetectionReviewResponseStack(Stack):

	def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
		super().__init__(scope, construct_id, **kwargs)

		# Depends on the `Hub` IAM ROLE present in the Security or Automation Account.
		src_role_arn = 'arn:aws:iam::' + AUTOMATION_ACCOUNT + ':role/security/hub-001'
		src_role = iam.Role.from_role_arn(self, 'Role', src_role_arn)

		# Subnet configurations for a public and private tier
		subnet1 = ec2.SubnetConfiguration(
				name="Public",
				subnet_type=ec2.SubnetType.PUBLIC,
				cidr_mask=24)
		subnet2 = ec2.SubnetConfiguration(
				name="Private",
				subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
				cidr_mask=24)

		vpc = ec2.Vpc(self,
				  "ContinuousSecurityGroupReviewVPC",
				  cidr="10.188.0.0/16", # Please change this if this would cause a conflict.
				  enable_dns_hostnames=True,
				  enable_dns_support=True,
				  max_azs=2,
				  nat_gateway_provider=ec2.NatProvider.gateway(),
				  nat_gateways=1,
				  subnet_configuration=[subnet1, subnet2]
				  )


		revertsg1 = lmb.Function(
			self, 'revertsg-1',
			code=lmb.Code.from_asset('src/revertsg-1/'),
			runtime=lmb.Runtime.PYTHON_3_9,
			handler='revertsg-1.main',
			timeout=Duration.seconds(900),
			memory_size=128,
			role=src_role,
			function_name='revertsg-1',
			vpc=vpc,
			vpc_subnets=ec2.SubnetType.PRIVATE_WITH_NAT,
		)

		revertsg2 = lmb.Function(
			self, 'revertsg-2',
			code=lmb.Code.from_asset('src/revertsg-2/'),
			runtime=lmb.Runtime.PYTHON_3_9,
			handler='revertsg-2.main',
			timeout=Duration.seconds(900),
			memory_size=128,
			role=src_role,
			function_name='revertsg-2',
			vpc=vpc,
			vpc_subnets=ec2.SubnetType.PRIVATE_WITH_NAT,
			environment={
				"signingsecret": SIGNINGSECRET
			}
		)

		rule = events.Rule(
			self, "TriggerCloudTrailLakeQuery",
			schedule=events.Schedule.rate(Duration.minutes(10))
		)

		rule.add_target(targets.LambdaFunction(revertsg1))


		api = apigateway.LambdaRestApi(self, "RevertSGAPI",
				rest_api_name="RevertSGAPI",
				description="API Calling the RevertSG Lambda",
				proxy=False,
				handler=revertsg2,
				endpoint_types=[apigateway.EndpointType.REGIONAL]
				)

		revertsg_integration = apigateway.LambdaIntegration(revertsg2, proxy=True)
				
		api.root.add_method("POST", revertsg_integration)

		# api_resource = api.root.add_resource("revertsg")		
		# api_resource.add_method("POST", revertsg_integration)
		# api_resource.add_method

		table = dynamodb.Table(
			self, 'Table',
			table_name='secgrouprequests',
			partition_key=dynamodb.Attribute(name='requestid', type=dynamodb.AttributeType.STRING)
		)

		table.auto_scale_write_capacity(
			min_capacity=1,
			max_capacity=10
		).scale_on_utilization(target_utilization_percent=75)

		table.auto_scale_read_capacity(
			min_capacity=1,
			max_capacity=10
		).scale_on_utilization(target_utilization_percent=75)