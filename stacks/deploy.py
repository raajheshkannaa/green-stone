import aws_cdk as cdk
from constructs import Construct

from .continuous_security_group_detection_review_response_stack import ContinuousSecurityGroupDetectionReviewResponseStack

class PipelineStage(cdk.Stage):
	def __init__(self, scope: Construct, id: str, **kwargs):
		super().__init__(scope, id, **kwargs)

		stack = ContinuousSecurityGroupDetectionReviewResponseStack(self, 'RevertSG-Stack')

