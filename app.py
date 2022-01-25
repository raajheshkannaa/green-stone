#!/usr/bin/env python3

import aws_cdk as cdk

from stacks.pipeline_stack import CSGDRRPipelineStack

app = cdk.App()
CSGDRRPipelineStack(app, 'CSGDRR-PipelineStack')
app.synth()
