from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    FieldPrefixMappingTransformation,
)

ecs_cloudtrail = ProcessingPipeline(
    vars={
        "json_load_prefixes": [
            "aws.cloudtrail.additional_eventdata",
            "aws.cloudtrail.request_parameters",
            "aws.cloudtrail.response_elements",
            "aws.cloudtrail.service_event_details",
        ]
    },
    items=[
        ProcessingItem(
            identifier="field_mapping",
            transformation=FieldMappingTransformation(
                {
                    "apiVersion": "aws.cloudtrail.api_version",
                    "awsRegion": "cloud.region",
                    "errorCode": "aws.cloudtrail.error_code",
                    "errorMessage": "aws.cloudtrail.error_message",
                    "eventID": "event.id",
                    "eventName": "event.action",
                    "eventSource": "event.provider",
                    "eventTime": "ts",
                    "eventType": "aws.cloudtrail.event_type",
                    "eventVersion": "aws.cloudtrail.event_version",
                    "managementEvent": "aws.cloudtrail.management_event",
                    "readOnly": "aws.cloudtrail.read_only",
                    "requestID": "aws.cloudtrail.request_id",
                    "resources.accountId": "aws.cloudtrail.resources.account_id",
                    "resources.ARN": "aws.cloudtrail.resources.arn",
                    "resources.type": "aws.cloudtrail.resources.type",
                    "sharedEventId": "aws.cloudtrail.shared_event_id",
                    "sourceIPAddress": "source.address",
                    "userAgent": "user_agent",
                    "userIdentity.accessKeyId": "aws.cloudtrail.user_identity.access_key_id",
                    "userIdentity.accountId": "cloud.account.id",
                    "userIdentity.arn": "aws.cloudtrail.user_identity.arn",
                    "userIdentity.invokedBy": "aws.cloudtrail.user_identity.invoked_by",
                    "userIdentity.principalId": "user.id",
                    "userIdentity.sessionContext.attributes.creationDate": "aws.cloudtrail.user_identity.session_context.creation_date",
                    "userIdentity.sessionContext.attributes.mfaAuthenticated": "aws.cloudtrail.user_identity.session_context.mfa_authenticated",
                    "userIdentity.sessionContext.sessionIssuer.userName": "role.name",
                    "userIdentity.type": "aws.cloudtrail.user_identity.type",
                    "userIdentity.userName": "user.name",
                    "vpcEndpointId": "aws.cloudtrail.vpc_endpoint_id",
                }
            ),
        ),
        ProcessingItem(
            identifier="field_mapping_prefix",
            transformation=FieldPrefixMappingTransformation(
                {
                    "additionalEventdata": "aws.cloudtrail.additional_eventdata",
                    "requestParameters": "aws.cloudtrail.request_parameters",
                    "responseElements": "aws.cloudtrail.response_elements",
                    "serviceEventDetails": "aws.cloudtrail.service_event_details",
                }
            ),
        ),
    ]
)
