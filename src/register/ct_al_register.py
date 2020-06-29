#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import boto3, json, time, sys, os, base64
import logging
from botocore.exceptions import ClientError
from botocore.vendored import requests

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

session = boto3.Session()

#API Endpoint
YARP_URL="api.cloudinsight.alertlogic.com"
ALERT_LOGIC_CI_SOURCE = "https://api.cloudinsight.alertlogic.com/sources/v1/"

def cfnresponse_send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    '''
    function to signal CloudFormation custom resource
    '''
    responseUrl = event['ResponseURL']
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData
    json_responseBody = json.dumps(responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }
    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        LOGGER.info("CFN Response Status code: " + response.reason)
    except Exception as e:
        LOGGER.info("CFN Response Failed: " + str(e))

def authenticate(user, paswd, yarp):
    #Authenticate with CI yarp to get token
    url = yarp
    user = user
    password = paswd
    r = requests.post('https://{0}/aims/v1/authenticate'.format(url), auth=(user, password), verify=True)
    if r.status_code != 200:
        sys.exit("Unable to authenticate %s" % (r.status_code))
    #account_id = json.loads(r.text)['authentication']['user']['account_id']
    token = r.json()['authentication']['token']
    return token

def prep_credentials(iam_arn, iam_ext_id, cred_name):
    #Setup dictionary for credentials payload
    RESULT = {}
    RESULT['credential']  = {}
    RESULT['credential']['name'] = str(cred_name)
    RESULT['credential']['type'] = "iam_role"
    RESULT['credential']['iam_role'] = {}
    RESULT['credential']['iam_role']['arn'] = str(iam_arn)
    RESULT['credential']['iam_role']['external_id'] = str(iam_ext_id)
    return RESULT

def post_credentials(token, payload, target_cid):
    #Call API with method POST to create new credentials, return the credential ID
    API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/credentials/"
    REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=True, data=payload)
    print ("Create Credentials Status : " + str(REQUEST.status_code), str(REQUEST.reason))
    if REQUEST.status_code == 201:
        RESULT = json.loads(REQUEST.text)
    else:
        RESULT = {}
        RESULT['credential']  = {}
        RESULT['credential']['id'] = "n/a"
    return RESULT

def prep_ci_source_environment(aws_account, cred_id, sqs_cred_id, environment_name, scope_data, enable_otis = False):
    #Setup dictionary for environment payload
    RESULT = {}
    RESULT['source']  = {}
    RESULT['source']['config'] = {}
    RESULT['source']['config']['collection_method'] = "api"
    RESULT['source']['config']['collection_type'] = "aws"
    if enable_otis:
        RESULT['source']['config']['deployment_mode'] = "guided"

    RESULT['source']['config']['aws'] = {}
    RESULT['source']['config']['aws']['account_id'] = aws_account
    RESULT['source']['config']['aws']['discover'] = True
    RESULT['source']['config']['aws']['scan'] = True
    RESULT['source']['config']['aws']['credential'] = {}
    RESULT['source']['config']['aws']['credential']['id'] = cred_id
    RESULT['source']['config']['aws']['credential']['version'] = "2020-01-10"
    RESULT['source']['config']['aws']['aux_credentials'] = []
    TEMP_X_CRED = {}
    TEMP_X_CRED['id'] = sqs_cred_id
    TEMP_X_CRED['purpose'] = 'x-account'
    TEMP_X_CRED['version'] = "2016-09-20"
    RESULT['source']['config']['aws']['aux_credentials'].append(TEMP_X_CRED)
    
    if (scope_data["include"] or scope_data["exclude"]):
        RESULT['source']['config']['aws']['scope'] = {}
        RESULT['source']['config']['aws']['scope']['include'] = scope_data["include"]
        RESULT['source']['config']['aws']['scope']['exclude'] = scope_data["exclude"]

    RESULT['source']['enabled'] = True
    RESULT['source']['name'] = environment_name
    RESULT['source']['product_type'] = "outcomes"
    RESULT['source']['tags'] = []
    RESULT['source']['type'] = "environment"
    return RESULT

def post_source_environment(token, payload, target_cid):
    #Call API with method POST to create new environment
    API_ENDPOINT = ALERT_LOGIC_CI_SOURCE + target_cid + "/sources/"
    REQUEST = requests.post(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=True, data=payload)
    print ("Create Environment Status : " + str(REQUEST.status_code), str(REQUEST.reason))
    if REQUEST.status_code == 201:
        RESULT = json.loads(REQUEST.text)
    else:
        RESULT = {}
        RESULT['source'] = {}
        RESULT['source']['id'] = "n/a"
    return RESULT

def get_secret(target_session, region, secret_name):
    secret_client = target_session.client('secretsmanager')
    try:
        get_secret_value_response = secret_client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        LOGGER.info("Get Secret Failed: " + str(e))
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret 
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

def lambda_handler(event, context):
    try:
        LOGGER.info('Lambda Handler - Start')
        LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))
        response_data = {}
        response_data["event"] = event

        for record in event['Records']:
            cfn_event = json.loads(record['Sns']['Message'])
            LOGGER.info ('CFN REQUEST RECEIVED: {}'.format(json.dumps(cfn_event, default=str)))
            if cfn_event['RequestType'] == 'Create':
                AL_CRED = get_secret(
                    session, 
                    str(context.invoked_function_arn).split(":")[4], 
                    os.environ['Secret']
                    )
                if AL_CRED:
                    LOGGER.info("AlertLogic credentials loaded from Secret Manager")
                    AL_CRED=json.loads(AL_CRED)
                    AL_ACCESS_KEY=AL_CRED['ALAccessKey']
                    AL_SECRET_KEY=AL_CRED['ALSecretKey']
                    TOKEN = str(authenticate(AL_ACCESS_KEY, AL_SECRET_KEY, YARP_URL))
                    
                    #Register credentials (IAM ROLE) to AlertLogic
                    LOGGER.info("Creating credentials for linked account and cross account (SQS)")
                    CRED_PAYLOAD = prep_credentials(
                        cfn_event['ResourceProperties']['ALSourceRoleArn'],
                        cfn_event['ResourceProperties']['CID'], 
                        cfn_event['ResourceProperties']['AccountId'] + '-linked-role'
                        )
                    CRED_RESULT = post_credentials(TOKEN, str(json.dumps(CRED_PAYLOAD, indent=4)), cfn_event['ResourceProperties']['CID'])
                    CRED_ID = str(CRED_RESULT['credential']['id'])
                    LOGGER.info("AlertLogic Linked Account Cred Id: {}".format(CRED_ID))

                    CRED_X_PAYLOAD = prep_credentials(
                        cfn_event['ResourceProperties']['ALCentralizedRoleArn'],
                        cfn_event['ResourceProperties']['CID'], 
                        cfn_event['ResourceProperties']['AccountId'] + '-sqs-role'
                        )
                    CRED_X_RESULT = post_credentials(TOKEN, str(json.dumps(CRED_X_PAYLOAD, indent=4)), cfn_event['ResourceProperties']['CID'])
                    CRED_X_ID = str(CRED_X_RESULT['credential']['id'])
                    LOGGER.info("AlertLogic Cross Account Cred Id: {}".format(CRED_X_ID))

                    #Prepare empty scope for discovery
                    INPUT_SCOPE = {}
                    INPUT_SCOPE['include'] = []
                    INPUT_SCOPE['exclude'] = []

                    if os.environ['FullRegionCoverage'] == 'true':
                        #Prepare scope for the selected regions
                        for region in str(os.environ['TargetRegion']).split(','):
                            INPUT_REGION = {}
                            INPUT_REGION['type'] = 'region'
                            INPUT_REGION['key'] = '/aws/' + region
                            INPUT_SCOPE['include'].append(INPUT_REGION)
                    
                    ENV_PAYLOAD = prep_ci_source_environment(
                        cfn_event['ResourceProperties']['AccountId'],
                        CRED_ID,
                        CRED_X_ID,
                        cfn_event['ResourceProperties']['AccountId'],
                        INPUT_SCOPE,
                        enable_otis = False
                        )
                    LOGGER.info(json.dumps(ENV_PAYLOAD))

                    #Create new environment to initiate discovery
                    ENV_RESULT = post_source_environment(
                        TOKEN, 
                        str(json.dumps(ENV_PAYLOAD, indent=4)), 
                        cfn_event['ResourceProperties']['CID']
                        )
                    ENV_ID = str(ENV_RESULT['source']['id'])
                    LOGGER.info(ENV_RESULT)
                    LOGGER.info("AlertLogic Deployment: {}".format(ENV_ID))
                    
                    cfnresponse_send(cfn_event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
                else:
                    LOGGER.error("Unable to retrieve the AlertLogic API credentials")
                    cfnresponse_send(cfn_event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
            else:
                LOGGER.warning("Non Create event - skipping")
                cfnresponse_send(cfn_event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
        LOGGER.info('Lambda Handler - End')
    except Exception as e:
        LOGGER.error(e)
        for record in event['Records']:
            cfn_event = json.loads(record['Sns']['Message'])
            LOGGER.info ('CFN REQUEST RECEIVED: {}'.format(json.dumps(cfn_event, default=str)))
            response_data = {}
            response_data["Status"] = str(e)
            cfnresponse_send(cfn_event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
