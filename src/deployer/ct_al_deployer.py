#
# Copyright Alert Logic, Inc. All Rights Reserved.
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
import boto3, json, time, sys, os, base64, copy
import logging
import requests
import almdrlib
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
almdrlib.set_logger('almdrlib', logging.INFO)

session = boto3.Session()
tag_keyword = str(os.environ['tag_keys']).replace(" ", "").split(",")
subnet_type = ['Disable', 'Public', 'Private']


def assume_role(aws_account_number, role_name, external_id):
    '''
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    '''
    try:
        sts_client = boto3.client('sts')
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName=str(aws_account_number + '-' + role_name),
            ExternalId=external_id
        )
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        LOGGER.info("Assumed session for {} - {}.".format(aws_account_number, role_name))
        return sts_session

    except Exception as e:
        LOGGER.error("Could not assume role : {}".format(e))
        return False


def parse_al_tag(tags):
    '''
    Search for tags with key 'alertlogic'
    '''
    try:
        #assume there's no alertlogic tag
        al_tag = -1
        for key, value in tags.items():
            if str.lower(key) in tag_keyword:
                if str.lower(value) in str(os.environ['tag_public_values']).replace(" ", "").split(","):
                    #enable appliance in public subnet
                    al_tag = 1
                elif str.lower(value) in str(os.environ['tag_private_values']).replace(" ", "").split(","):
                    #enable appliance in private subnet
                    al_tag = 2
                else:
                    #disable appliance
                    al_tag = 0
                LOGGER.info("Found tag : {} = {}".format(key, value))
                break
        return al_tag
    except Exception as e:
        LOGGER.error("Failed to search AlertLogic tag: {}".format(e))
        return False


def get_secret(target_session, region, secret_name):
    secret_client = target_session.client('secretsmanager')
    try:
        get_secret_value_response = secret_client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        LOGGER.info(f"Get Secret Failed: {str(e)}")
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
            
            
def get_asset_key(type, region, id):
    return f'/aws/{region}/{type}/{id}'
    

def update_scope(assets, policy_id, type, key, al_tag_status):
    if al_tag_status > 0:
        result = [
                {
                    'key': key,
                    'type': type,
                    'policy': {
                        'id': policy_id
                    }
                }
            ]
        for asset in assets:
            if asset['key'] != key:
                result.append(asset)
        return result
    else:
        return [asset for asset in assets if asset['key'] != key]
    
def get_policy_id(client, al_account_id):
    try:
        policies = client.list_policies(account_id=al_account_id).json()
        for policy in policies:
            if policy['name'] == 'Professional':
                return policy['id']
        LOGGER.Error(f"Cannot find 'Professional' policy id")
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list policies. Error: {str(e)}")
        return None
    
def get_deployment(client, al_account_id, aws_account_id):
    try:
        deployments = client.list_deployments(account_id=al_account_id).json()
        for deployment in deployments:
            platform = deployment['platform']
            if platform['type'] == 'aws' and platform['id'] == aws_account_id:
                LOGGER.info(f"Alert Logic Deployment ID: {deployment['id']}")
                return deployment
          
        LOGGER.Info(f"Account {aws_account_id} is not protected by Alert Logic MDR")      
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list deployments. Error: {str(e)}")
        return None
    
    
def lambda_handler(event, context):
    LOGGER.info('Lambda Handler - Start')
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))
    
    if 'detail-type' in event and event['detail-type'] == 'Tag Change on Resource':
        LOGGER.info("Using Event Bus Handler")
        resource_type = event['detail']['resource-type']
        if not resource_type in ['subnet', 'vpc']:
            LOGGER.warning("Tag changes on non supported resource, skipping")
            LOGGER.info('Lambda Handler - End')
            return
        
        account_id = event['account']
        region = event['region']
        
        # Get Alert Logic API Credentials
        al_credentials = get_secret(
            session,
            str(context.invoked_function_arn).split(":")[4],
            os.environ['secret'])
        if not al_credentials:
            LOGGER.error("Unable to retrieve the AlertLogic API credentials")
            LOGGER.info('Lambda Handler - End')
            return
        
        # Initialize session to Alert Logic backend
        auth = json.loads(al_credentials)
        al_session = almdrlib.Session(
                access_key_id=auth['ALAccessKey'],
                secret_key=auth['ALSecretKey'])
                
        # Create Alert Logic Deployment Object
        deployments_client = al_session.client('deployments')         
        deployment = get_deployment(deployments_client, auth['ALCID'], account_id)
        if not deployment:
            LOGGER.info('Lambda Handler - End')
            return
        
        # Get protection policy ID
        policy_id = get_policy_id(al_session.client('policies'), auth['ALCID'])
        if not policy_id:
            LOGGER.info('Lambda Handler - End')
            return
        
        include_scope = deployment['scope']['include']
        for key in event['detail']['changed-tag-keys']:
            if str.lower(key) in tag_keyword:
                tags = event['detail']['tags']
                al_tag_status = parse_al_tag(tags)
                for resource in event['resources']:
                    asset_key = get_asset_key(
                        resource_type,
                        region,
                        resource.split(":")[5].split("/")[1]
                        )
                    include_scope = update_scope(include_scope, policy_id, resource_type, asset_key, al_tag_status)
        
        
        deployment['scope']['include'] = include_scope
        result = deployments_client.update_deployment(
            account_id=auth['ALCID'],
            deployment_id=deployment['id'],
            scope=deployment['scope'],
            version = deployment['version']
            )            
        LOGGER.info(f"Updated protection scope: {result.json()}")
                    
    else:
        LOGGER.error("Invalid event type - skipping")
    LOGGER.info('Lambda Handler - End')

