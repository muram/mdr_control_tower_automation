# mdr\_control\_tower\_automation

Alert Logic Managed Detection and Response Integration with AWS Control Tower.

## Overview

AWS Control Tower enables a customer to set up and govern a secure, multi-account AWS environment based on best practices recommended by AWS. 

AWS Control Tower creates the audit and log archive account automatically in addition to the master account. We also recommend that you create a new security account to be used for Alert Logic MDR integration with AWS Control Tower.

AWS Control Tower managed accounts CloudTrail logs are stored in a centralized Amazon S3 bucket located in the Log archive account. The CloudTrail are set to send notification to Amazon SNS topic located in the Audit account. Alert Logic MDR uses Amazon SQS to ingest CloudTrail logs. This solution creates an SQS queue in the Log archive account and subscribes it to the CloudTrail SNS topic in the audit account.

### Supported Protection Modes:

1. Automatic Mode - Alert Logic will create necessary IAM Roles to enable automated deployment of Alert Logic IDS and Scan appliances.
2. Manual Mode - Alert Logic will create necessary IAM Roles to monitor changes via AWS Cloud Trail and discovery APIs, but will not deploy Alert Logic IDS and Scan appliances, instead it will be customer's responsibility. 
```Note that Remediations will be generated in Alert Logic MDR to indicate absence of appliances```
 
### Alert Logic MDR Protection Scope
Depending on your selection during the CloudFormation deployment, Alert Logic MDR will either protect the entire regions or only VPCs that are tagged with specific Tags.

### Architecture Overview

In the solution architecture overview we will use the following terminology:

1. Control Tower Master Account
2. Audit Account - Shared AWS Control Tower account that hosts SNS Topic used to publish account's Cloud Trail notifications
3. Log Archive Account - Shared AWS Control Tower account where Cloud Trail logs are stored.
4. Security Account - An AWS Control Tower managed account that hosts Alert Logic MDR automation Infrastructure (Lambdas and Event Bus)
5. Protected account - An AWS Control Tower account to be protected by Alert Logic MDR.

##### Deployment Process
1. The solution is deployed via creation of AWS CloudFormation Stack using this template <https://s3.amazonaws.com/alertlogic-public-repo.us-east-1/templates/ct-al-master-onboarding.yaml>
2. This Stack will:
	* Create all necessary IAM Roles for cross-account integration between Alert Logic MDR AWS Account and accounts selected to be protected by this integration.
	* Set up SQS subscription to AWS Cloud Trail SNS Topic
	* Deploy Alert Logic MDR automation (Lambdas and EventBus) to designated Security Account
	* Update Master Account to create new CloudFormation StackSet instance for enrolled account when an account is enrolled to be governed by AWS Control Tower.
	* Update protected accounts to publish VPC tag changes to Security Account's Event Bus.
	
[Architecture Diagram](architecture.png)



#### Deployment
##### Prerequisites

```Note: Audit, Log Archive and Security Accounts are always protected by Alert Logic MDR```

