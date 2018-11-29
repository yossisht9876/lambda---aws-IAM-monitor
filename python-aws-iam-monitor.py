from __future__ import print_function

import json
import urllib2
import boto3
from io import BytesIO
from gzip import GzipFile
import urllib
import pprint

print('Loading function')

s3 = boto3.client('s3')

# NOTE change these to configure slack integration
SLACK_HOOK = "https://xxxxxxxxxxxxxxxxxxx"  # change me
SLACK_CHANNEL = "aws-iam-monitor"  # change me
SLACK_USER = "aws-iam"  # change me
SLACK_ICON = ":shield:"
SLACK_TOKEN =“your slack token"
SLACK_UPLOAD_URL="https://slack.com/api/files.upload"

ACCEPT = ["iam.amazonaws.com"]
WATCHLIST_OK = [
    "DetachGroupPolicy",
    "DetachRolePolicy",
    "DetachUserPolicy",
    "RemoveRoleFromInstanceProfile",
    "RemoveUserFromGroup"
]
WATCHLIST_WARN = [
    "AddUserToGroup",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "ChangePassword",
    "CreateAccessKey",
    "CreateSAMLProvider",
    "CreateUser",
    "UpdateUser"
]
WATCHLIST_IGNORE = [
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "CreatePolicy",
    "CreateRole",
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "CreateServiceLinkedRole",
    "CreateServiceSpecificCredential",
    "UploadServerCertificate",
    "UploadSigningCertificate",
    "UploadSSHPublicKey"
    "UpdateAccessKey",
    "UpdateAccountPasswordPolicy",
    "UpdateAssumeRolePolicy",
    "UpdateGroup",
    "UpdateLoginProfile",
    "UpdateOpenIDConnectProviderThumbprint",
    "UpdateRoleDescription",
    "UpdateSAMLProvider",
    "UpdateServerCertificate",
    "UpdateServiceSpecificCredential",
    "UpdateSigningCertificate",
    "UpdateSSHPublicKey",
    "CreateVirtualMFADevice",
    "CreatePolicyVersion",
    "CreateAccountAlias",
    "CreateGroup",
    "CreateInstanceProfile",
    "CreateLoginProfile",
    "CreateOpenIDConnectProvider",
    "RemoveClientIDFromOpenIDConnectProvider",
    "DeleteAccessKey",
    "DeleteAccountAlias",
    "DeleteAccountPasswordPolicy",
    "DeleteGroup",
    "DeleteGroupPolicy",
    "DeleteInstanceProfile",
    "DeleteLoginProfile",
    "DeleteOpenIDConnectProvider",
    "DeletePolicy",
    "DeletePolicyVersion",
    "DeleteRole",
    "DeleteRolePolicy",
    "DeleteSAMLProvider",
    "DeleteServerCertificate",
    "DeleteServiceSpecificCredential",
    "DeleteSigningCertificate",
    "DeleteSSHPublicKey",
    "DeleteUser",
    "DeleteUserPolicy",
    "DeleteVirtualMFADevice",
    "DeactivateMFADevice",
    "AddClientIDToOpenIDConnectProvider",
    "AddRoleToInstanceProfile",
    "EnableMFADevice",
    "GenerateCredentialReport",
    "GetAccessKeyLastUsed",
    "GetAccountAuthorizationDetails",
    "GetAccountPasswordPolicy",
    "GetAccountSummary",
    "GetContextKeysForCustomPolicy",
    "GetContextKeysForPrincipalPolicy",
    "GetCredentialReport",
    "GetGroup",
    "GetGroupPolicy",
    "GetInstanceProfile",
    "GetLoginProfile",
    "GetOpenIDConnectProvider",
    "GetPolicy",
    "GetPolicyVersion",
    "GetRole",
    "GetRolePolicy",
    "GetSAMLProvider",
    "GetServerCertificate",
    "GetSSHPublicKey",
    "GetUser",
    "GetUserPolicy",
    "ListAccessKeys",
    "ListAccountAliases",
    "ListAttachedGroupPolicies",
    "ListAttachedRolePolicies",
    "ListAttachedUserPolicies",
    "ListEntitiesForPolicy",
    "ListGroupPolicies",
    "ListGroups",
    "ListGroupsForUser",
    "ListInstanceProfiles",
    "ListInstanceProfilesForRole",
    "ListMFADevices",
    "ListOpenIDConnectProviders",
    "ListPolicies",
    "ListPolicyVersions",
    "ListRolePolicies",
    "ListRoles",
    "ListSAMLProviders",
    "ListServerCertificates",
    "ListServiceSpecificCredentials",
    "ListSigningCertificates",
    "ListSSHPublicKeys",
    "ListUserPolicies",
    "ListUsers",
    "ListVirtualMFADevices",
    "ResetServiceSpecificCredential",
    "ResyncMFADevice",
    "SetDefaultPolicyVersion",
    "SimulateCustomPolicy",
    "SimulatePrincipalPolicy"
]

WATCHLIST = WATCHLIST_OK + WATCHLIST_WARN

def getPolicy(policyArn):
    print("getting policy {0}".format(policyArn))
    client = boto3.client('iam')
    policy = client.get_policy(
        PolicyArn=policyArn
    )
    policy_version = client.get_policy_version(
       PolicyArn = policyArn,
       VersionId = policy['Policy']['DefaultVersionId']
    )
    
    return(json.dumps(policy_version['PolicyVersion']['Document']))
    
    

def lambda_handler(event, context):
    
    
    
    message = event['Records'][0]['Sns']['Message']
    print(message)
    ev = json.loads(message)
    if ( not "s3Bucket" in ev ):
        print("s3Bucket not in message")
        return
    
    policy_version={}
    bucket = ev["s3Bucket"]
    for key in ev["s3ObjectKey"]:
        print("getting " + key)
        response = s3.get_object(Bucket=bucket, Key=key)
        bytestream = BytesIO(response['Body'].read())
        body = GzipFile(None, 'rb', fileobj=bytestream).read().decode('utf-8')
        j = json.loads(body)
        attachments = []
        
        for record in j["Records"]:
            if record["eventSource"] in ACCEPT:
                if record["eventName"] not in WATCHLIST:
                    continue
                print("found IAM change in log " + key)
                
                policy_version={}
                if ( "eventName" in record and ( record["eventName"] == "DetachUserPolicy" or record["eventName"] == "AttachUserPolicy" or record["eventName"] == "AttachRolePolicy" or record["eventName"] == "DetachRolePolicy" ) ):
                   policyArn=record["requestParameters"]["policyArn"]
                   policy_version=getPolicy(policyArn)
                   print("found event {0}".format(record["eventName"]))

                author_name=record["userIdentity"]["arn"]
                if "Auto_Gen" in author_name:
                    return
                else:
                    author_name=author_name[author_name.rfind("/O")+1:len(author_name)]
                    
                attachment = {
                    "pretext": "*Commited by:*",
                    "author_name": author_name,
                    "title": "Action: " + record["eventName"],
                    "mrkdwn_in": ["text", "pretext"],
                    "fields": [
                        {"title": k, "value": v, "short": True}
                        for k, v
                        in record["requestParameters"].iteritems()
                    ],
                    "color": "ok" if record["eventName"] in WATCHLIST_OK else "warning"
                }
                
                if ( "Version" in policy_version ):
                   policy_version_json = "```" + pprint.pformat(json.loads(policy_version)) + "```"
                   policy_version_json = policy_version_json.replace("u\'","\'")
                   attachment["fields"].append({"title": "Policy Document", "value": policy_version_json , "short": False })
                   
                attachments.append(attachment)
                
        if attachments:
            print(attachments)
            if len(attachments) > 20:
                print("warning! too many attachments")
            data = {
                "channel": SLACK_CHANNEL,
                "username": SLACK_USER,
                "icon_emoji": SLACK_ICON,
                "attachments": attachments
            }
            print(json.dumps(data, indent=2))
            headers = {"Content-Type": "application/json"}
            payload = json.dumps(data)
            req = urllib2.Request(SLACK_HOOK, payload, headers)
            try:
                urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                print(e)
                print(e.read())
                
            #if ( "Version" in policy_version):
            #    data = dict(
            #          channels=SLACK_CHANNEL,
            #           icon_emoji=SLACK_ICON,
            #           content=policy_version,
            #           token=SLACK_TOKEN
            #          )
                          
                
            #    try:          
            #       data = urllib.urlencode(data)    
            #       req = urllib2.Request(SLACK_UPLOAD_URL, data, headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" })
            #       result=urllib2.urlopen(req)
            #    except urllib2.HTTPError as e:
            #      print(e)
            #      print(e.read())

    return message
