#!/usr/bin/env python

import boto3
import sys
import os
import csv
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


#######################################################################################
## ABOUT:
## This script evaluates all IAM identities in all accounts in an organization for admin privileges.
##  
## DEPENDENCIES: 
##   - Proper credentials to assume the ccoe-auditor-management-role in management account.
##   - Existence of IAM role ccoe-auditor-management-role in the management account.
##   - Existence of IAM role ccoe-auditor-members-role in the member accounts of the Organization.
##
## It will analyze every IAM customer-managed policy, and the utilized AWS-managed policies. 
## It will also analyze all the IAM users, groups, and roles for attached & inline policies. 
## And it will map if any users have admin privileges via any of the IAM resources analyzed.
##
## NOTE: This evaluates every policy statement in each of the above mentioned policies.
## 
## USAGE:
## If using temporary credentials set in your AWS environment variables:
##      $ python3 script-name.py
## If using profile credentials set in your AWS credentials file:
##      $ python3 script-name.py [profile_name]
## 


## Data model for findings from policies analysis.
class FindingsListPolicy(BaseModel):
    account_id: Optional[str] = ""
    account_name: Optional[str] = ""
    policy_name: str
    policy_arn: str ## (if policy_type "Inline", then this is Arn of identity.)
    policy_type: str ## ("Inline" | "Customer-Managed" | "AWS-Managed")
    check_id: str = "CHECK_ID" ## "full-admin"
    operation_type: Optional[str] = ""
    finding_statement: str

class FindingsList(BaseModel):
    account_id: Optional[str] = ""
    account_name: Optional[str] = ""
    identity_name: str
    identity_arn: str
    finding_statement: str
    check_id: str = "full_admin"
    operation_type: str
    group_name: Optional[str] = ""
    group_arn: Optional[str] = ""
    role_name: Optional[str] = ""
    role_arn: Optional[str] = ""
    policy_name: Optional[str] = ""
    policy_arn: Optional[str] = ""
    user_name: Optional[str] = ""
    user_arn: Optional[str] = ""

## The check_id attribute in the above data models was meant to leave a place to develop for other types of checks, other than for "full_admin".

aggregated_findings_list = []

timestamp = datetime.now().strftime('%Y%m%d_%H%M')

output_file = f'admins_audit_all_accounts_{timestamp}.csv'

def get_data(profile_name=None):
    REGION = 'us-east-1'
    if 'credentials_auditor_member' in globals() and credentials_auditor_member:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=credentials_auditor_member['AccessKeyId'],
            aws_secret_access_key=credentials_auditor_member['SecretAccessKey'],
            aws_session_token=credentials_auditor_member['SessionToken']
        )
        # sts_client = boto3.client(
        #     'sts',
        #     aws_access_key_id=credentials_auditor_member['AccessKeyId'],
        #     aws_secret_access_key=credentials_auditor_member['SecretAccessKey'],
        #     aws_session_token=credentials_auditor_member['SessionToken']
        # )
    else:
        session = boto3.Session(profile_name=profile_name)
        # sts_client = session.client('sts', region_name=REGION)
        iam_client = session.client('iam', region_name=REGION)


    auth_pages = iam_client.get_paginator('get_account_authorization_details').paginate()
    global auth_result
    auth_result = auth_pages.build_full_result()


def evaluate_all_relevant_noninline_policies(account_id):
    ## Evaluates IAM policies being used by the customer in account (non-inline).
    ## This includes ALL customer-managed policies, even if unattached.
    ## This does NOT include all AWS-Managed policies, since that's too many - only the attached ones being used in account. 
    ## This does NOT include inline policies.  (See other operation "evaluate_all_inline_policies".)

    for policy in auth_result["Policies"]:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        for document in policy['PolicyVersionList']:
            if document['IsDefaultVersion']:
                policy_doc = document['Document']
                if not isinstance(policy_doc["Statement"], list):
                    statements = [policy_doc["Statement"]]
                else:
                    statements = policy_doc["Statement"]
                for statement in statements:
                    has_elevated_privileges = check_statement_for_full_admin(statement)
                    if has_elevated_privileges:
                        policy_type = "Customer-Managed"
                        if policy_arn.startswith("arn:aws:iam::aws:"):
                            policy_type = "AWS-Managed"
                        finding = "{0} policy \"{1}\" contains policy statement for full-admin privileges.".format(policy_type, policy_name)
                        
                        findings_list_policy.append(FindingsListPolicy(
                            policy_name=policy_name,
                            policy_arn=policy_arn,
                            policy_type=policy_type,
                            check_id="full-admin",
                            operation_type="PolicyEval",
                            finding_statement=finding
                        ))


def evaluate_all_inline_policies():
    ## Evaluates inline policies for IAM identities (users, groups, roles)
    ## For non-inline identity policies (AWS-managed & customer-managed), see other operation (evaluate_all_relevant_noninline_policies).

    identity_types = ['User', 'Group', 'Role']
    for identity_type in identity_types:
        for identity in auth_result[f"{identity_type}DetailList"]:
            name = identity[f"{identity_type}Name"]
            arn = identity['Arn']
            ## Check if inline policies exist
            if f"{identity_type}PolicyList" in identity:
                inline_policies = identity[f"{identity_type}PolicyList"]
                ## if so, go through list of inlines
                for inl_policy in inline_policies:
                    policy_name = inl_policy['PolicyName']
                    policy_doc = inl_policy['PolicyDocument']
                    statements = policy_doc["Statement"]
                    if not isinstance(statements, list):
                        statements = [statements]
                    for statement in statements:
                        ## Evaluate the policy document against elevated privileges. See logic in the referenced function.
                        if check_statement_for_full_admin(statement):
                            finding = f"Inline policy \"{policy_name}\" for {identity_type} \"{name}\" contains policy statement for full-admin privileges."
                            findings_list_policy.append(FindingsListPolicy(
                                policy_name=policy_name,
                                policy_arn=arn,
                                policy_type="Inline",
                                check_id="full-admin",
                                operation_type="PolicyEval",
                                finding_statement=finding
                            ))
                            identity_finding = f"{identity_type} \"{name}\" provides full-admin privileges via inline policy: \"{policy_name}\"."
                            findings_list = findings_list_user if identity_type == 'User' else findings_list_group if identity_type == 'Group' else findings_list_role
                            ## Append data to the class model.
                            findings_list.append(FindingsList(
                                identity_name=name,
                                identity_arn=arn,
                                finding_statement=identity_finding,
                                check_id="full-admin",
                                operation_type="InlineEval",
                                policy_name=policy_name,
                                policy_arn=arn
                            ))


def evaluate_all_via_attached_policies():
    identity_types = ['User', 'Group', 'Role']
    for identity_type in identity_types:
        for identity in auth_result[f"{identity_type}DetailList"]:
            name = identity[f"{identity_type}Name"]
            arn = identity['Arn']
            attached_policies = identity['AttachedManagedPolicies']
            ## Check if attached policies exist
            if attached_policies:
                for attached_policy in attached_policies:
                    policy_arn = attached_policy['PolicyArn']
                    policy_name = attached_policy['PolicyName']
                    ## Check if has elevated privileges
                    for finding in findings_list_policy:
                        if finding.policy_arn == policy_arn:
                            finding_statement = f"{identity_type} \"{name}\" provides full-admin privileges via attached {finding.policy_type} policy: \"{policy_name}\"."
                            findings_list = findings_list_user if identity_type == 'User' else findings_list_group if identity_type == 'Group' else findings_list_role
                            findings_list.append(FindingsList(
                                identity_name=name,
                                identity_arn=arn,
                                finding_statement=finding_statement,
                                check_id=finding.check_id,
                                operation_type="AttachedEval",
                                policy_name=policy_name,
                                policy_arn=policy_arn
                            ))


def find_users_admin_via_group_association():
    for identity in auth_result["UserDetailList"]:
        name = identity["UserName"]
        arn = identity['Arn']
        group_list = identity['GroupList']
        if group_list:
            for group in group_list:
                for group_finding in findings_list_group:
                    if group == group_finding.identity_name:
                        finding = f"User \"{name}\" provides full-admin privileges from group association, in which: {group_finding.finding_statement}"
                        ## Append data to the class model.
                        findings_list_user.append(FindingsList(
                            identity_name=name,
                            identity_arn=arn,
                            group_name=group,
                            group_arn=group_finding.identity_arn,
                            finding_statement=finding,
                            check_id="full-admin",
                            operation_type="UserGroupEval"
                        ))


def check_statement_for_full_admin(statement):
    ## check_id: full_admin
    if (
        statement["Effect"] == "Allow"
        and "Action" in statement
        and (statement["Action"] == "*" or statement["Action"] == ["*"])
        and (statement["Resource"] == "*" or statement["Resource"] == ["*"])
    ):
        return True
    else:
        return False


def append_to_csv_list(account_id, account_name, resource_type, resource_name, identity_arn, policy_arn, finding_statement):
    aggregated_findings_list.append([account_id, account_name, resource_type, resource_name, identity_arn, policy_arn, finding_statement])


def report_output():
    for finding in findings_list_policy:
        resource_name = finding.policy_name
        policy_arn = finding.policy_arn
        finding_statement = finding.finding_statement

        if finding.finding_statement.startswith("Customer-Managed policy"):
            resource_type = "policy-customer-managed"
        if finding.finding_statement.startswith("AWS-Managed policy"):
            resource_type = "policy-aws-managed"
        if finding.finding_statement.startswith("Inline policy"):
            resource_type = "policy-inline"
        append_to_csv_list(account_id, account_name, resource_type, resource_name, "", policy_arn, finding_statement)

    for findings_list in [findings_list_user, findings_list_group, findings_list_role]:
        for finding in findings_list:
            resource_name = finding.identity_name
            identity_arn = finding.identity_arn
            policy_arn = finding.policy_arn if finding.policy_arn else identity_arn
            finding_statement = finding.finding_statement

            if finding.finding_statement.startswith("User"):
                resource_type = "user"
            if finding.finding_statement.startswith("Group"):
                resource_type = "group"
            if finding.finding_statement.startswith("Role"):
                resource_type = "role"
            append_to_csv_list(account_id, account_name, resource_type, resource_name, identity_arn, policy_arn, finding.finding_statement)


def report():
    evaluate_all_relevant_noninline_policies(account_id)
    evaluate_all_inline_policies()
    evaluate_all_via_attached_policies()
    find_users_admin_via_group_association()
    report_output()


## Function to do work in the management account
def do_work_in_mgmt(profile_name=None): 
    print(f"\n   ADMIN PRIVILEGES AUDIT - AWS IAM\n")

    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client('sts', region_name='us-east-1')
    mgmt_account_number = sts_client.get_caller_identity()['Account']
    global account_id
    account_id = mgmt_account_number
    global account_name
    account_name = 'Management Account'

    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{mgmt_account_number}:role/ccoe-auditor-management-role",
            RoleSessionName="AssumeAuditorRoleSessionInMemberAcct"
        )
        global credentials_auditor_member
        credentials_auditor_member = assumed_role['Credentials']

    except:
        print("Could not assume auditor manager role.", file=sys.stderr)
        sys.exit()


    print(f"Processing account {account_name} (ID: {account_id}).\n", file=sys.stderr)
    
    ## Reset findings lists for each account
    global findings_list_policy, findings_list_user, findings_list_group, findings_list_role
    findings_list_policy = []
    findings_list_user = []
    findings_list_group = []
    findings_list_role = []

    get_data(aws_profile)
    report()


## Function to do work in other accounts in the organization
def do_work_in_org(profile_name=None):

    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client('sts', region_name='us-east-1')
    mgmt_account_number = sts_client.get_caller_identity()['Account']

    ## Assume AuditorRole in management account
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{mgmt_account_number}:role/ccoe-auditor-management-role",
            RoleSessionName="AssumeAuditorRoleSessionInMemberAcct"
        )
        credentials_auditor_manager = assumed_role['Credentials']
    except:
        print("Could not assume auditor manager role.", file=sys.stderr)
        sys.exit()

    ## List all accounts in the organization using paginator
    org_client = boto3.client(
        'organizations',
        aws_access_key_id=credentials_auditor_manager['AccessKeyId'],
        aws_secret_access_key=credentials_auditor_manager['SecretAccessKey'],
        aws_session_token=credentials_auditor_manager['SessionToken']
    )

    paginator_accts = org_client.get_paginator('list_accounts')
    for page in paginator_accts.paginate():
        accounts = page['Accounts']
        
        for account in accounts:
            global account_id, account_name
            account_id = account['Id']
            account_name = account['Name']
            ## Skip the current account
            if account_id != mgmt_account_number:
                
                print(f"Processing account {account_name} (ID: {account_id}).\n", file=sys.stderr)
                
                ## Reset findings lists for each account
                global findings_list_policy, findings_list_user, findings_list_group, findings_list_role
                findings_list_policy = []
                findings_list_user = []
                findings_list_group = []
                findings_list_role = []

                ## Assume AuditorRole in member account
                sts_assume_role_member_client = boto3.client(
                    'sts',
                    aws_access_key_id=credentials_auditor_manager['AccessKeyId'],
                    aws_secret_access_key=credentials_auditor_manager['SecretAccessKey'],
                    aws_session_token=credentials_auditor_manager['SessionToken']
                )
                try:
                    assumed_role = sts_assume_role_member_client.assume_role(
                        RoleArn=f"arn:aws:iam::{account_id}:role/ccoe-auditor-members-role",
                        RoleSessionName="AssumeAuditorRoleSessionInMemberAcct"
                    )
                    global credentials_auditor_member
                    credentials_auditor_member = assumed_role['Credentials']

                except Exception as e:
                    print(f"Error: {e}")
                    print(f"Error: {e}", file=sys.stderr)

                get_data(aws_profile)
                report()



def output_aggregated_findings_as_csv(aggregated_findings_list, filename):

    header = ['accountId', 'accountName', 'resourceType', 'resourceName', 'identityArn', 'policyArn', 'findingStatement']
    with open(output_file, mode='w', newline='') as file:
        csv_writer = csv.writer(file)
        
        ## Write header to the file
        csv_writer.writerow(header)
        
        ## Write each row of findings to the file
        for row in aggregated_findings_list:
            csv_writer.writerow(row)
            
            ## Also print the row to the screen
            print(','.join(row))
            
    print(f"\nCSV file created: {output_file}\n")

                
## The starter: 
## First, check if a profile name is passed as an argument. If not, then check if environment variables are set. 
if __name__ == "__main__":
    aws_profile = None
    
    if len(sys.argv) == 2:
        aws_profile = sys.argv[1]
        try:
            test_session = boto3.Session(profile_name=aws_profile)
        except Exception as e:
            print(f"\nError: {e}", file=sys.stderr)
            print("\nPlease check your AWS credentials and try again.\n", file=sys.stderr)
            sys.exit(1)

    elif aws_profile is None: 
        if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
            try:
                test_client = boto3.client('sts', region_name='us-east-1')
                mgmt_account_number = test_client.get_caller_identity()['Account']
            except Exception as e:
                print(f"\nError: {e}", file=sys.stderr)
                print("\nPlease check your AWS credentials and try again.\n", file=sys.stderr)
                sys.exit(1)
        else:
            print("\nError: No AWS profile name was passed in argument, nor temporary credentials found in environment variables.", file=sys.stderr)
            print("\n\tUse either a valid AWS local profile or set valid temporary credentials into your environment variables.", file=sys.stderr)
            print("\n\tExample usage with a valid AWS local profile:", file=sys.stderr)
            print("\tpython script_name.py <aws_profile>", file=sys.stderr)
            print("\n\tSee:", file=sys.stderr)
            print("\thttps://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html\n", file=sys.stderr)
            sys.exit(1)
    
    ## Initiate task(s) while passing the aws_profile:
    do_work_in_mgmt(aws_profile)
    do_work_in_org(aws_profile)
    print(aggregated_findings_list)
    output_aggregated_findings_as_csv(aggregated_findings_list, output_file)
