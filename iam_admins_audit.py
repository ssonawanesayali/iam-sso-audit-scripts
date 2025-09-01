import boto3
import sys
import os
from pydantic import BaseModel
from typing import Optional


#######################################################################################
## ABOUT:
## This script evaluates all the IAM identities in an account for admin privileges. 
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



## Data model for list of findings from the policies analysis.
class FindingsListPolicy(BaseModel):
    policy_name: str
    policy_arn: str ## (if policy_type "Inline", then this is Arn of identity.)
    policy_type: str ## ("Inline" | "Customer-Managed" | "AWS-Managed")
    check_id: str = "CHECK_ID" ## "full-admin"
    operation_type: Optional[str] = ""
    finding_statement: str

## Data model for list of findings from identities analysis (i.e. users, groups, or roles).
class FindingsList(BaseModel):
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
    # finding_notes: Optional[str] = ""

## The check_id attribute in the above data models was meant to leave a place to develop for other types of checks, other than for "full_admin".

findings_list_policy = []

findings_list_user = []

findings_list_group = []

findings_list_role = []


def get_data(profile_name=None):
    REGION = 'us-east-1'
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client('sts', region_name=REGION)
    account_id = sts_client.get_caller_identity()["Account"]

    print("")
    print("")
    print("---------------------------------------------------------------------------------------------------------")
    print("")
    print(f"ADMIN PRIVILEGES AUDIT - AWS IAM - Account: {account_id}")

    iam_client = session.client('iam', region_name=REGION)

    ## Get all the information to be evaluated from "get-account-authorization-details" API output. 
    ## In terms of AWS policies, this includes all AWS-managed policies utilized, and all customer-managed policies. 
    auth_pages = iam_client.get_paginator('get_account_authorization_details').paginate()
    global auth_result
    auth_result = auth_pages.build_full_result()
    # print(f"\n\n{auth_result}\n\n")


def evaluate_all_relevant_noninline_policies():
    ## Evaluates IAM policies being used by the customer in account (non-inline).
    ## NOTE:
    ## This includes ALL customer-managed policies, even if unattached.
    ## This does NOT include all AWS-Managed policies, since that's too many - only the attached ones being used in account. 
    ## This does NOT include inline policies.  (See other operation "evaluate_all_inline_policies".)

    for policy in auth_result["Policies"]:
        policy_name=policy['PolicyName']
        policy_arn=policy['Arn']
        for document in policy['PolicyVersionList']:
            if (document['IsDefaultVersion']) == True:
                policy_doc=policy['PolicyVersionList'][0]['Document']
                if not isinstance(policy_doc["Statement"], list):
                    statements = [policy_doc["Statement"]]
                else:
                    statements = policy_doc["Statement"]
                for statement in statements:
                    ## check_statement_for_full_admin
                    check_id="full-admin"

                    ## Evaluate the policy document against elevated privileges. See logic in the referenced function.
                    has_elevated_privileges = check_statement_for_full_admin(statement)
                    if has_elevated_privileges == True:
                        policy_type="Customer-Managed"
                        if policy_arn.startswith("arn:aws:iam::aws:"):
                             policy_type="AWS-Managed"
                        finding = "{0} policy \"{1}\" contains policy statement for {2} privileges.".format(policy_type, policy_name, check_id)
                        
                        findings_list_policy.append(FindingsListPolicy(
                            policy_name=policy_name,
                            policy_arn=policy_arn,
                            policy_type=policy_type,
                            check_id=check_id,
                            operation_type="PolicyEval",
                            finding_statement=finding
                        ))


def evaluate_all_inline_policies():
    ## Evaluates inline policies for IAM identities (users, groups, roles)
    ## For non-inline identity policies (AWS-managed & customer-managed), see other operation (evaluate_all_relevant_noninline_policies).

    identity_types = ['User', 'Group', 'Role']
    for identity_type in identity_types:
        for identity in auth_result[f"{identity_type}DetailList"]:
            inline_policies = []
            policy_doc = {}
            try:
                name=identity[f"{identity_type}Name"]
            except:
                print("SOMETHING BAD HAPPENED")
            arn=identity['Arn']
            ## check if inline policies exist
            if f"{identity_type}PolicyList" in identity:
                inline_policies=identity[f"{identity_type}PolicyList"]
                ## if so, go through list of inlines
                for inl_policy in inline_policies:
                    policy_name=inl_policy['PolicyName']
                    policy_doc=inl_policy['PolicyDocument']
                    if not isinstance(policy_doc["Statement"], list):
                        statements = [policy_doc["Statement"]]
                    else:
                        statements = policy_doc["Statement"]
                    for statement in statements:
                        
                        ## Evaluate the policy document against elevated privileges. See logic in the referenced function.
                        has_elevated_privileges = check_statement_for_full_admin(statement)
                        if has_elevated_privileges == True:
                            check_id="full-admin"
                            policy_type = "Inline"
                            finding = "{0} policy \"{1}\" for {2} \"{3}\" contains policy statement for {4} privileges.".format(policy_type, policy_name, identity_type, name, check_id)

                            ## Append data to the class model.
                            findings_list_policy.append(FindingsListPolicy(
                                policy_name=policy_name,
                                policy_arn=arn,
                                policy_type=policy_type,
                                check_id=check_id,
                                operation_type="PolicyEval",
                                finding_statement=finding
                            ))
                            identity_finding = "{0} \"{1}\" provides {2} privileges via {3} policy: \"{4}\".".format(identity_type, name, check_id, policy_type, policy_name)

                            if identity_type == 'User':
                                findings_list = findings_list_user
                            elif identity_type == 'Group':
                                findings_list = findings_list_group
                            elif identity_type == 'Role':
                                findings_list = findings_list_role
                            findings_list.append(FindingsList(
                                identity_name=name,
                                identity_arn=arn,
                                finding_statement=identity_finding,
                                check_id=check_id,
                                operation_type="InlineEval",
                                policy_name=policy_name,
                                policy_arn=arn
                            ))


def evaluate_all_via_attached_policies():
    identity_types = ['User', 'Group', 'Role']
    for identity_type in identity_types:
        for identity in auth_result[f"{identity_type}DetailList"]:
            name=identity[f"{identity_type}Name"]
            arn=identity['Arn']
            attached_policies=identity['AttachedManagedPolicies']
            ## check if attached policies exist
            if attached_policies:
                for attached_policy in attached_policies:
                    policy_arn=attached_policy['PolicyArn']
                    policy_name=attached_policy['PolicyName']
                    ## check if has elevated privileges
                    for finding in findings_list_policy:
                        if finding.policy_arn == policy_arn:

                            check_id = finding.check_id
                            finding = "{0} \"{1}\" provides {2} privileges via attached {3} policy: \"{4}\".".format(identity_type, name, check_id, finding.policy_type, policy_name)

                            if identity_type == 'User':
                                findings_list = findings_list_user
                            elif identity_type == 'Group':
                                findings_list = findings_list_group
                            elif identity_type == 'Role':
                                findings_list = findings_list_role

                            ## Append data to the class model.
                            findings_list.append(FindingsList(
                                identity_name=name,
                                identity_arn=arn,
                                finding_statement=finding,
                                check_id=check_id,
                                operation_type="AttachedEval",
                                policy_name=policy_name,
                                policy_arn=policy_arn
                            ))


def find_users_admin_via_group_association():
    group_list = []
    for identity in auth_result["UserDetailList"]:
        name=identity["UserName"]
        arn=identity['Arn']
        group_list=identity['GroupList']
        ## check if groups in group_list
        if group_list:
            for group in group_list:
                ## check if group exists in findings_list_group
                for group_finding in findings_list_group:
                    if group == group_finding.identity_name:
                        check_id = group_finding.check_id
                        group_arn = group_finding.identity_arn

                        finding = "User \"{0}\" provides {1} privileges from group association, in which: {2}".format(name, check_id, group_finding.finding_statement)
                        
                        ## Append data to the class model.
                        findings_list_user.append(FindingsList(
                            identity_name=name,
                            identity_arn=arn,
                            group_name=group,
                            group_arn=group_arn,
                            check_id=check_id,
                            operation_type="UserGroupEval",
                            finding_statement=finding
                        ))


def evaluate_role_trust_policy():
    ## get the unique roles in findings
    get_roles_in_findings = [x.identity_arn for x in findings_list_role]
    get_roles_in_findings.sort()
    roles_in_findings = set(get_roles_in_findings)
    for role in roles_in_findings:
        ## get temp dictionary for roles details (to get trust policies)
        temp_dict = {d["Arn"]: d for d in auth_result["RoleDetailList"]}
        identity = temp_dict[role]
        role_check = check_statement_for_assume_role(identity)
        ## TODO: refactor if can consolidate here.


def check_statement_for_assume_role(identity):
    policy_doc = {}
    name=identity["RoleName"]
    arn=identity['Arn']
    trusting_aws_account=arn.split(':')[4]
    trust_policydoc=identity['AssumeRolePolicyDocument']
    for statement in trust_policydoc['Statement']:

        principal = statement['Principal']
        effect = statement['Effect']
        action = statement['Action']
        if 'AWS' in principal and effect == "Allow" and action == 'sts:AssumeRole':
            trusted_arn = principal['AWS']
            if ':role/' in trusted_arn:
                trusted_identity_type = "Role"
            if ':user/' in trusted_arn:
                trusted_identity_type = "User"
            if ':group/' in trusted_arn:
                trusted_identity_type = "Group"
            else:
                trusted_identity_type = "Other"
            if trusted_identity_type != "Other":
                trusted_aws_account = trusted_arn.split(':')[4]
            else:
                ## In the case where the Arn is not known (such as if IAM entity has been deleted)
                trusted_aws_account = "UNKNOWN-ACCOUNT"
            cross_account = False
            cross_account_notes = "same AWS account"
            if trusted_aws_account != trusting_aws_account:
                cross_account = True
                cross_account_notes = f"EXTERNAL AWS Acct {trusted_aws_account}"
            finding = "Policy \"{0}\" trusts {1} \"{2}\" ({3}).".format(name, trusted_identity_type, trusted_arn, cross_account_notes)
            if trusted_identity_type == "User":
                ## get the findings (check_id's) for the role to provide context in user findings
                check_id_list = []
                for x in findings_list_role:
                    check_id_list.append(x.check_id)
                check_id_list_unique = set(check_id_list)
                check_ids = ", ".join(check_id_list_unique)
                user_name = trusted_arn.split('/')[-1]

                finding = "User \"{0}\" (which belongs to {1}) can assume {2} privileges associated to Role \"{3}\", per its trust policy.".format(user_name, cross_account_notes, check_ids, name)

                ## Append data to the class model.
                findings_list_user.append(FindingsList(
                    identity_name=user_name,
                    identity_arn=trusted_arn,
                    role_name=name,
                    role_arn=arn,
                    check_id=check_ids,
                    operation_type="RoleTrustEval",
                    finding_statement=finding
                ))
            
            #if trusted_identity_type == "Role":
            ## TODO: evaluate here for roles that provide admin rights, what identities are allowed to assume it in its trust policy.


def check_statement_for_full_admin(statement):
    ## check_id: full_admin
    if (
        statement["Effect"] == "Allow" 
        and "Action" in statement
        and (
        statement["Action"] == "*" 
        or statement["Action"] == ["*"]
        )
        and (
        statement["Resource"] == "*"
        or statement["Resource"] == ["*"]  
        )
    ):
        return True
    else:
        return False


def report():
    
    evaluate_all_relevant_noninline_policies()
    evaluate_all_inline_policies()
    evaluate_all_via_attached_policies()
    find_users_admin_via_group_association()
    evaluate_role_trust_policy()
    
    findings_list_user_count = len(findings_list_user)
    findings_list_group_count = len(findings_list_group)
    findings_list_role_count = len(findings_list_role)
    findings_list_policy_count = len(findings_list_policy)

    ## get the unique users in findings
    
    get_roles_in_findings = [x.identity_arn for x in findings_list_role]
    get_roles_in_findings.sort()
    roles_in_findings = set(get_roles_in_findings)

    ## Print out the user findings.
    print("")
    print(f"\t - There are {findings_list_user_count} items in the User findings list.")
    ## Sort this by identity_name
    u_sorted = sorted(findings_list_user, key=lambda x: x.identity_name)
    for finding in u_sorted:
        # print(finding.operation_type, finding.check_id, finding.identity_arn, finding.finding_statement, finding.policy_arn)
        # print("{0} done: {1}".format(finding.operation_type, finding.finding_statement))
        print(finding.finding_statement)
    print("")

    ## Print out the group findings.  
    print("")
    print(f"\t - There are {findings_list_group_count} items in the Group findings list.")
    u_sorted = sorted(findings_list_group, key=lambda x: x.identity_name)
    for finding in u_sorted:
        # print(finding.operation_type, finding.check_id, finding.identity_arn, finding.finding_statement, finding.policy_arn)
        print(finding.finding_statement)
    print("")

    ## Print out the role findings.  
    print("")
    print(f"\t - There are {findings_list_role_count} items in the Role findings list.")
    u_sorted = sorted(findings_list_role, key=lambda x: x.identity_name)
    for finding in u_sorted:
        # print(finding.operation_type, finding.check_id, finding.identity_arn, finding.finding_statement, finding.policy_arn)
        print(finding.finding_statement)
    print("")

    ## Print out the policy findings.  
    print("")
    print(f"\t - There are {findings_list_policy_count} items in the Policy findings list.")
    for finding in findings_list_policy:
        # print(finding.operation_type, finding.check_id, finding.finding_statement, finding.policy_arn)
        print(finding.finding_statement)
    print("")
    print("")
    # print("---------------------------------------------------------------------------------------------------------")


def get_profile_from_env():
    ## Check if environment variables are set for AWS credentials
    if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
        access_key = os.getenv('AWS_ACCESS_KEY_ID')
        secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        session_token = os.getenv('AWS_SESSION_TOKEN')

        if access_key and secret_key and session_token:
            session_args = {
                'aws_access_key_id': access_key,
                'aws_secret_access_key': secret_key,
                'aws_session_token': session_token
            }

if __name__ == "__main__":
    aws_profile = None
    
    if len(sys.argv) == 2:
        aws_profile = sys.argv[1]

    elif aws_profile is None:
        aws_profile = get_profile_from_env()    
    
    else:
        print("Usage: python script_name.py <aws_profile>")
        sys.exit(1)
    
    get_data(aws_profile)
    report()

## TODO: 
##  - list all users
##  - list all users with full-admin
##  - list all users that have console access disabled
##  - MFA, where console access is enabled
##  - password age
##  - access key age
##  - rotations needed (passwords/keys)
##  - password last used 
##  - access key last used
##  - last login over (60/90) days
##  - evaluate roles for ALL cross account trust permissions
##  - evaluate & report on the trust policies of roles that provide full-admin