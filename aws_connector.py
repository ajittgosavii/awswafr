"""
AWS Organization Connector Module
Enterprise multi-account AWS integration for Well-Architected Reviews

Features:
- AWS Organizations integration for account discovery
- Cross-account role assumption (OrganizationAccountAccessRole)
- Multi-account resource inventory
- Cost Explorer aggregation
- Security Hub findings consolidation
- AWS Config compliance status
- Trusted Advisor recommendations
- Well-Architected Tool integration
- Automatic credential loading from Streamlit secrets
"""

import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import concurrent.futures
import time

# Import secrets helper - make it truly optional
SECRETS_HELPER_AVAILABLE = False
get_aws_credentials = None
get_aws_organization_config = None
get_aws_regions_config = None
get_app_config = None
render_secrets_status = None
render_manual_credentials_input = None
AWSCredentials = None

try:
    from .secrets_helper import (
        get_aws_credentials as _get_aws_credentials,
        get_aws_organization_config as _get_aws_organization_config,
        get_aws_regions_config as _get_aws_regions_config,
        get_app_config as _get_app_config,
        render_secrets_status as _render_secrets_status,
        render_manual_credentials_input as _render_manual_credentials_input,
        AWSCredentials as _AWSCredentials
    )
    get_aws_credentials = _get_aws_credentials
    get_aws_organization_config = _get_aws_organization_config
    get_aws_regions_config = _get_aws_regions_config
    get_app_config = _get_app_config
    render_secrets_status = _render_secrets_status
    render_manual_credentials_input = _render_manual_credentials_input
    AWSCredentials = _AWSCredentials
    SECRETS_HELPER_AVAILABLE = True
except ImportError:
    try:
        from modules.secrets_helper import (
            get_aws_credentials as _get_aws_credentials,
            get_aws_organization_config as _get_aws_organization_config,
            get_aws_regions_config as _get_aws_regions_config,
            get_app_config as _get_app_config,
            render_secrets_status as _render_secrets_status,
            render_manual_credentials_input as _render_manual_credentials_input,
            AWSCredentials as _AWSCredentials
        )
        get_aws_credentials = _get_aws_credentials
        get_aws_organization_config = _get_aws_organization_config
        get_aws_regions_config = _get_aws_regions_config
        get_app_config = _get_app_config
        render_secrets_status = _render_secrets_status
        render_manual_credentials_input = _render_manual_credentials_input
        AWSCredentials = _AWSCredentials
        SECRETS_HELPER_AVAILABLE = True
    except ImportError:
        pass
except Exception:
    pass

# ============================================================================
# CONFIGURATION
# ============================================================================

AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
    "sa-east-1", "ca-central-1", "me-south-1", "af-south-1"
]

# Standard cross-account role name
CROSS_ACCOUNT_ROLE = "OrganizationAccountAccessRole"

# Alternative role names to try
ALTERNATIVE_ROLES = [
    "OrganizationAccountAccessRole",
    "AWSControlTowerExecution",
    "WAFAdvisorCrossAccountRole",
    "AuditRole"
]

# Boto3 config for retries
BOTO_CONFIG = Config(
    retries={'max_attempts': 3, 'mode': 'adaptive'},
    connect_timeout=10,
    read_timeout=30
)


class AccountStatus(Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    PENDING_CLOSURE = "PENDING_CLOSURE"


@dataclass
class AWSAccount:
    """Represents an AWS Account in the organization"""
    id: str
    name: str
    email: str
    status: str
    arn: str
    joined_method: str = ""
    joined_timestamp: datetime = None
    ou_path: str = ""
    tags: Dict = field(default_factory=dict)
    accessible: bool = False
    role_used: str = ""


@dataclass
class OrganizationInfo:
    """AWS Organization information"""
    id: str
    arn: str
    master_account_id: str
    master_account_email: str
    feature_set: str
    accounts: List[AWSAccount] = field(default_factory=list)
    organizational_units: Dict = field(default_factory=dict)
    policies: List[Dict] = field(default_factory=list)


# ============================================================================
# AWS SESSION MANAGER
# ============================================================================

class AWSSessionManager:
    """Manages AWS sessions including cross-account access"""
    
    def __init__(self):
        self.master_session = None
        self.assumed_sessions = {}
        self.organization = None
        self._credentials_source = None
    
    def initialize_from_credentials(self, access_key: str, secret_key: str, 
                                    session_token: str = None, region: str = "us-east-1") -> bool:
        """Initialize with explicit credentials"""
        try:
            self.master_session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region
            )
            self._credentials_source = "explicit"
            return self._verify_credentials()
        except Exception as e:
            st.error(f"Failed to initialize AWS session: {e}")
            return False
    
    def initialize_from_profile(self, profile_name: str, region: str = "us-east-1") -> bool:
        """Initialize from AWS profile"""
        try:
            self.master_session = boto3.Session(
                profile_name=profile_name,
                region_name=region
            )
            self._credentials_source = f"profile:{profile_name}"
            return self._verify_credentials()
        except Exception as e:
            st.error(f"Failed to initialize from profile: {e}")
            return False
    
    def initialize_from_environment(self, region: str = "us-east-1") -> bool:
        """Initialize from environment variables or instance profile"""
        try:
            self.master_session = boto3.Session(region_name=region)
            self._credentials_source = "environment/instance"
            return self._verify_credentials()
        except Exception as e:
            st.error(f"Failed to initialize from environment: {e}")
            return False
    
    def _verify_credentials(self) -> bool:
        """Verify credentials are valid"""
        try:
            sts = self.master_session.client('sts', config=BOTO_CONFIG)
            identity = sts.get_caller_identity()
            st.session_state.aws_identity = identity
            return True
        except Exception as e:
            st.error(f"Invalid AWS credentials: {e}")
            return False
    
    def get_caller_identity(self) -> Dict:
        """Get current AWS identity"""
        if not self.master_session:
            return {}
        try:
            sts = self.master_session.client('sts', config=BOTO_CONFIG)
            return sts.get_caller_identity()
        except Exception:
            return {}
    
    def assume_role(self, account_id: str, role_name: str = None, 
                    session_name: str = "WAFAdvisor") -> Optional[boto3.Session]:
        """Assume role in target account"""
        if not self.master_session:
            return None
        
        # Check cache first
        cache_key = f"{account_id}:{role_name}"
        if cache_key in self.assumed_sessions:
            return self.assumed_sessions[cache_key]
        
        roles_to_try = [role_name] if role_name else ALTERNATIVE_ROLES
        
        for role in roles_to_try:
            try:
                sts = self.master_session.client('sts', config=BOTO_CONFIG)
                role_arn = f"arn:aws:iam::{account_id}:role/{role}"
                
                response = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=3600
                )
                
                credentials = response['Credentials']
                assumed_session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=self.master_session.region_name
                )
                
                self.assumed_sessions[cache_key] = assumed_session
                return assumed_session
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    continue
                raise
        
        return None
    
    def get_session_for_account(self, account_id: str) -> Optional[boto3.Session]:
        """Get session for specific account (master or assumed)"""
        identity = self.get_caller_identity()
        if identity.get('Account') == account_id:
            return self.master_session
        return self.assume_role(account_id)


# ============================================================================
# ORGANIZATION DISCOVERY
# ============================================================================

class OrganizationDiscovery:
    """Discovers and maps AWS Organization structure"""
    
    def __init__(self, session_manager: AWSSessionManager):
        self.session_manager = session_manager
        self.org_client = None
    
    def discover_organization(self) -> Optional[OrganizationInfo]:
        """Discover the AWS Organization structure"""
        if not self.session_manager.master_session:
            return None
        
        try:
            self.org_client = self.session_manager.master_session.client(
                'organizations', config=BOTO_CONFIG
            )
            
            # Get organization details
            org_response = self.org_client.describe_organization()
            org = org_response['Organization']
            
            org_info = OrganizationInfo(
                id=org['Id'],
                arn=org['Arn'],
                master_account_id=org['MasterAccountId'],
                master_account_email=org['MasterAccountEmail'],
                feature_set=org['FeatureSet']
            )
            
            # Discover accounts
            org_info.accounts = self._list_all_accounts()
            
            # Discover OUs
            org_info.organizational_units = self._discover_ou_structure()
            
            # Map accounts to OUs
            self._map_accounts_to_ous(org_info)
            
            # Check account accessibility
            self._check_account_accessibility(org_info)
            
            return org_info
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                st.warning("This AWS account is not part of an AWS Organization")
            else:
                st.error(f"Failed to discover organization: {e}")
            return None
    
    def _list_all_accounts(self) -> List[AWSAccount]:
        """List all accounts in the organization"""
        accounts = []
        paginator = self.org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page['Accounts']:
                aws_account = AWSAccount(
                    id=account['Id'],
                    name=account['Name'],
                    email=account['Email'],
                    status=account['Status'],
                    arn=account['Arn'],
                    joined_method=account.get('JoinedMethod', ''),
                    joined_timestamp=account.get('JoinedTimestamp')
                )
                
                # Get account tags
                try:
                    tags_response = self.org_client.list_tags_for_resource(
                        ResourceId=account['Id']
                    )
                    aws_account.tags = {
                        tag['Key']: tag['Value'] 
                        for tag in tags_response.get('Tags', [])
                    }
                except Exception:
                    pass
                
                accounts.append(aws_account)
        
        return accounts
    
    def _discover_ou_structure(self) -> Dict:
        """Discover Organizational Unit structure"""
        ous = {}
        
        try:
            # Get root
            roots = self.org_client.list_roots()['Roots']
            if not roots:
                return ous
            
            root_id = roots[0]['Id']
            ous['root'] = {'id': root_id, 'name': 'Root', 'children': [], 'accounts': []}
            
            # Recursively discover OUs
            self._discover_ous_recursive(root_id, ous, 'root')
            
        except Exception as e:
            st.warning(f"Could not discover OU structure: {e}")
        
        return ous
    
    def _discover_ous_recursive(self, parent_id: str, ous: Dict, parent_path: str):
        """Recursively discover OUs"""
        try:
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page['OrganizationalUnits']:
                    ou_path = f"{parent_path}/{ou['Name']}"
                    ous[ou['Id']] = {
                        'id': ou['Id'],
                        'name': ou['Name'],
                        'arn': ou['Arn'],
                        'path': ou_path,
                        'parent': parent_id,
                        'children': [],
                        'accounts': []
                    }
                    
                    # Add to parent's children
                    if parent_id in ous:
                        ous[parent_id]['children'].append(ou['Id'])
                    
                    # Recurse
                    self._discover_ous_recursive(ou['Id'], ous, ou_path)
                    
        except Exception:
            pass
    
    def _map_accounts_to_ous(self, org_info: OrganizationInfo):
        """Map accounts to their parent OUs"""
        for account in org_info.accounts:
            try:
                parents = self.org_client.list_parents(ChildId=account.id)
                if parents['Parents']:
                    parent_id = parents['Parents'][0]['Id']
                    if parent_id in org_info.organizational_units:
                        ou = org_info.organizational_units[parent_id]
                        account.ou_path = ou.get('path', '')
                        ou['accounts'].append(account.id)
            except Exception:
                pass
    
    def _check_account_accessibility(self, org_info: OrganizationInfo):
        """Check which accounts are accessible via role assumption"""
        master_id = org_info.master_account_id
        
        for account in org_info.accounts:
            if account.id == master_id:
                account.accessible = True
                account.role_used = "master"
                continue
            
            if account.status != "ACTIVE":
                continue
            
            # Try to assume role
            session = self.session_manager.assume_role(account.id)
            if session:
                account.accessible = True
                # Find which role worked
                for role in ALTERNATIVE_ROLES:
                    cache_key = f"{account.id}:{role}"
                    if cache_key in self.session_manager.assumed_sessions:
                        account.role_used = role
                        break


# ============================================================================
# RESOURCE INVENTORY COLLECTOR
# ============================================================================

class ResourceInventoryCollector:
    """Collects resource inventory across accounts"""
    
    def __init__(self, session_manager: AWSSessionManager):
        self.session_manager = session_manager
    
    def collect_account_inventory(self, account_id: str, regions: List[str] = None) -> Dict:
        """Collect resource inventory for a single account"""
        session = self.session_manager.get_session_for_account(account_id)
        if not session:
            return {"error": f"Cannot access account {account_id}"}
        
        regions = regions or ["us-east-1"]  # Default to us-east-1
        inventory = {
            "account_id": account_id,
            "collected_at": datetime.now().isoformat(),
            "regions": {},
            "global_resources": {},
            "summary": {}
        }
        
        # Collect global resources (IAM, S3, etc.)
        inventory["global_resources"] = self._collect_global_resources(session)
        
        # Collect regional resources
        for region in regions:
            try:
                regional_session = boto3.Session(
                    aws_access_key_id=session.get_credentials().access_key,
                    aws_secret_access_key=session.get_credentials().secret_key,
                    aws_session_token=session.get_credentials().token,
                    region_name=region
                )
                inventory["regions"][region] = self._collect_regional_resources(regional_session, region)
            except Exception as e:
                inventory["regions"][region] = {"error": str(e)}
        
        # Generate summary
        inventory["summary"] = self._generate_inventory_summary(inventory)
        
        return inventory
    
    def _collect_global_resources(self, session: boto3.Session) -> Dict:
        """Collect global (non-regional) resources"""
        global_resources = {}
        
        # IAM Users
        try:
            iam = session.client('iam', config=BOTO_CONFIG)
            users = iam.list_users()['Users']
            global_resources['iam_users'] = {
                'count': len(users),
                'users': [{'name': u['UserName'], 'created': u['CreateDate'].isoformat()} for u in users[:10]]
            }
        except Exception as e:
            global_resources['iam_users'] = {'error': str(e)}
        
        # IAM Roles
        try:
            roles = iam.list_roles()['Roles']
            global_resources['iam_roles'] = {
                'count': len(roles),
                'service_roles': len([r for r in roles if 'service-role' in r.get('Path', '')])
            }
        except Exception as e:
            global_resources['iam_roles'] = {'error': str(e)}
        
        # S3 Buckets
        try:
            s3 = session.client('s3', config=BOTO_CONFIG)
            buckets = s3.list_buckets()['Buckets']
            global_resources['s3_buckets'] = {
                'count': len(buckets),
                'buckets': [{'name': b['Name'], 'created': b['CreationDate'].isoformat()} for b in buckets[:20]]
            }
        except Exception as e:
            global_resources['s3_buckets'] = {'error': str(e)}
        
        # Route53 Hosted Zones
        try:
            route53 = session.client('route53', config=BOTO_CONFIG)
            zones = route53.list_hosted_zones()['HostedZones']
            global_resources['route53_zones'] = {
                'count': len(zones),
                'zones': [{'name': z['Name'], 'type': 'private' if z.get('Config', {}).get('PrivateZone') else 'public'} for z in zones]
            }
        except Exception as e:
            global_resources['route53_zones'] = {'error': str(e)}
        
        return global_resources
    
    def _collect_regional_resources(self, session: boto3.Session, region: str) -> Dict:
        """Collect resources for a specific region"""
        resources = {}
        
        # EC2 Instances
        try:
            ec2 = session.client('ec2', config=BOTO_CONFIG)
            instances = ec2.describe_instances()
            instance_list = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_list.append({
                        'id': instance['InstanceId'],
                        'type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'vpc': instance.get('VpcId', ''),
                        'az': instance.get('Placement', {}).get('AvailabilityZone', '')
                    })
            resources['ec2_instances'] = {
                'count': len(instance_list),
                'running': len([i for i in instance_list if i['state'] == 'running']),
                'instances': instance_list[:20]
            }
        except Exception as e:
            resources['ec2_instances'] = {'error': str(e)}
        
        # VPCs
        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
            resources['vpcs'] = {
                'count': len(vpcs),
                'vpcs': [{'id': v['VpcId'], 'cidr': v['CidrBlock'], 'default': v.get('IsDefault', False)} for v in vpcs]
            }
        except Exception as e:
            resources['vpcs'] = {'error': str(e)}
        
        # RDS Instances
        try:
            rds = session.client('rds', config=BOTO_CONFIG)
            db_instances = rds.describe_db_instances()['DBInstances']
            resources['rds_instances'] = {
                'count': len(db_instances),
                'instances': [{
                    'id': db['DBInstanceIdentifier'],
                    'engine': db['Engine'],
                    'class': db['DBInstanceClass'],
                    'status': db['DBInstanceStatus'],
                    'multi_az': db.get('MultiAZ', False)
                } for db in db_instances[:10]]
            }
        except Exception as e:
            resources['rds_instances'] = {'error': str(e)}
        
        # EKS Clusters
        try:
            eks = session.client('eks', config=BOTO_CONFIG)
            clusters = eks.list_clusters()['clusters']
            cluster_details = []
            for cluster_name in clusters[:5]:
                try:
                    cluster = eks.describe_cluster(name=cluster_name)['cluster']
                    cluster_details.append({
                        'name': cluster['name'],
                        'version': cluster['version'],
                        'status': cluster['status'],
                        'endpoint': cluster.get('endpoint', '')[:50] + '...' if cluster.get('endpoint') else ''
                    })
                except Exception:
                    pass
            resources['eks_clusters'] = {
                'count': len(clusters),
                'clusters': cluster_details
            }
        except Exception as e:
            resources['eks_clusters'] = {'error': str(e)}
        
        # Lambda Functions
        try:
            lambda_client = session.client('lambda', config=BOTO_CONFIG)
            functions = lambda_client.list_functions()['Functions']
            resources['lambda_functions'] = {
                'count': len(functions),
                'functions': [{
                    'name': f['FunctionName'],
                    'runtime': f.get('Runtime', 'N/A'),
                    'memory': f.get('MemorySize', 0)
                } for f in functions[:10]]
            }
        except Exception as e:
            resources['lambda_functions'] = {'error': str(e)}
        
        # ELBv2 (ALB/NLB)
        try:
            elbv2 = session.client('elbv2', config=BOTO_CONFIG)
            lbs = elbv2.describe_load_balancers()['LoadBalancers']
            resources['load_balancers'] = {
                'count': len(lbs),
                'load_balancers': [{
                    'name': lb['LoadBalancerName'],
                    'type': lb['Type'],
                    'scheme': lb['Scheme'],
                    'state': lb['State']['Code']
                } for lb in lbs[:10]]
            }
        except Exception as e:
            resources['load_balancers'] = {'error': str(e)}
        
        return resources
    
    def _generate_inventory_summary(self, inventory: Dict) -> Dict:
        """Generate summary statistics from inventory"""
        summary = {
            'total_ec2': 0,
            'total_rds': 0,
            'total_eks': 0,
            'total_lambda': 0,
            'total_s3': inventory.get('global_resources', {}).get('s3_buckets', {}).get('count', 0),
            'total_vpcs': 0,
            'regions_with_resources': 0
        }
        
        for region, resources in inventory.get('regions', {}).items():
            if isinstance(resources, dict) and 'error' not in resources:
                summary['total_ec2'] += resources.get('ec2_instances', {}).get('count', 0)
                summary['total_rds'] += resources.get('rds_instances', {}).get('count', 0)
                summary['total_eks'] += resources.get('eks_clusters', {}).get('count', 0)
                summary['total_lambda'] += resources.get('lambda_functions', {}).get('count', 0)
                summary['total_vpcs'] += resources.get('vpcs', {}).get('count', 0)
                
                if any(resources.get(k, {}).get('count', 0) > 0 for k in resources if isinstance(resources.get(k), dict)):
                    summary['regions_with_resources'] += 1
        
        return summary


# ============================================================================
# COST EXPLORER AGGREGATOR
# ============================================================================

class CostExplorerAggregator:
    """Aggregates cost data across the organization"""
    
    def __init__(self, session_manager: AWSSessionManager):
        self.session_manager = session_manager
    
    def get_organization_costs(self, days: int = 30) -> Dict:
        """Get organization-wide cost data"""
        if not self.session_manager.master_session:
            return {"error": "No AWS session available"}
        
        try:
            ce = self.session_manager.master_session.client('ce', config=BOTO_CONFIG)
            
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get costs by account
            response = ce.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost', 'UsageQuantity'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}
                ]
            )
            
            costs_by_account = {}
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    account_id = group['Keys'][0]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    if account_id not in costs_by_account:
                        costs_by_account[account_id] = 0
                    costs_by_account[account_id] += cost
            
            # Get costs by service
            service_response = ce.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ]
            )
            
            costs_by_service = {}
            for result in service_response['ResultsByTime']:
                for group in result['Groups']:
                    service = group['Keys'][0]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    if service not in costs_by_service:
                        costs_by_service[service] = 0
                    costs_by_service[service] += cost
            
            # Sort by cost
            sorted_services = sorted(costs_by_service.items(), key=lambda x: x[1], reverse=True)
            sorted_accounts = sorted(costs_by_account.items(), key=lambda x: x[1], reverse=True)
            
            return {
                'period': f"{start_date} to {end_date}",
                'total_cost': sum(costs_by_account.values()),
                'by_account': dict(sorted_accounts),
                'by_service': dict(sorted_services[:20]),
                'account_count': len(costs_by_account),
                'currency': 'USD'
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return {"error": "Access denied to Cost Explorer. Ensure proper permissions."}
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}
    
    def get_cost_forecast(self, months: int = 3) -> Dict:
        """Get cost forecast"""
        if not self.session_manager.master_session:
            return {"error": "No AWS session available"}
        
        try:
            ce = self.session_manager.master_session.client('ce', config=BOTO_CONFIG)
            
            start_date = datetime.now().date()
            end_date = start_date + timedelta(days=months * 30)
            
            response = ce.get_cost_forecast(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Metric='UNBLENDED_COST',
                Granularity='MONTHLY'
            )
            
            return {
                'total_forecast': float(response['Total']['Amount']),
                'forecast_by_month': [
                    {
                        'period': f['TimePeriod']['Start'],
                        'mean': float(f['MeanValue']),
                        'range': (float(f['PredictionIntervalLowerBound']), 
                                 float(f['PredictionIntervalUpperBound']))
                    }
                    for f in response['ForecastResultsByTime']
                ],
                'currency': 'USD'
            }
            
        except Exception as e:
            return {"error": str(e)}


# ============================================================================
# SECURITY HUB AGGREGATOR
# ============================================================================

class SecurityHubAggregator:
    """Aggregates Security Hub findings across the organization"""
    
    def __init__(self, session_manager: AWSSessionManager):
        self.session_manager = session_manager
    
    def get_organization_findings(self, max_findings: int = 100) -> Dict:
        """Get Security Hub findings across the organization"""
        if not self.session_manager.master_session:
            return {"error": "No AWS session available"}
        
        try:
            securityhub = self.session_manager.master_session.client('securityhub', config=BOTO_CONFIG)
            
            # Get findings with high severity
            response = securityhub.get_findings(
                Filters={
                    'SeverityLabel': [
                        {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
                        {'Value': 'HIGH', 'Comparison': 'EQUALS'}
                    ],
                    'WorkflowStatus': [
                        {'Value': 'NEW', 'Comparison': 'EQUALS'},
                        {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
                    ],
                    'RecordState': [
                        {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
                    ]
                },
                MaxResults=min(max_findings, 100)
            )
            
            findings = response['Findings']
            
            # Categorize findings
            by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            by_account = {}
            by_type = {}
            
            for finding in findings:
                severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
                account = finding.get('AwsAccountId', 'Unknown')
                finding_type = finding.get('Types', ['Unknown'])[0]
                
                by_severity[severity] = by_severity.get(severity, 0) + 1
                by_account[account] = by_account.get(account, 0) + 1
                by_type[finding_type] = by_type.get(finding_type, 0) + 1
            
            return {
                'total_findings': len(findings),
                'by_severity': by_severity,
                'by_account': by_account,
                'by_type': dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]),
                'critical_findings': [
                    {
                        'title': f.get('Title', ''),
                        'account': f.get('AwsAccountId', ''),
                        'resource': f.get('Resources', [{}])[0].get('Id', ''),
                        'compliance': f.get('Compliance', {}).get('Status', ''),
                        'recommendation': f.get('Remediation', {}).get('Recommendation', {}).get('Text', '')
                    }
                    for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL'
                ][:10]
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAccessException':
                return {"error": "Security Hub not enabled or access denied"}
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}


# ============================================================================
# CONFIG COMPLIANCE CHECKER
# ============================================================================

class ConfigComplianceChecker:
    """Checks AWS Config compliance across the organization"""
    
    def __init__(self, session_manager: AWSSessionManager):
        self.session_manager = session_manager
    
    def get_compliance_summary(self, account_id: str = None) -> Dict:
        """Get AWS Config compliance summary"""
        session = self.session_manager.master_session
        if account_id:
            session = self.session_manager.get_session_for_account(account_id)
        
        if not session:
            return {"error": "No AWS session available"}
        
        try:
            config = session.client('config', config=BOTO_CONFIG)
            
            # Get compliance summary by config rule
            response = config.get_compliance_summary_by_config_rule()
            
            compliance = response.get('ComplianceSummary', {})
            
            # Get detailed rule compliance
            rules_response = config.describe_compliance_by_config_rule()
            
            rule_details = []
            for rule in rules_response.get('ComplianceByConfigRules', []):
                rule_details.append({
                    'rule_name': rule['ConfigRuleName'],
                    'compliance': rule['Compliance']['ComplianceType'],
                    'compliant_count': rule['Compliance'].get('ComplianceContributorCount', {}).get('CappedCount', 0)
                })
            
            return {
                'compliant_rules': compliance.get('CompliantResourceCount', {}).get('CappedCount', 0),
                'non_compliant_rules': compliance.get('NonCompliantResourceCount', {}).get('CappedCount', 0),
                'rules': rule_details[:20],
                'compliance_percentage': self._calculate_compliance_percentage(compliance)
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchConfigurationRecorderException':
                return {"error": "AWS Config not enabled"}
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}
    
    def _calculate_compliance_percentage(self, compliance: Dict) -> float:
        """Calculate compliance percentage"""
        compliant = compliance.get('CompliantResourceCount', {}).get('CappedCount', 0)
        non_compliant = compliance.get('NonCompliantResourceCount', {}).get('CappedCount', 0)
        total = compliant + non_compliant
        if total == 0:
            return 100.0
        return round((compliant / total) * 100, 1)


# ============================================================================
# WELL-ARCHITECTED TOOL INTEGRATION
# ============================================================================

class WellArchitectedToolIntegration:
    """Integrates with AWS Well-Architected Tool"""
    
    def __init__(self, session_manager: AWSSessionManager):
        self.session_manager = session_manager
    
    def list_workloads(self) -> List[Dict]:
        """List all Well-Architected workloads"""
        if not self.session_manager.master_session:
            return []
        
        try:
            wa = self.session_manager.master_session.client('wellarchitected', config=BOTO_CONFIG)
            
            workloads = []
            paginator = wa.get_paginator('list_workloads')
            
            for page in paginator.paginate():
                for workload in page['WorkloadSummaries']:
                    workloads.append({
                        'id': workload['WorkloadId'],
                        'name': workload['WorkloadName'],
                        'owner': workload.get('Owner', ''),
                        'risk_counts': workload.get('RiskCounts', {}),
                        'updated_at': workload.get('UpdatedAt', '').isoformat() if workload.get('UpdatedAt') else ''
                    })
            
            return workloads
            
        except Exception as e:
            st.warning(f"Could not list Well-Architected workloads: {e}")
            return []
    
    def get_workload_details(self, workload_id: str) -> Dict:
        """Get detailed workload information"""
        if not self.session_manager.master_session:
            return {}
        
        try:
            wa = self.session_manager.master_session.client('wellarchitected', config=BOTO_CONFIG)
            
            workload = wa.get_workload(WorkloadId=workload_id)['Workload']
            
            # Get lens reviews
            lens_reviews = wa.list_lens_reviews(WorkloadId=workload_id)['LensReviewSummaries']
            
            return {
                'workload': workload,
                'lens_reviews': lens_reviews
            }
            
        except Exception as e:
            return {"error": str(e)}


# ============================================================================
# MAIN CONNECTOR CLASS
# ============================================================================

class AWSOrganizationConnector:
    """Main connector class that orchestrates all AWS integrations"""
    
    def __init__(self):
        self.session_manager = AWSSessionManager()
        self.org_discovery = None
        self.resource_collector = None
        self.cost_aggregator = None
        self.security_aggregator = None
        self.config_checker = None
        self.wa_integration = None
        self.organization = None
    
    def connect(self, **kwargs) -> bool:
        """
        Connect to AWS using provided credentials
        
        Accepts:
        - access_key, secret_key, session_token (explicit credentials)
        - profile_name (AWS profile)
        - (nothing) for environment/instance credentials
        """
        success = False
        
        if 'access_key' in kwargs and 'secret_key' in kwargs:
            success = self.session_manager.initialize_from_credentials(
                kwargs['access_key'],
                kwargs['secret_key'],
                kwargs.get('session_token'),
                kwargs.get('region', 'us-east-1')
            )
        elif 'profile_name' in kwargs:
            success = self.session_manager.initialize_from_profile(
                kwargs['profile_name'],
                kwargs.get('region', 'us-east-1')
            )
        else:
            success = self.session_manager.initialize_from_environment(
                kwargs.get('region', 'us-east-1')
            )
        
        if success:
            self._initialize_components()
        
        return success
    
    def _initialize_components(self):
        """Initialize all component collectors"""
        self.org_discovery = OrganizationDiscovery(self.session_manager)
        self.resource_collector = ResourceInventoryCollector(self.session_manager)
        self.cost_aggregator = CostExplorerAggregator(self.session_manager)
        self.security_aggregator = SecurityHubAggregator(self.session_manager)
        self.config_checker = ConfigComplianceChecker(self.session_manager)
        self.wa_integration = WellArchitectedToolIntegration(self.session_manager)
    
    def discover_organization(self) -> Optional[OrganizationInfo]:
        """Discover the AWS Organization structure"""
        if self.org_discovery:
            self.organization = self.org_discovery.discover_organization()
        return self.organization
    
    def get_full_landscape_assessment(self, regions: List[str] = None) -> Dict:
        """Get a comprehensive assessment of the entire AWS landscape"""
        if not self.organization:
            self.discover_organization()
        
        assessment = {
            'timestamp': datetime.now().isoformat(),
            'organization': None,
            'accounts': [],
            'costs': None,
            'security': None,
            'compliance': None,
            'well_architected': None
        }
        
        # Organization info
        if self.organization:
            assessment['organization'] = {
                'id': self.organization.id,
                'master_account': self.organization.master_account_id,
                'total_accounts': len(self.organization.accounts),
                'accessible_accounts': len([a for a in self.organization.accounts if a.accessible]),
                'feature_set': self.organization.feature_set
            }
            
            # Account summaries
            for account in self.organization.accounts:
                account_info = {
                    'id': account.id,
                    'name': account.name,
                    'status': account.status,
                    'accessible': account.accessible,
                    'ou_path': account.ou_path,
                    'tags': account.tags
                }
                
                if account.accessible and regions:
                    account_info['inventory'] = self.resource_collector.collect_account_inventory(
                        account.id, regions[:3]  # Limit regions for speed
                    )
                
                assessment['accounts'].append(account_info)
        
        # Costs
        if self.cost_aggregator:
            assessment['costs'] = self.cost_aggregator.get_organization_costs()
        
        # Security
        if self.security_aggregator:
            assessment['security'] = self.security_aggregator.get_organization_findings()
        
        # Compliance
        if self.config_checker:
            assessment['compliance'] = self.config_checker.get_compliance_summary()
        
        # Well-Architected
        if self.wa_integration:
            assessment['well_architected'] = {
                'workloads': self.wa_integration.list_workloads()
            }
        
        return assessment


# ============================================================================
# STREAMLIT UI FUNCTIONS
# ============================================================================

def render_aws_connection_ui():
    """Render AWS connection interface"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #FF9900; margin: 0;">🔌 AWS Organization Connector</h2>
        <p style="color: #AAB7B8; margin: 0.5rem 0 0 0;">Connect to your AWS Organization for comprehensive landscape analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize connector in session state
    if 'aws_connector' not in st.session_state:
        st.session_state.aws_connector = AWSOrganizationConnector()
    
    if 'aws_connected' not in st.session_state:
        st.session_state.aws_connected = False
    
    if 'aws_landscape' not in st.session_state:
        st.session_state.aws_landscape = None
    
    # Check for pre-configured secrets
    preconfigured_creds = None
    if SECRETS_HELPER_AVAILABLE:
        preconfigured_creds = get_aws_credentials()
        
        # Show secrets status
        st.markdown("### 🔐 Credentials Status")
        render_secrets_status()
        st.markdown("---")
    
    # Connection Status
    if st.session_state.aws_connected:
        identity = st.session_state.get('aws_identity', {})
        st.success(f"✅ Connected as: {identity.get('Arn', 'Unknown')}")
        st.markdown(f"**Account:** {identity.get('Account', 'N/A')} | **User ID:** {identity.get('UserId', 'N/A')}")
        
        if st.button("🔌 Disconnect"):
            st.session_state.aws_connected = False
            st.session_state.aws_connector = AWSOrganizationConnector()
            st.session_state.aws_landscape = None
            st.rerun()
        
        return True
    
    # Auto-connect option if secrets are pre-configured
    if preconfigured_creds:
        st.markdown("### ⚡ Quick Connect")
        st.info(f"AWS credentials found in secrets ({preconfigured_creds.source})")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🚀 Connect with Configured Credentials", type="primary", use_container_width=True):
                with st.spinner("Connecting to AWS..."):
                    connector = st.session_state.aws_connector
                    
                    connect_kwargs = {
                        'access_key': preconfigured_creds.access_key_id,
                        'secret_key': preconfigured_creds.secret_access_key,
                        'region': preconfigured_creds.region
                    }
                    
                    if preconfigured_creds.session_token:
                        connect_kwargs['session_token'] = preconfigured_creds.session_token
                    
                    if connector.connect(**connect_kwargs):
                        st.session_state.aws_connected = True
                        st.success("✅ Connected successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to connect. Check your credentials.")
        
        st.markdown("---")
        st.markdown("### 🔧 Or Connect Manually")
    
    # Connection Methods
    st.markdown("### 🔐 Authentication Method")
    
    auth_method = st.radio(
        "Choose authentication method",
        ["IAM Access Keys", "AWS Profile", "Environment/Instance Role"],
        horizontal=True,
        help="Select how to authenticate with AWS"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        if auth_method == "IAM Access Keys":
            st.markdown("#### Enter AWS Credentials")
            access_key = st.text_input("Access Key ID", type="password", 
                                       help="AWS Access Key ID (starts with AKIA...)")
            secret_key = st.text_input("Secret Access Key", type="password")
            session_token = st.text_input("Session Token (Optional)", type="password",
                                         help="Required for temporary credentials")
            region = st.selectbox("Default Region", AWS_REGIONS, index=0)
            
            if st.button("🔗 Connect", type="primary", disabled=not (access_key and secret_key)):
                with st.spinner("Connecting to AWS..."):
                    connector = st.session_state.aws_connector
                    if connector.connect(
                        access_key=access_key,
                        secret_key=secret_key,
                        session_token=session_token if session_token else None,
                        region=region
                    ):
                        st.session_state.aws_connected = True
                        st.success("✅ Connected successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to connect. Check your credentials.")
        
        elif auth_method == "AWS Profile":
            st.markdown("#### Select AWS Profile")
            
            # Try to list available profiles
            import os
            profiles = ['default']
            try:
                import configparser
                config = configparser.ConfigParser()
                creds_path = os.path.expanduser('~/.aws/credentials')
                if os.path.exists(creds_path):
                    config.read(creds_path)
                    profiles = list(config.sections()) or ['default']
            except Exception:
                pass
            
            profile = st.selectbox("AWS Profile", profiles)
            region = st.selectbox("Default Region", AWS_REGIONS, index=0, key="profile_region")
            
            if st.button("🔗 Connect with Profile", type="primary"):
                with st.spinner("Connecting to AWS..."):
                    connector = st.session_state.aws_connector
                    if connector.connect(profile_name=profile, region=region):
                        st.session_state.aws_connected = True
                        st.success("✅ Connected successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to connect with profile.")
        
        else:  # Environment/Instance Role
            st.markdown("#### Environment/Instance Credentials")
            st.info("Will use credentials from environment variables or EC2 instance role")
            region = st.selectbox("Default Region", AWS_REGIONS, index=0, key="env_region")
            
            if st.button("🔗 Connect from Environment", type="primary"):
                with st.spinner("Connecting to AWS..."):
                    connector = st.session_state.aws_connector
                    if connector.connect(region=region):
                        st.session_state.aws_connected = True
                        st.success("✅ Connected successfully!")
                        st.rerun()
                    else:
                        st.error("❌ No valid credentials found in environment.")
    
    with col2:
        st.markdown("#### Required Permissions")
        st.markdown("""
        The connected IAM principal needs these permissions:
        
        **Organization Access:**
        - `organizations:DescribeOrganization`
        - `organizations:ListAccounts`
        - `organizations:ListOrganizationalUnitsForParent`
        - `sts:AssumeRole` (for cross-account access)
        
        **Resource Discovery:**
        - `ec2:Describe*`
        - `rds:Describe*`
        - `eks:List*`, `eks:Describe*`
        - `s3:ListBuckets`
        - `lambda:ListFunctions`
        - `iam:List*`
        
        **Cost & Security:**
        - `ce:GetCostAndUsage`
        - `securityhub:GetFindings`
        - `config:Describe*`
        - `wellarchitected:List*`
        """)
        
        st.markdown("---")
        
        st.markdown("#### Cross-Account Role")
        st.info(f"""
        For multi-account access, ensure each member account has one of these roles:
        - `{CROSS_ACCOUNT_ROLE}` (default)
        - `AWSControlTowerExecution`
        - `WAFAdvisorCrossAccountRole`
        
        The role must trust the management account.
        """)
    
    return False


def render_organization_overview():
    """Render organization overview"""
    
    connector = st.session_state.aws_connector
    
    st.markdown("### 🏢 Organization Discovery")
    
    if st.button("🔍 Discover Organization", type="primary"):
        with st.spinner("Discovering AWS Organization structure..."):
            org = connector.discover_organization()
            
            if org:
                st.session_state.aws_organization = org
                st.success(f"✅ Discovered organization with {len(org.accounts)} accounts")
            else:
                st.warning("Could not discover organization. You may be in a standalone account.")
    
    # Show organization details if available
    if hasattr(st.session_state, 'aws_organization') and st.session_state.aws_organization:
        org = st.session_state.aws_organization
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Accounts", len(org.accounts))
        with col2:
            accessible = len([a for a in org.accounts if a.accessible])
            st.metric("Accessible Accounts", accessible)
        with col3:
            active = len([a for a in org.accounts if a.status == "ACTIVE"])
            st.metric("Active Accounts", active)
        with col4:
            st.metric("Organization Units", len(org.organizational_units))
        
        st.markdown("---")
        
        # Account list
        st.markdown("### 📋 Account Inventory")
        
        accounts_data = []
        for account in org.accounts:
            accounts_data.append({
                'Account ID': account.id,
                'Name': account.name,
                'Status': account.status,
                'OU Path': account.ou_path or 'Root',
                'Accessible': '✅' if account.accessible else '❌',
                'Role': account.role_used or 'N/A'
            })
        
        import pandas as pd
        df = pd.DataFrame(accounts_data)
        st.dataframe(df, use_container_width=True, hide_index=True)


def render_landscape_assessment():
    """Render full landscape assessment"""
    
    connector = st.session_state.aws_connector
    
    st.markdown("### 🌍 AWS Landscape Assessment")
    
    # Region selection
    selected_regions = st.multiselect(
        "Select regions to scan",
        AWS_REGIONS,
        default=["us-east-1", "us-west-2"],
        help="Limit regions for faster scanning"
    )
    
    if st.button("🔍 Run Full Assessment", type="primary"):
        with st.spinner("Running comprehensive landscape assessment... This may take several minutes."):
            assessment = connector.get_full_landscape_assessment(regions=selected_regions)
            st.session_state.aws_landscape = assessment
            st.success("✅ Assessment complete!")
    
    # Show assessment results
    if st.session_state.aws_landscape:
        assessment = st.session_state.aws_landscape
        
        # Cost Summary
        if assessment.get('costs') and 'error' not in assessment['costs']:
            costs = assessment['costs']
            st.markdown("### 💰 Cost Summary")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Cost (30 days)", f"${costs.get('total_cost', 0):,.2f}")
            with col2:
                st.metric("Accounts with Spend", costs.get('account_count', 0))
            with col3:
                top_service = list(costs.get('by_service', {}).keys())[0] if costs.get('by_service') else 'N/A'
                st.metric("Top Service", top_service)
        
        # Security Summary
        if assessment.get('security') and 'error' not in assessment['security']:
            security = assessment['security']
            st.markdown("### 🔒 Security Summary")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Findings", security.get('by_severity', {}).get('CRITICAL', 0))
            with col2:
                st.metric("High Findings", security.get('by_severity', {}).get('HIGH', 0))
            with col3:
                st.metric("Total Findings", security.get('total_findings', 0))
            with col4:
                st.metric("Affected Accounts", len(security.get('by_account', {})))
        
        # Compliance Summary
        if assessment.get('compliance') and 'error' not in assessment['compliance']:
            compliance = assessment['compliance']
            st.markdown("### ✅ Compliance Summary")
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Compliance Score", f"{compliance.get('compliance_percentage', 0)}%")
            with col2:
                st.metric("Non-Compliant Rules", compliance.get('non_compliant_rules', 0))


def render_aws_connector_module():
    """Main renderer for AWS Connector module"""
    
    tabs = st.tabs([
        "🔌 Connection",
        "🏢 Organization",
        "🌍 Landscape",
        "📊 For WAR Analysis"
    ])
    
    with tabs[0]:
        connected = render_aws_connection_ui()
    
    with tabs[1]:
        if st.session_state.get('aws_connected'):
            render_organization_overview()
        else:
            st.info("👆 Connect to AWS first")
    
    with tabs[2]:
        if st.session_state.get('aws_connected'):
            render_landscape_assessment()
        else:
            st.info("👆 Connect to AWS first")
    
    with tabs[3]:
        if st.session_state.get('aws_landscape'):
            st.markdown("### 📊 Export for WAR Analysis")
            st.markdown("Use this data for Well-Architected Review analysis")
            
            # Export button
            landscape_json = json.dumps(st.session_state.aws_landscape, indent=2, default=str)
            st.download_button(
                "📥 Download Landscape Data (JSON)",
                landscape_json,
                file_name=f"aws_landscape_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
            
            st.markdown("---")
            st.markdown("### 🔄 Use in WAR Analysis")
            
            if st.button("📤 Send to Architecture Review", type="primary"):
                st.session_state.war_input_data = st.session_state.aws_landscape
                st.success("✅ Data ready for WAR analysis! Go to Architecture Review tab.")
        else:
            st.info("👆 Run a landscape assessment first")


# Export
__all__ = [
    'AWSOrganizationConnector',
    'AWSSessionManager',
    'OrganizationDiscovery',
    'ResourceInventoryCollector',
    'CostExplorerAggregator',
    'SecurityHubAggregator',
    'ConfigComplianceChecker',
    'WellArchitectedToolIntegration',
    'render_aws_connector_module',
    'AWS_REGIONS'
]
