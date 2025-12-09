"""
AWS Well-Architected Framework Advisor - Single File Version
Optimized for Streamlit Cloud Deployment

This is a consolidated single-file version that works reliably on Streamlit Cloud
without module import issues.
"""

import streamlit as st
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import os

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="AWS Well-Architected Advisor",
    page_icon="🏗️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# OPTIONAL IMPORTS (with graceful fallback)
# ============================================================================

# Anthropic client
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# AWS SDK
try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
    BOTO_CONFIG = Config(
        retries={'max_attempts': 3, 'mode': 'adaptive'},
        connect_timeout=10,
        read_timeout=30
    )
except ImportError:
    BOTO3_AVAILABLE = False

# PDF Generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, ListFlowable, ListItem
    )
    from io import BytesIO
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ============================================================================
# CUSTOM STYLES
# ============================================================================

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #232F3E 0%, #37475A 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .main-header h1 {
        color: #FF9900;
        margin: 0;
        font-size: 2.2rem;
    }
    .main-header p {
        color: #FF9900;
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
    }
    .pillar-card {
        background: white;
        border-radius: 10px;
        padding: 1.2rem;
        margin: 0.5rem 0;
        border-left: 4px solid;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .risk-badge {
        padding: 0.4rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
    }
    .risk-critical { background: #FFEBEE; color: #C62828; }
    .risk-high { background: #FFF3E0; color: #E65100; }
    .risk-medium { background: #FFFDE7; color: #F9A825; }
    .risk-low { background: #E8F5E9; color: #2E7D32; }
    .finding-card {
        background: #FAFAFA;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 3px solid #1976D2;
    }
    .metric-card {
        background: white;
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: #232F3E;
    }
    .metric-label {
        color: #666;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# WAF PILLARS DEFINITION
# ============================================================================

WAF_PILLARS = {
    "operational_excellence": {
        "name": "Operational Excellence",
        "icon": "⚙️",
        "color": "#FF9900",
        "description": "Run and monitor systems to deliver business value",
        "focus_areas": ["Organization", "Prepare", "Operate", "Evolve"]
    },
    "security": {
        "name": "Security",
        "icon": "🔒",
        "color": "#D32F2F",
        "description": "Protect information, systems, and assets",
        "focus_areas": ["Identity & Access", "Detection", "Infrastructure Protection", "Data Protection", "Incident Response"]
    },
    "reliability": {
        "name": "Reliability",
        "icon": "🛡️",
        "color": "#1976D2",
        "description": "Recover from failures and meet demand",
        "focus_areas": ["Foundations", "Workload Architecture", "Change Management", "Failure Management"]
    },
    "performance": {
        "name": "Performance Efficiency",
        "icon": "⚡",
        "color": "#7B1FA2",
        "description": "Use computing resources efficiently",
        "focus_areas": ["Selection", "Review", "Monitoring", "Tradeoffs"]
    },
    "cost": {
        "name": "Cost Optimization",
        "icon": "💰",
        "color": "#388E3C",
        "description": "Avoid unnecessary costs",
        "focus_areas": ["Practice Cloud Financial Management", "Expenditure Awareness", "Cost-Effective Resources", "Manage Demand & Supply", "Optimize Over Time"]
    },
    "sustainability": {
        "name": "Sustainability",
        "icon": "🌱",
        "color": "#00897B",
        "description": "Minimize environmental impact",
        "focus_areas": ["Region Selection", "User Behavior Patterns", "Software & Architecture", "Data Patterns", "Hardware Patterns", "Development & Deployment"]
    }
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AWSCredentials:
    """AWS Credentials container"""
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    source: str = "manual"

@dataclass
class Finding:
    """Represents a WAF-related finding"""
    id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    pillar: str
    source_service: str
    affected_resources: List[str] = field(default_factory=list)
    recommendation: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    account_id: str = ""
    region: str = ""
    estimated_savings: float = 0.0
    effort: str = "Medium"

@dataclass
class ResourceInventory:
    """AWS Resource inventory summary"""
    ec2_instances: int = 0
    ec2_running: int = 0
    rds_instances: int = 0
    rds_multi_az: int = 0
    s3_buckets: int = 0
    s3_public: int = 0
    lambda_functions: int = 0
    eks_clusters: int = 0
    vpcs: int = 0
    load_balancers: int = 0
    ebs_volumes: int = 0
    ebs_unattached: int = 0
    iam_users: int = 0
    iam_users_no_mfa: int = 0
    iam_roles: int = 0

@dataclass
class LandscapeAssessment:
    """Complete AWS Landscape Assessment"""
    assessment_id: str
    timestamp: datetime
    accounts_scanned: List[str] = field(default_factory=list)
    regions_scanned: List[str] = field(default_factory=list)
    overall_score: int = 0
    overall_risk: str = "Unknown"
    inventory: ResourceInventory = field(default_factory=ResourceInventory)
    monthly_cost: float = 0.0
    savings_opportunities: float = 0.0
    pillar_scores: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    services_scanned: Dict[str, bool] = field(default_factory=dict)
    scan_errors: Dict[str, str] = field(default_factory=dict)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_api_key() -> Optional[str]:
    """Get Anthropic API key from various sources"""
    # Check session state first
    if st.session_state.get('anthropic_api_key'):
        return st.session_state.anthropic_api_key
    
    # Check Streamlit secrets
    try:
        if hasattr(st, 'secrets'):
            # Flat format
            if 'ANTHROPIC_API_KEY' in st.secrets:
                return st.secrets['ANTHROPIC_API_KEY']
            # Nested format
            if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                return st.secrets['anthropic']['api_key']
    except Exception:
        pass
    
    # Check environment
    env_key = os.environ.get('ANTHROPIC_API_KEY')
    if env_key:
        return env_key
    
    return None

def get_aws_credentials() -> Tuple[Optional[AWSCredentials], Optional[str]]:
    """
    Get AWS credentials from various sources.
    Returns tuple of (credentials, debug_info)
    """
    debug_info = []
    
    # Check session state first (manual input takes priority)
    if st.session_state.get('aws_credentials'):
        return st.session_state.aws_credentials, "Found in session state"
    
    # Check Streamlit secrets - try multiple formats
    try:
        if hasattr(st, 'secrets'):
            debug_info.append(f"Secrets keys: {list(st.secrets.keys())}")
            
            # FORMAT 1: [aws] section with various key names
            if 'aws' in st.secrets:
                aws_secrets = dict(st.secrets['aws'])
                debug_info.append(f"[aws] section keys: {list(aws_secrets.keys())}")
                
                # Try different key name variations
                access_key = (
                    aws_secrets.get('access_key_id') or 
                    aws_secrets.get('ACCESS_KEY_ID') or
                    aws_secrets.get('aws_access_key_id') or
                    aws_secrets.get('AWS_ACCESS_KEY_ID')
                )
                secret_key = (
                    aws_secrets.get('secret_access_key') or 
                    aws_secrets.get('SECRET_ACCESS_KEY') or
                    aws_secrets.get('aws_secret_access_key') or
                    aws_secrets.get('AWS_SECRET_ACCESS_KEY')
                )
                region = (
                    aws_secrets.get('default_region') or 
                    aws_secrets.get('region') or 
                    aws_secrets.get('AWS_REGION') or
                    aws_secrets.get('aws_region') or
                    'us-east-1'
                )
                session_token = (
                    aws_secrets.get('session_token') or
                    aws_secrets.get('SESSION_TOKEN') or
                    aws_secrets.get('aws_session_token') or
                    aws_secrets.get('AWS_SESSION_TOKEN')
                )
                
                if access_key and secret_key:
                    debug_info.append("SUCCESS: Found credentials in [aws] section")
                    return AWSCredentials(
                        access_key_id=access_key,
                        secret_access_key=secret_key,
                        session_token=session_token,
                        region=region,
                        source="secrets"
                    ), "\n".join(debug_info)
                else:
                    debug_info.append(f"[aws] section missing keys. Has access_key: {access_key is not None}, Has secret_key: {secret_key is not None}")
            
            # FORMAT 2: Flat AWS_ prefixed keys (uppercase)
            access_key = st.secrets.get('AWS_ACCESS_KEY_ID')
            secret_key = st.secrets.get('AWS_SECRET_ACCESS_KEY')
            if access_key and secret_key:
                debug_info.append("SUCCESS: Found flat AWS_ keys")
                return AWSCredentials(
                    access_key_id=access_key,
                    secret_access_key=secret_key,
                    session_token=st.secrets.get('AWS_SESSION_TOKEN'),
                    region=st.secrets.get('AWS_REGION', 'us-east-1'),
                    source="secrets"
                ), "\n".join(debug_info)
            
            # FORMAT 3: Flat aws_ prefixed keys (lowercase)
            access_key = st.secrets.get('aws_access_key_id')
            secret_key = st.secrets.get('aws_secret_access_key')
            if access_key and secret_key:
                debug_info.append("SUCCESS: Found flat aws_ keys")
                return AWSCredentials(
                    access_key_id=access_key,
                    secret_access_key=secret_key,
                    session_token=st.secrets.get('aws_session_token'),
                    region=st.secrets.get('aws_region', 'us-east-1'),
                    source="secrets"
                ), "\n".join(debug_info)
            
            debug_info.append("No valid AWS credentials found in any format")
            
    except Exception as e:
        debug_info.append(f"Error reading secrets: {type(e).__name__}: {str(e)}")
    
    return None, "\n".join(debug_info) if debug_info else "No secrets available"

def init_session_state():
    """Initialize session state variables"""
    # Get credentials from secrets on first load
    api_key = get_api_key()
    aws_creds, aws_debug = get_aws_credentials()
    
    defaults = {
        'anthropic_api_key': api_key,
        'aws_credentials': aws_creds,
        'aws_connected': aws_creds is not None,
        'aws_session': None,
        'analysis_results': None,
        'organization_context': '',
        'landscape_assessment': None,
        'app_mode': 'demo',  # 'demo' or 'live'
        'aws_debug_info': aws_debug  # Store debug info
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    
    # Auto-create AWS session if credentials available
    if st.session_state.aws_credentials and not st.session_state.aws_session and BOTO3_AVAILABLE:
        session = create_aws_session(st.session_state.aws_credentials)
        if session:
            success, _ = test_aws_connection(session)
            if success:
                st.session_state.aws_session = session
                st.session_state.aws_connected = True

def get_anthropic_client():
    """Get Anthropic client"""
    if not ANTHROPIC_AVAILABLE:
        return None
    
    api_key = get_api_key()
    if not api_key:
        return None
    
    return anthropic.Anthropic(api_key=api_key)

# ============================================================================
# AWS CONNECTOR
# ============================================================================

def create_aws_session(credentials: AWSCredentials):
    """Create boto3 session from credentials"""
    if not BOTO3_AVAILABLE:
        return None
    
    try:
        session = boto3.Session(
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            region_name=credentials.region
        )
        return session
    except Exception as e:
        st.error(f"Failed to create AWS session: {e}")
        return None

def test_aws_connection(session) -> Tuple[bool, str]:
    """Test AWS connection"""
    if not session:
        return False, "No session available"
    
    try:
        sts = session.client('sts', config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        return True, f"Connected as {identity['Arn']}"
    except Exception as e:
        return False, str(e)

# ============================================================================
# AWS LANDSCAPE SCANNER
# ============================================================================

class AWSLandscapeScanner:
    """Scan AWS resources for WAF assessment"""
    
    def __init__(self, session):
        self.session = session
        self.account_id = None
        self.findings: List[Finding] = []
        self.inventory = ResourceInventory()
        self.scan_status = {}
        self.scan_errors = {}
        
        try:
            sts = session.client('sts', config=BOTO_CONFIG)
            self.account_id = sts.get_caller_identity()['Account']
        except Exception:
            pass
    
    def run_scan(self, regions: List[str], progress_callback=None) -> LandscapeAssessment:
        """Run comprehensive scan"""
        assessment = LandscapeAssessment(
            assessment_id=f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now(),
            accounts_scanned=[self.account_id] if self.account_id else [],
            regions_scanned=regions
        )
        
        scan_tasks = [
            ("IAM Analysis", self._scan_iam),
            ("S3 Buckets", self._scan_s3),
            ("EC2 Instances", lambda: self._scan_ec2(regions[0])),
            ("RDS Databases", lambda: self._scan_rds(regions[0])),
            ("VPC Configuration", lambda: self._scan_vpc(regions[0])),
            ("CloudTrail", lambda: self._scan_cloudtrail(regions[0])),
        ]
        
        if BOTO3_AVAILABLE:
            for idx, (name, scan_func) in enumerate(scan_tasks):
                if progress_callback:
                    progress_callback(idx / len(scan_tasks), f"Scanning {name}...")
                
                try:
                    scan_func()
                    self.scan_status[name] = True
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    self.scan_errors[name] = f"Access denied" if 'Access' in error_code else str(e)
                    self.scan_status[name] = False
                except Exception as e:
                    self.scan_errors[name] = str(e)
                    self.scan_status[name] = False
        
        if progress_callback:
            progress_callback(1.0, "Calculating scores...")
        
        assessment.findings = self.findings
        assessment.inventory = self.inventory
        assessment.services_scanned = self.scan_status
        assessment.scan_errors = self.scan_errors
        assessment.pillar_scores = self._calculate_pillar_scores()
        assessment.overall_score = self._calculate_overall_score(assessment.pillar_scores)
        assessment.overall_risk = self._determine_risk_level(assessment.overall_score)
        
        return assessment
    
    def _scan_iam(self):
        """Scan IAM for security issues"""
        iam = self.session.client('iam', config=BOTO_CONFIG)
        
        # Count users and roles
        users = iam.list_users()['Users']
        self.inventory.iam_users = len(users)
        
        roles = iam.list_roles()['Roles']
        self.inventory.iam_roles = len(roles)
        
        # Check for users without MFA
        for user in users[:20]:  # Limit to avoid timeout
            try:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if not mfa_devices:
                    self.inventory.iam_users_no_mfa += 1
                    self.findings.append(Finding(
                        id=f"iam-nomfa-{user['UserName']}",
                        title=f"IAM User Without MFA: {user['UserName']}",
                        description=f"User {user['UserName']} does not have MFA enabled",
                        severity='HIGH',
                        pillar='Security',
                        source_service="IAM",
                        affected_resources=[user['UserName']],
                        recommendation="Enable MFA for this user",
                        effort="Low"
                    ))
            except Exception:
                pass
        
        # Check password policy
        try:
            iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntityException:
            self.findings.append(Finding(
                id="iam-no-password-policy",
                title="No IAM Password Policy",
                description="Account does not have a custom password policy",
                severity='MEDIUM',
                pillar='Security',
                source_service="IAM",
                recommendation="Configure a strong password policy",
                effort="Low"
            ))
    
    def _scan_s3(self):
        """Scan S3 buckets"""
        s3 = self.session.client('s3', config=BOTO_CONFIG)
        
        buckets = s3.list_buckets()['Buckets']
        self.inventory.s3_buckets = len(buckets)
        
        for bucket in buckets[:10]:  # Limit to avoid timeout
            try:
                # Check for public access
                acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    if 'AllUsers' in grantee.get('URI', '') or 'AuthenticatedUsers' in grantee.get('URI', ''):
                        self.inventory.s3_public += 1
                        self.findings.append(Finding(
                            id=f"s3-public-{bucket['Name']}",
                            title=f"Public S3 Bucket: {bucket['Name']}",
                            description=f"Bucket {bucket['Name']} has public access",
                            severity='HIGH',
                            pillar='Security',
                            source_service="S3",
                            affected_resources=[bucket['Name']],
                            recommendation="Remove public access unless required",
                            effort="Low"
                        ))
                        break
            except Exception:
                pass
    
    def _scan_ec2(self, region: str):
        """Scan EC2 instances"""
        ec2 = self.session.client('ec2', region_name=region, config=BOTO_CONFIG)
        
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                self.inventory.ec2_instances += 1
                if instance['State']['Name'] == 'running':
                    self.inventory.ec2_running += 1
        
        # Check for unattached EBS volumes
        volumes = ec2.describe_volumes()['Volumes']
        for vol in volumes:
            self.inventory.ebs_volumes += 1
            if vol['State'] == 'available':
                self.inventory.ebs_unattached += 1
                self.findings.append(Finding(
                    id=f"ec2-unattached-{vol['VolumeId']}",
                    title=f"Unattached EBS Volume: {vol['VolumeId']}",
                    description=f"EBS volume is not attached to any instance",
                    severity='LOW',
                    pillar='Cost Optimization',
                    source_service="EC2",
                    affected_resources=[vol['VolumeId']],
                    recommendation="Delete or attach this volume",
                    region=region,
                    effort="Low"
                ))
        
        # Count VPCs
        vpcs = ec2.describe_vpcs()['Vpcs']
        self.inventory.vpcs = len(vpcs)
    
    def _scan_rds(self, region: str):
        """Scan RDS databases"""
        rds = self.session.client('rds', region_name=region, config=BOTO_CONFIG)
        
        dbs = rds.describe_db_instances()['DBInstances']
        for db in dbs:
            self.inventory.rds_instances += 1
            if db.get('MultiAZ', False):
                self.inventory.rds_multi_az += 1
            else:
                self.findings.append(Finding(
                    id=f"rds-no-multiaz-{db['DBInstanceIdentifier']}",
                    title=f"RDS Not Multi-AZ: {db['DBInstanceIdentifier']}",
                    description=f"Database is not configured for Multi-AZ",
                    severity='MEDIUM',
                    pillar='Reliability',
                    source_service="RDS",
                    affected_resources=[db['DBInstanceIdentifier']],
                    recommendation="Enable Multi-AZ for production databases",
                    region=region,
                    effort="Medium"
                ))
            
            # Check encryption
            if not db.get('StorageEncrypted', False):
                self.findings.append(Finding(
                    id=f"rds-no-encryption-{db['DBInstanceIdentifier']}",
                    title=f"RDS Not Encrypted: {db['DBInstanceIdentifier']}",
                    description=f"Database storage is not encrypted",
                    severity='HIGH',
                    pillar='Security',
                    source_service="RDS",
                    affected_resources=[db['DBInstanceIdentifier']],
                    recommendation="Enable encryption at rest",
                    region=region,
                    effort="High"
                ))
    
    def _scan_vpc(self, region: str):
        """Scan VPC configuration"""
        ec2 = self.session.client('ec2', region_name=region, config=BOTO_CONFIG)
        
        # Check for default VPC usage
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            if vpc.get('IsDefault', False):
                self.findings.append(Finding(
                    id=f"vpc-default-{vpc['VpcId']}",
                    title="Default VPC In Use",
                    description="Workloads should use custom VPCs, not the default VPC",
                    severity='MEDIUM',
                    pillar='Security',
                    source_service="VPC",
                    affected_resources=[vpc['VpcId']],
                    recommendation="Migrate resources to a custom VPC",
                    region=region,
                    effort="High"
                ))
        
        # Check for flow logs
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        vpc_ids_with_flow_logs = {fl['ResourceId'] for fl in flow_logs}
        
        for vpc in vpcs:
            if vpc['VpcId'] not in vpc_ids_with_flow_logs:
                self.findings.append(Finding(
                    id=f"vpc-no-flowlogs-{vpc['VpcId']}",
                    title=f"VPC Without Flow Logs: {vpc['VpcId']}",
                    description="VPC does not have flow logs enabled",
                    severity='MEDIUM',
                    pillar='Security',
                    source_service="VPC",
                    affected_resources=[vpc['VpcId']],
                    recommendation="Enable VPC flow logs for traffic analysis",
                    region=region,
                    effort="Low"
                ))
    
    def _scan_cloudtrail(self, region: str):
        """Check CloudTrail configuration"""
        cloudtrail = self.session.client('cloudtrail', region_name=region, config=BOTO_CONFIG)
        
        trails = cloudtrail.describe_trails()['trailList']
        
        if not trails:
            self.findings.append(Finding(
                id="ct-no-trails",
                title="No CloudTrail Configured",
                description="CloudTrail is not configured for audit logging",
                severity='HIGH',
                pillar='Security',
                source_service="CloudTrail",
                recommendation="Enable CloudTrail for all regions",
                effort="Medium"
            ))
        else:
            has_multi_region = any(t.get('IsMultiRegionTrail', False) for t in trails)
            if not has_multi_region:
                self.findings.append(Finding(
                    id="ct-no-multiregion",
                    title="No Multi-Region CloudTrail",
                    description="CloudTrail is not configured for all regions",
                    severity='MEDIUM',
                    pillar='Security',
                    source_service="CloudTrail",
                    recommendation="Enable multi-region CloudTrail",
                    effort="Low"
                ))
    
    def _calculate_pillar_scores(self) -> Dict[str, Dict]:
        """Calculate scores for each WAF pillar"""
        pillar_findings = {}
        for pillar in ['Security', 'Reliability', 'Performance Efficiency', 'Cost Optimization', 'Operational Excellence', 'Sustainability']:
            pillar_findings[pillar] = [f for f in self.findings if f.pillar == pillar]
        
        pillar_scores = {}
        for pillar, findings_list in pillar_findings.items():
            critical = sum(1 for f in findings_list if f.severity == 'CRITICAL')
            high = sum(1 for f in findings_list if f.severity == 'HIGH')
            medium = sum(1 for f in findings_list if f.severity == 'MEDIUM')
            low = sum(1 for f in findings_list if f.severity in ['LOW', 'INFO'])
            
            score = 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1)
            score = max(0, min(100, score))
            
            pillar_scores[pillar] = {
                'score': score,
                'findings_count': len(findings_list),
                'critical_count': critical,
                'high_count': high,
                'medium_count': medium,
                'low_count': low,
                'top_findings': sorted(findings_list, key=lambda f: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(f.severity, 4))[:5]
            }
        
        return pillar_scores
    
    def _calculate_overall_score(self, pillar_scores: Dict) -> int:
        """Calculate overall WAF score"""
        if not pillar_scores:
            return 0
        
        weights = {
            'Security': 1.5,
            'Reliability': 1.2,
            'Performance Efficiency': 1.0,
            'Cost Optimization': 1.0,
            'Operational Excellence': 1.0,
            'Sustainability': 0.8,
        }
        
        total_weight = 0
        weighted_score = 0
        
        for pillar_name, data in pillar_scores.items():
            weight = weights.get(pillar_name, 1.0)
            weighted_score += data['score'] * weight
            total_weight += weight
        
        return int(weighted_score / total_weight) if total_weight > 0 else 0
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine overall risk level"""
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"

# ============================================================================
# DEMO MODE DATA GENERATOR
# ============================================================================

def generate_demo_assessment() -> LandscapeAssessment:
    """Generate realistic demo data for demonstration purposes"""
    
    # Create demo findings
    demo_findings = [
        Finding(
            id="demo-iam-001",
            title="IAM Users Without MFA",
            description="3 IAM users do not have MFA enabled, increasing risk of unauthorized access",
            severity="HIGH",
            pillar="Security",
            source_service="IAM",
            affected_resources=["user-developer1", "user-developer2", "user-admin"],
            recommendation="Enable MFA for all IAM users immediately",
            effort="Low"
        ),
        Finding(
            id="demo-s3-001",
            title="S3 Bucket with Public Access",
            description="Bucket 'company-public-assets' has public read access enabled",
            severity="MEDIUM",
            pillar="Security",
            source_service="S3",
            affected_resources=["company-public-assets"],
            recommendation="Review if public access is required; if not, remove public ACLs",
            effort="Low"
        ),
        Finding(
            id="demo-rds-001",
            title="RDS Instance Not Multi-AZ",
            description="Production database 'prod-db-mysql' is not configured for Multi-AZ deployment",
            severity="HIGH",
            pillar="Reliability",
            source_service="RDS",
            affected_resources=["prod-db-mysql"],
            recommendation="Enable Multi-AZ for production databases to ensure high availability",
            effort="Medium"
        ),
        Finding(
            id="demo-rds-002",
            title="RDS Storage Not Encrypted",
            description="Database 'dev-db-postgres' does not have encryption at rest enabled",
            severity="HIGH",
            pillar="Security",
            source_service="RDS",
            affected_resources=["dev-db-postgres"],
            recommendation="Enable encryption at rest for all databases",
            effort="High"
        ),
        Finding(
            id="demo-ec2-001",
            title="Unattached EBS Volumes",
            description="5 EBS volumes are not attached to any instance, incurring unnecessary costs",
            severity="LOW",
            pillar="Cost Optimization",
            source_service="EC2",
            affected_resources=["vol-0a1b2c3d4e5f", "vol-1a2b3c4d5e6f", "vol-2a3b4c5d6e7f", "vol-3a4b5c6d7e8f", "vol-4a5b6c7d8e9f"],
            recommendation="Delete unattached volumes or attach them to instances",
            estimated_savings=150.0,
            effort="Low"
        ),
        Finding(
            id="demo-vpc-001",
            title="VPC Without Flow Logs",
            description="Main production VPC does not have flow logs enabled",
            severity="MEDIUM",
            pillar="Security",
            source_service="VPC",
            affected_resources=["vpc-main-production"],
            recommendation="Enable VPC flow logs for network traffic analysis and security monitoring",
            effort="Low"
        ),
        Finding(
            id="demo-ct-001",
            title="CloudTrail Not Multi-Region",
            description="CloudTrail is only configured for us-east-1 region",
            severity="MEDIUM",
            pillar="Security",
            source_service="CloudTrail",
            affected_resources=["main-trail"],
            recommendation="Enable multi-region CloudTrail for comprehensive audit logging",
            effort="Low"
        ),
        Finding(
            id="demo-ec2-002",
            title="EC2 Instances Using Previous Generation",
            description="8 EC2 instances are using previous generation instance types (m4, c4)",
            severity="LOW",
            pillar="Performance Efficiency",
            source_service="EC2",
            affected_resources=["i-0a1b2c3d", "i-1a2b3c4d", "i-2a3b4c5d"],
            recommendation="Migrate to current generation instances (m6i, c6i) for better price-performance",
            estimated_savings=320.0,
            effort="Medium"
        ),
        Finding(
            id="demo-backup-001",
            title="No Backup Plan for Critical Resources",
            description="Critical EC2 instances and RDS databases are not covered by AWS Backup plans",
            severity="HIGH",
            pillar="Reliability",
            source_service="AWS Backup",
            affected_resources=["prod-web-server", "prod-db-mysql"],
            recommendation="Create comprehensive backup plans for all critical resources",
            effort="Medium"
        ),
        Finding(
            id="demo-lambda-001",
            title="Lambda Functions with Excessive Permissions",
            description="3 Lambda functions have overly permissive IAM roles with admin access",
            severity="HIGH",
            pillar="Security",
            source_service="Lambda",
            affected_resources=["data-processor", "api-handler", "event-trigger"],
            recommendation="Apply least privilege principle to Lambda execution roles",
            effort="Medium"
        ),
        Finding(
            id="demo-cost-001",
            title="Reserved Instance Opportunity",
            description="On-demand EC2 usage pattern suggests RI purchase could save costs",
            severity="INFO",
            pillar="Cost Optimization",
            source_service="Cost Explorer",
            affected_resources=["ec2-fleet"],
            recommendation="Purchase 1-year Reserved Instances for steady-state workloads",
            estimated_savings=2400.0,
            effort="Low"
        ),
        Finding(
            id="demo-tag-001",
            title="Resources Missing Required Tags",
            description="47 resources are missing required tags (Environment, Owner, CostCenter)",
            severity="MEDIUM",
            pillar="Operational Excellence",
            source_service="Resource Groups",
            affected_resources=["Multiple resources"],
            recommendation="Implement tagging policy and remediate untagged resources",
            effort="Medium"
        ),
    ]
    
    # Create demo inventory
    demo_inventory = ResourceInventory(
        ec2_instances=24,
        ec2_running=18,
        rds_instances=6,
        rds_multi_az=4,
        s3_buckets=15,
        s3_public=1,
        lambda_functions=12,
        eks_clusters=2,
        vpcs=3,
        load_balancers=4,
        ebs_volumes=42,
        ebs_unattached=5,
        iam_users=28,
        iam_users_no_mfa=3,
        iam_roles=45
    )
    
    # Calculate pillar scores
    pillar_findings = {}
    for pillar in ['Security', 'Reliability', 'Performance Efficiency', 'Cost Optimization', 'Operational Excellence', 'Sustainability']:
        pillar_findings[pillar] = [f for f in demo_findings if f.pillar == pillar]
    
    pillar_scores = {}
    for pillar, findings_list in pillar_findings.items():
        critical = sum(1 for f in findings_list if f.severity == 'CRITICAL')
        high = sum(1 for f in findings_list if f.severity == 'HIGH')
        medium = sum(1 for f in findings_list if f.severity == 'MEDIUM')
        low = sum(1 for f in findings_list if f.severity in ['LOW', 'INFO'])
        
        score = 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1)
        score = max(0, min(100, score))
        
        pillar_scores[pillar] = {
            'score': score,
            'findings_count': len(findings_list),
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'top_findings': sorted(findings_list, key=lambda f: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(f.severity, 5))[:5]
        }
    
    # Calculate overall score
    weights = {'Security': 1.5, 'Reliability': 1.2, 'Performance Efficiency': 1.0, 
               'Cost Optimization': 1.0, 'Operational Excellence': 1.0, 'Sustainability': 0.8}
    
    weighted_score = sum(pillar_scores[p]['score'] * weights.get(p, 1.0) for p in pillar_scores)
    total_weight = sum(weights.get(p, 1.0) for p in pillar_scores)
    overall_score = int(weighted_score / total_weight)
    
    # Determine risk level
    if overall_score >= 80:
        risk = "Low"
    elif overall_score >= 60:
        risk = "Medium"
    elif overall_score >= 40:
        risk = "High"
    else:
        risk = "Critical"
    
    # Create assessment
    assessment = LandscapeAssessment(
        assessment_id=f"demo-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        timestamp=datetime.now(),
        accounts_scanned=["123456789012"],
        regions_scanned=["us-east-1", "us-west-2"],
        overall_score=overall_score,
        overall_risk=risk,
        inventory=demo_inventory,
        monthly_cost=12450.00,
        savings_opportunities=2870.0,
        pillar_scores=pillar_scores,
        findings=demo_findings,
        services_scanned={
            "IAM Analysis": True,
            "S3 Buckets": True,
            "EC2 Instances": True,
            "RDS Databases": True,
            "VPC Configuration": True,
            "CloudTrail": True,
            "Lambda Functions": True,
            "Cost Explorer": True
        },
        scan_errors={}
    )
    
    return assessment

# ============================================================================
# PDF REPORT GENERATOR
# ============================================================================

def generate_pdf_report(assessment: LandscapeAssessment) -> bytes:
    """Generate PDF report from assessment"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is not installed")
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.75*inch, leftMargin=0.75*inch, topMargin=1*inch, bottomMargin=0.75*inch)
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Title2', parent=styles['Title'], fontSize=24, textColor=colors.HexColor('#232F3E')))
    styles.add(ParagraphStyle(name='SubTitle', parent=styles['Normal'], fontSize=12, textColor=colors.gray))
    styles.add(ParagraphStyle(name='Section', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#232F3E'), spaceBefore=20, spaceAfter=10))
    styles.add(ParagraphStyle(name='Body', parent=styles['Normal'], fontSize=10, alignment=TA_JUSTIFY))
    
    elements = []
    
    # Cover
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("AWS Well-Architected", styles['Title2']))
    elements.append(Paragraph("Framework Review Report", styles['Title2']))
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph(f"Assessment Date: {assessment.timestamp.strftime('%B %d, %Y')}", styles['SubTitle']))
    elements.append(Paragraph(f"Assessment ID: {assessment.assessment_id}", styles['SubTitle']))
    elements.append(Spacer(1, 1*inch))
    
    score_color = colors.green if assessment.overall_score >= 80 else colors.orange if assessment.overall_score >= 60 else colors.red
    elements.append(Paragraph(f"<font size='48' color='{score_color}'><b>{assessment.overall_score}</b></font>", styles['Title']))
    elements.append(Paragraph("Overall WAF Score", styles['SubTitle']))
    elements.append(Paragraph(f"Risk Level: <b>{assessment.overall_risk}</b>", styles['Body']))
    elements.append(PageBreak())
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", styles['Section']))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#FF9900')))
    elements.append(Spacer(1, 10))
    
    critical_count = sum(1 for f in assessment.findings if f.severity == 'CRITICAL')
    high_count = sum(1 for f in assessment.findings if f.severity == 'HIGH')
    
    summary = f"""This Well-Architected Review assessed your AWS environment. 
    The assessment identified <b>{len(assessment.findings)} findings</b>, including 
    <b>{critical_count} critical</b> and <b>{high_count} high</b> severity issues.
    Your overall WAF score is <b>{assessment.overall_score}/100</b> with a <b>{assessment.overall_risk}</b> risk level."""
    elements.append(Paragraph(summary, styles['Body']))
    elements.append(Spacer(1, 20))
    
    # Metrics table
    metrics_data = [
        ['Metric', 'Value'],
        ['Total Findings', str(len(assessment.findings))],
        ['Critical Issues', str(critical_count)],
        ['High Issues', str(high_count)],
        ['EC2 Instances', str(assessment.inventory.ec2_instances)],
        ['RDS Databases', str(assessment.inventory.rds_instances)],
        ['S3 Buckets', str(assessment.inventory.s3_buckets)],
    ]
    
    table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F5F5F5')),
    ]))
    elements.append(table)
    elements.append(PageBreak())
    
    # Pillar Scores
    elements.append(Paragraph("Pillar Assessment Scores", styles['Section']))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#FF9900')))
    elements.append(Spacer(1, 10))
    
    pillar_data = [['Pillar', 'Score', 'Critical', 'High', 'Medium', 'Status']]
    for pillar_name, data in assessment.pillar_scores.items():
        status = 'Good' if data['score'] >= 80 else 'Needs Work' if data['score'] >= 60 else 'At Risk'
        pillar_data.append([
            pillar_name,
            f"{data['score']}/100",
            str(data['critical_count']),
            str(data['high_count']),
            str(data['medium_count']),
            status
        ])
    
    pillar_table = Table(pillar_data, colWidths=[2*inch, 0.8*inch, 0.7*inch, 0.7*inch, 0.8*inch, 1*inch])
    pillar_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]))
    elements.append(pillar_table)
    elements.append(PageBreak())
    
    # Findings
    elements.append(Paragraph("Key Findings", styles['Section']))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#FF9900')))
    elements.append(Spacer(1, 10))
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
        severity_findings = [f for f in assessment.findings if f.severity == severity]
        if severity_findings:
            color_map = {'CRITICAL': colors.red, 'HIGH': colors.orange, 'MEDIUM': colors.HexColor('#FBC02D')}
            elements.append(Paragraph(f"<font color='{color_map[severity]}'><b>{severity} ({len(severity_findings)})</b></font>", styles['Body']))
            
            for finding in severity_findings[:5]:
                elements.append(Paragraph(f"• <b>{finding.title}</b>: {finding.description[:100]}", styles['Body']))
            
            elements.append(Spacer(1, 10))
    
    # Build PDF
    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes

# ============================================================================
# AI ANALYSIS
# ============================================================================

def analyze_architecture(client, architecture_data: str, pillars: Dict, context: str = "") -> Dict:
    """Analyze architecture using Claude AI"""
    
    pillar_list = ", ".join([p['name'] for k, p in pillars.items()])
    
    prompt = f"""You are an AWS Well-Architected Framework expert. Analyze this architecture and provide a comprehensive assessment.

Architecture Description:
{architecture_data}

{f"Additional Context: {context}" if context else ""}

Analyze against these WAF pillars: {pillar_list}

Provide your response in this exact JSON format:
{{
    "executive_summary": "Brief overall assessment (2-3 sentences)",
    "overall_risk": "Critical|High|Medium|Low",
    "overall_score": 0-100,
    "pillar_assessments": {{
        "pillar_name": {{
            "score": 0-100,
            "risk_level": "Critical|High|Medium|Low",
            "strengths": ["strength1", "strength2"],
            "gaps": ["gap1", "gap2"],
            "recommendations": [
                {{
                    "title": "Recommendation title",
                    "description": "Detailed description",
                    "priority": "Critical|High|Medium|Low",
                    "effort": "Low|Medium|High",
                    "impact": "High|Medium|Low"
                }}
            ]
        }}
    }},
    "immediate_actions": ["action1", "action2", "action3"],
    "long_term_recommendations": ["rec1", "rec2"]
}}

Be specific and actionable in your recommendations. Focus on AWS best practices."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = response.content[0].text
        
        # Extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            return json.loads(json_match.group())
        else:
            return {"error": "Could not parse response", "raw": response_text}
            
    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# SIDEBAR
# ============================================================================

def render_sidebar():
    """Render sidebar with configuration"""
    with st.sidebar:
        st.image("https://a0.awsstatic.com/libra-css/images/logos/aws_smile-header-desktop-en-white_59x35.png", width=80)
        
        # Mode Toggle - PROMINENT
        st.markdown("### 🎮 Mode")
        mode = st.radio(
            "Select Mode",
            ["🎭 Demo", "🔴 Live"],
            index=0 if st.session_state.get('app_mode', 'demo') == 'demo' else 1,
            horizontal=True,
            help="Demo uses sample data; Live connects to real AWS"
        )
        st.session_state.app_mode = 'demo' if '🎭' in mode else 'live'
        
        if st.session_state.app_mode == 'demo':
            st.info("📋 Demo mode uses realistic sample data. No AWS credentials needed.")
        else:
            st.warning("🔴 Live mode connects to your real AWS account.")
        
        st.markdown("---")
        
        # Configuration
        st.markdown("### ⚙️ Configuration")
        
        # API Key
        api_key = get_api_key()
        if api_key:
            st.success("✓ API Key configured")
        else:
            api_key_input = st.text_input(
                "Anthropic API Key",
                type="password",
                placeholder="sk-ant-...",
                help="Required for AI analysis"
            )
            if api_key_input:
                st.session_state.anthropic_api_key = api_key_input
                st.rerun()
        
        st.markdown("---")
        
        # AWS Credentials (only relevant for Live mode)
        st.markdown("### 🔐 AWS Connection")
        
        if st.session_state.app_mode == 'demo':
            st.markdown("_Not required in Demo mode_")
        elif BOTO3_AVAILABLE:
            aws_creds, aws_debug = get_aws_credentials()
            
            if aws_creds and aws_creds.source == "secrets":
                st.success("✓ AWS credentials from secrets")
                # Test connection if not already connected
                if not st.session_state.get('aws_connected'):
                    session = create_aws_session(aws_creds)
                    if session:
                        success, msg = test_aws_connection(session)
                        if success:
                            st.session_state.aws_credentials = aws_creds
                            st.session_state.aws_session = session
                            st.session_state.aws_connected = True
                            st.success(f"✓ Connected")
                        else:
                            st.error(f"Connection failed: {msg}")
                else:
                    st.success("✓ Connected to AWS")
            elif st.session_state.get('aws_connected'):
                st.success("✓ AWS connected (manual)")
            else:
                st.warning("AWS credentials not found in secrets")
                
                # Show debug info to help troubleshoot
                with st.expander("🔍 Debug: What's in your secrets?"):
                    st.code(aws_debug or "No debug info available", language="text")
                    st.markdown("""
                    **Expected format in Streamlit Secrets:**
                    ```toml
                    [aws]
                    access_key_id = "AKIA..."
                    secret_access_key = "your-secret-key"
                    default_region = "us-east-1"
                    ```
                    
                    **Or flat format:**
                    ```toml
                    AWS_ACCESS_KEY_ID = "AKIA..."
                    AWS_SECRET_ACCESS_KEY = "..."
                    AWS_REGION = "us-east-1"
                    ```
                    """)
                
                with st.expander("Enter AWS Credentials Manually"):
                    access_key = st.text_input("Access Key ID", type="password", key="aws_access_key")
                    secret_key = st.text_input("Secret Access Key", type="password", key="aws_secret_key")
                    region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"], key="aws_region")
                    
                    if st.button("Connect to AWS"):
                        if access_key and secret_key:
                            creds = AWSCredentials(
                                access_key_id=access_key,
                                secret_access_key=secret_key,
                                region=region,
                                source="manual"
                            )
                            session = create_aws_session(creds)
                            if session:
                                success, msg = test_aws_connection(session)
                                if success:
                                    st.session_state.aws_credentials = creds
                                    st.session_state.aws_session = session
                                    st.session_state.aws_connected = True
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(f"Connection failed: {msg}")
                        else:
                            st.warning("Please enter both keys")
        else:
            st.warning("boto3 not installed - AWS features disabled")
        
        st.markdown("---")
        
        # Component Status
        st.markdown("### 📦 Components")
        components = {
            "AI Analysis": ANTHROPIC_AVAILABLE,
            "AWS SDK": BOTO3_AVAILABLE,
            "PDF Reports": REPORTLAB_AVAILABLE
        }
        for name, available in components.items():
            st.markdown(f"{'✅' if available else '❌'} {name}")
        
        st.markdown("---")
        
        # Organization Context
        st.markdown("### 🏢 Context")
        org_context = st.text_area(
            "Custom Context",
            value=st.session_state.get("organization_context", ""),
            placeholder="Add organization-specific context...",
            height=80
        )
        st.session_state.organization_context = org_context

# ============================================================================
# MAIN TABS
# ============================================================================

def render_aws_scanner_tab():
    """Render AWS Scanner tab"""
    is_demo = st.session_state.get('app_mode', 'demo') == 'demo'
    
    if is_demo:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #1565C0 0%, #1976D2 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
            <h2 style="color: #FFFFFF; margin: 0;">🎭 Demo Mode - AWS Scanner</h2>
            <p style="color: #BBDEFB; margin: 0.5rem 0 0 0;">Experience the scanner with realistic sample data</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.info("🎭 **Demo Mode**: This uses pre-built sample data to demonstrate the scanner capabilities. Switch to Live mode in the sidebar to connect to your real AWS account.")
    else:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #1a472a 0%, #2d5a3d 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
            <h2 style="color: #98FB98; margin: 0;">🔴 Live Mode - AWS Scanner</h2>
            <p style="color: #90EE90; margin: 0.5rem 0 0 0;">Scanning your real AWS resources</p>
        </div>
        """, unsafe_allow_html=True)
        
        if not BOTO3_AVAILABLE:
            st.error("❌ boto3 not installed. Add `boto3` to requirements.txt")
            return
        
        if not st.session_state.get('aws_connected'):
            st.warning("⚠️ Connect to AWS first using the sidebar, or switch to Demo mode.")
            return
    
    # Region selection (different options for demo vs live)
    col1, col2 = st.columns(2)
    with col1:
        if is_demo:
            selected_regions = st.multiselect(
                "Regions (Demo)",
                ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
                default=["us-east-1", "us-west-2"],
                disabled=True
            )
        else:
            selected_regions = st.multiselect(
                "Regions to Scan",
                ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1", "eu-central-1"],
                default=["us-east-1"]
            )
    with col2:
        generate_pdf = st.checkbox("📄 Generate PDF Report", value=True)
    
    # Scan button
    button_text = "🎭 Run Demo Assessment" if is_demo else "🚀 Run Live Assessment"
    button_type = "secondary" if is_demo else "primary"
    
    if st.button(button_text, type=button_type, use_container_width=True):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        if is_demo:
            # Demo mode - use sample data
            import time
            
            demo_steps = [
                (0.1, "Initializing demo environment..."),
                (0.2, "Loading IAM configuration..."),
                (0.3, "Scanning S3 buckets..."),
                (0.4, "Analyzing EC2 instances..."),
                (0.5, "Checking RDS databases..."),
                (0.6, "Reviewing VPC configuration..."),
                (0.7, "Analyzing CloudTrail..."),
                (0.8, "Checking Lambda functions..."),
                (0.9, "Calculating pillar scores..."),
                (1.0, "Generating assessment report...")
            ]
            
            for progress, message in demo_steps:
                progress_bar.progress(progress)
                status_text.text(message)
                time.sleep(0.3)
            
            assessment = generate_demo_assessment()
            status_text.text("✅ Demo assessment complete!")
        else:
            # Live mode - real AWS scan
            def update_progress(progress, message):
                progress_bar.progress(progress)
                status_text.text(message)
            
            session = st.session_state.aws_session
            if not session:
                creds, _ = get_aws_credentials()
                if creds:
                    session = create_aws_session(creds)
                    st.session_state.aws_session = session
            
            if not session:
                st.error("No AWS session available")
                return
            
            scanner = AWSLandscapeScanner(session)
            
            with st.spinner("Scanning AWS resources..."):
                assessment = scanner.run_scan(selected_regions, update_progress)
            
            status_text.text("✅ Live scan complete!")
        
        st.session_state.landscape_assessment = assessment
        
        # Show results
        mode_indicator = "🎭 Demo" if is_demo else "🔴 Live"
        st.success(f"{mode_indicator} | Found {len(assessment.findings)} findings across {len(assessment.services_scanned)} services")
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        score_color = "#388E3C" if assessment.overall_score >= 80 else "#FBC02D" if assessment.overall_score >= 60 else "#D32F2F"
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color: {score_color};">{assessment.overall_score}</div>
                <div class="metric-label">WAF Score</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            risk_icon = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}.get(assessment.overall_risk, "⚪")
            st.metric("Risk Level", f"{risk_icon} {assessment.overall_risk}")
        with col3:
            st.metric("Total Findings", len(assessment.findings))
        with col4:
            critical = sum(1 for f in assessment.findings if f.severity == 'CRITICAL')
            high = sum(1 for f in assessment.findings if f.severity == 'HIGH')
            st.metric("Critical/High", f"{critical}/{high}")
        
        # Resource Inventory
        st.markdown("### 📦 Resource Inventory")
        inv = assessment.inventory
        
        inv_col1, inv_col2, inv_col3, inv_col4 = st.columns(4)
        with inv_col1:
            st.metric("EC2 Instances", f"{inv.ec2_running}/{inv.ec2_instances} running")
            st.metric("Lambda Functions", inv.lambda_functions)
        with inv_col2:
            st.metric("RDS Databases", f"{inv.rds_multi_az}/{inv.rds_instances} Multi-AZ")
            st.metric("EKS Clusters", inv.eks_clusters)
        with inv_col3:
            st.metric("S3 Buckets", f"{inv.s3_buckets} ({inv.s3_public} public)")
            st.metric("VPCs", inv.vpcs)
        with inv_col4:
            st.metric("IAM Users", f"{inv.iam_users} ({inv.iam_users_no_mfa} no MFA)")
            st.metric("EBS Volumes", f"{inv.ebs_volumes} ({inv.ebs_unattached} unattached)")
        
        # Pillar scores
        st.markdown("### 📊 Pillar Scores")
        cols = st.columns(6)
        icons = {"Security": "🔒", "Reliability": "🛡️", "Performance Efficiency": "⚡", 
                 "Cost Optimization": "💰", "Operational Excellence": "⚙️", "Sustainability": "🌱"}
        
        for idx, (pillar, data) in enumerate(assessment.pillar_scores.items()):
            with cols[idx % 6]:
                color = "#388E3C" if data['score'] >= 80 else "#FBC02D" if data['score'] >= 60 else "#D32F2F"
                st.markdown(f"""
                <div style="text-align: center; padding: 0.5rem; background: white; border-radius: 8px; margin-bottom: 0.5rem;">
                    <div style="font-size: 1.5rem;">{icons.get(pillar, '📊')}</div>
                    <div style="font-size: 1.5rem; font-weight: bold; color: {color};">{data['score']}</div>
                    <div style="font-size: 0.7rem; color: #666;">{pillar.split()[0]}</div>
                </div>
                """, unsafe_allow_html=True)
        
        # Services scanned
        with st.expander("📋 Services Scanned"):
            for service, success in assessment.services_scanned.items():
                if success:
                    st.markdown(f"✅ {service}")
                else:
                    error = assessment.scan_errors.get(service, "Unknown error")
                    st.markdown(f"❌ {service}: {error}")
        
        # Top findings
        st.markdown("### 🚨 Top Findings")
        for finding in assessment.findings[:10]:
            severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(finding.severity, '⚪')
            with st.expander(f"{severity_icon} {finding.title}"):
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.markdown(f"**Pillar:** {finding.pillar}")
                    st.markdown(f"**Service:** {finding.source_service}")
                    st.markdown(f"**Description:** {finding.description}")
                with col2:
                    st.markdown(f"**Severity:** {finding.severity}")
                    st.markdown(f"**Effort:** {finding.effort}")
                    if finding.estimated_savings > 0:
                        st.markdown(f"**Savings:** ${finding.estimated_savings:,.0f}/mo")
                
                if finding.affected_resources:
                    st.markdown(f"**Affected Resources:** {', '.join(finding.affected_resources[:5])}")
                if finding.recommendation:
                    st.success(f"💡 **Recommendation:** {finding.recommendation}")
        
        # Cost savings summary
        total_savings = sum(f.estimated_savings for f in assessment.findings if f.estimated_savings > 0)
        if total_savings > 0:
            st.markdown("### 💰 Cost Optimization Opportunities")
            st.markdown(f"**Total Monthly Savings Potential:** ${total_savings:,.2f}")
            
            savings_findings = [f for f in assessment.findings if f.estimated_savings > 0]
            for f in sorted(savings_findings, key=lambda x: x.estimated_savings, reverse=True)[:5]:
                st.markdown(f"- {f.title}: **${f.estimated_savings:,.0f}/mo**")
        
        # PDF download
        if generate_pdf and REPORTLAB_AVAILABLE:
            st.markdown("---")
            st.markdown("### 📄 Download Report")
            try:
                pdf_bytes = generate_pdf_report(assessment)
                mode_label = "Demo" if is_demo else "Live"
                st.download_button(
                    f"📥 Download PDF Report ({mode_label})",
                    pdf_bytes,
                    file_name=f"AWS_WAF_Report_{mode_label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"Failed to generate PDF: {e}")

def render_upload_tab():
    """Render architecture upload tab"""
    st.markdown("### Upload Your AWS Architecture")
    st.markdown("Provide your architecture for analysis using one of the following methods:")
    
    input_method = st.radio(
        "Input Method",
        ["Architecture Diagram (Image)", "CloudFormation/Terraform (Code)", "Architecture Description (Text)", "AWS Config Export (JSON)"],
        horizontal=True
    )
    
    architecture_data = None
    
    if input_method == "Architecture Diagram (Image)":
        uploaded_file = st.file_uploader("Upload architecture diagram", type=['png', 'jpg', 'jpeg', 'gif', 'webp'])
        if uploaded_file:
            st.image(uploaded_file, caption="Uploaded Architecture", use_container_width=True)
            image_data = base64.b64encode(uploaded_file.read()).decode('utf-8')
            architecture_data = f"[Architecture Diagram - Image uploaded: {uploaded_file.name}]"
            st.session_state['uploaded_image'] = {
                'data': image_data,
                'media_type': uploaded_file.type
            }
    
    elif input_method == "CloudFormation/Terraform (Code)":
        code = st.text_area("Paste your IaC code", height=300, placeholder="Paste CloudFormation YAML/JSON or Terraform code...")
        if code:
            architecture_data = code
    
    elif input_method == "Architecture Description (Text)":
        description = st.text_area("Describe your architecture", height=300, placeholder="Describe your AWS architecture, including services used, data flows, security measures...")
        if description:
            architecture_data = description
    
    else:  # JSON
        uploaded_json = st.file_uploader("Upload AWS Config export", type=['json'])
        if uploaded_json:
            architecture_data = uploaded_json.read().decode('utf-8')
    
    context = st.text_area("Additional Context (Optional)", placeholder="Compliance requirements, expected traffic, specific concerns...", height=100)
    
    if st.button("🔍 Analyze Architecture", type="primary", use_container_width=True):
        if not architecture_data:
            st.warning("Please provide architecture information")
            return
        
        client = get_anthropic_client()
        if not client:
            st.error("Please configure your Anthropic API key in the sidebar")
            return
        
        with st.spinner("Analyzing architecture against WAF pillars..."):
            results = analyze_architecture(client, architecture_data, WAF_PILLARS, context)
        
        if "error" in results:
            st.error(f"Analysis failed: {results['error']}")
        else:
            st.session_state.analysis_results = results
            st.success("✅ Analysis complete! View results in the WAF Results tab.")

def render_results_tab():
    """Render WAF results tab"""
    results = st.session_state.get('analysis_results')
    
    if not results:
        st.info("No analysis results yet. Upload and analyze an architecture first.")
        return
    
    # Executive Summary
    st.markdown("### 📋 Executive Summary")
    st.markdown(results.get('executive_summary', 'No summary available'))
    
    # Overall metrics
    col1, col2, col3 = st.columns(3)
    score = results.get('overall_score', 0)
    risk = results.get('overall_risk', 'Unknown')
    
    with col1:
        color = "#388E3C" if score >= 80 else "#FBC02D" if score >= 60 else "#D32F2F"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {color};">{score}</div>
            <div class="metric-label">Overall Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        risk_class = f"risk-{risk.lower()}"
        st.markdown(f'<span class="risk-badge {risk_class}">{risk} Risk</span>', unsafe_allow_html=True)
    
    with col3:
        pillar_count = len(results.get('pillar_assessments', {}))
        st.metric("Pillars Analyzed", pillar_count)
    
    # Pillar Assessments
    st.markdown("### 📊 Pillar Assessments")
    
    pillar_assessments = results.get('pillar_assessments', {})
    for pillar_name, assessment in pillar_assessments.items():
        pillar_info = next((p for p in WAF_PILLARS.values() if p['name'] == pillar_name), None)
        icon = pillar_info['icon'] if pillar_info else '📋'
        color = pillar_info['color'] if pillar_info else '#666'
        
        with st.expander(f"{icon} {pillar_name} - Score: {assessment.get('score', 'N/A')}/100"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Strengths:**")
                for strength in assessment.get('strengths', []):
                    st.markdown(f"✅ {strength}")
            
            with col2:
                st.markdown("**Gaps:**")
                for gap in assessment.get('gaps', []):
                    st.markdown(f"⚠️ {gap}")
            
            st.markdown("**Recommendations:**")
            for rec in assessment.get('recommendations', []):
                priority = rec.get('priority', 'Medium')
                priority_color = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(priority, '⚪')
                st.markdown(f"{priority_color} **{rec.get('title', 'Recommendation')}** ({priority})")
                st.markdown(f"   {rec.get('description', '')}")
    
    # Immediate Actions
    st.markdown("### 🚨 Immediate Actions")
    for action in results.get('immediate_actions', []):
        st.markdown(f"- {action}")
    
    # Export
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Export as JSON",
            json.dumps(results, indent=2),
            file_name=f"waf_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

def render_knowledge_base_tab():
    """Render knowledge base tab"""
    st.markdown("### 📚 AWS Well-Architected Framework Knowledge Base")
    
    for key, pillar in WAF_PILLARS.items():
        with st.expander(f"{pillar['icon']} {pillar['name']}", expanded=False):
            st.markdown(f"**Description:** {pillar['description']}")
            st.markdown("**Focus Areas:**")
            for area in pillar['focus_areas']:
                st.markdown(f"- {area}")
            st.markdown(f"[📖 AWS Documentation](https://docs.aws.amazon.com/wellarchitected/latest/framework/{key.replace('_', '-')}.html)")

# ============================================================================
# EKS & MODERNIZATION TAB
# ============================================================================

EKS_TOOLS_CATALOG = {
    "container_runtime": {
        "name": "Container Runtime",
        "icon": "🐳",
        "tools": [
            {"name": "containerd", "description": "Industry-standard container runtime", "recommendation": "Default for EKS 1.24+"},
            {"name": "Docker", "description": "Legacy runtime (deprecated)", "recommendation": "Migrate to containerd"},
            {"name": "CRI-O", "description": "Lightweight OCI runtime", "recommendation": "Alternative option"}
        ]
    },
    "service_mesh": {
        "name": "Service Mesh",
        "icon": "🕸️",
        "tools": [
            {"name": "AWS App Mesh", "description": "AWS-native service mesh", "recommendation": "Best for AWS integration"},
            {"name": "Istio", "description": "Feature-rich open source mesh", "recommendation": "Complex workloads"},
            {"name": "Linkerd", "description": "Lightweight service mesh", "recommendation": "Simpler deployments"}
        ]
    },
    "observability": {
        "name": "Observability",
        "icon": "📊",
        "tools": [
            {"name": "Amazon CloudWatch Container Insights", "description": "Native AWS monitoring", "recommendation": "Default choice"},
            {"name": "Prometheus + Grafana", "description": "Open source monitoring stack", "recommendation": "Custom dashboards"},
            {"name": "Datadog", "description": "Commercial APM solution", "recommendation": "Enterprise features"},
            {"name": "AWS X-Ray", "description": "Distributed tracing", "recommendation": "Trace analysis"}
        ]
    },
    "security": {
        "name": "Security",
        "icon": "🔒",
        "tools": [
            {"name": "AWS IAM Roles for Service Accounts", "description": "Pod-level IAM", "recommendation": "Required"},
            {"name": "Amazon GuardDuty for EKS", "description": "Threat detection", "recommendation": "Enable for all clusters"},
            {"name": "Falco", "description": "Runtime security", "recommendation": "Advanced threat detection"},
            {"name": "OPA Gatekeeper", "description": "Policy enforcement", "recommendation": "Governance"}
        ]
    },
    "networking": {
        "name": "Networking",
        "icon": "🌐",
        "tools": [
            {"name": "AWS VPC CNI", "description": "Native VPC networking", "recommendation": "Default"},
            {"name": "Calico", "description": "Network policies", "recommendation": "Enhanced policies"},
            {"name": "AWS Load Balancer Controller", "description": "ALB/NLB integration", "recommendation": "Required"}
        ]
    },
    "gitops": {
        "name": "GitOps & CI/CD",
        "icon": "🔄",
        "tools": [
            {"name": "ArgoCD", "description": "GitOps continuous delivery", "recommendation": "Popular choice"},
            {"name": "Flux", "description": "CNCF GitOps toolkit", "recommendation": "Kubernetes-native"},
            {"name": "AWS CodePipeline", "description": "AWS-native CI/CD", "recommendation": "AWS integration"},
            {"name": "Jenkins X", "description": "Kubernetes-native Jenkins", "recommendation": "Jenkins users"}
        ]
    }
}

def render_eks_tab():
    """Render EKS & Modernization tab"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #0d47a1 0%, #1565c0 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #BBDEFB; margin: 0;">🚀 EKS & Container Modernization</h2>
        <p style="color: #90CAF9; margin: 0.5rem 0 0 0;">Kubernetes tools catalog and CI/CD maturity assessment</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🛠️ Tools Catalog", "📈 CI/CD Maturity", "🎯 Recommendations"])
    
    with tab1:
        st.markdown("### EKS Ecosystem Tools")
        
        for category_key, category in EKS_TOOLS_CATALOG.items():
            with st.expander(f"{category['icon']} {category['name']}", expanded=False):
                for tool in category['tools']:
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{tool['name']}**")
                        st.caption(tool['description'])
                    with col2:
                        st.info(tool['recommendation'])
    
    with tab2:
        st.markdown("### CI/CD Maturity Assessment")
        
        st.markdown("Rate your current CI/CD practices:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            source_control = st.select_slider("Source Control", options=["None", "Basic Git", "Branching Strategy", "GitFlow/Trunk"], value="Basic Git")
            build_automation = st.select_slider("Build Automation", options=["Manual", "Scripts", "CI Server", "Fully Automated"], value="CI Server")
            testing = st.select_slider("Testing", options=["Manual", "Unit Tests", "Integration", "Full Pipeline"], value="Unit Tests")
        
        with col2:
            deployment = st.select_slider("Deployment", options=["Manual", "Scripts", "CD Pipeline", "GitOps"], value="Scripts")
            monitoring = st.select_slider("Monitoring", options=["None", "Basic Logs", "Metrics", "Full Observability"], value="Basic Logs")
            security = st.select_slider("Security Scanning", options=["None", "Manual", "Automated", "Shift-Left"], value="Manual")
        
        # Calculate maturity score
        scores = {"None": 0, "Manual": 1, "Basic Git": 1, "Scripts": 2, "Basic Logs": 1, 
                  "Branching Strategy": 2, "CI Server": 3, "Unit Tests": 2, "Metrics": 2,
                  "Integration": 3, "CD Pipeline": 3, "Automated": 3,
                  "GitFlow/Trunk": 3, "Fully Automated": 4, "Full Pipeline": 4, "GitOps": 4, 
                  "Full Observability": 4, "Shift-Left": 4}
        
        total = sum(scores.get(v, 0) for v in [source_control, build_automation, testing, deployment, monitoring, security])
        max_score = 24
        maturity_pct = int((total / max_score) * 100)
        
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            level = "Advanced" if maturity_pct >= 75 else "Intermediate" if maturity_pct >= 50 else "Basic" if maturity_pct >= 25 else "Initial"
            st.metric("Maturity Level", level)
        with col2:
            st.metric("Maturity Score", f"{maturity_pct}%")
        with col3:
            st.metric("Next Goal", f"{min(100, maturity_pct + 25)}%")
    
    with tab3:
        st.markdown("### Recommended Modernization Path")
        
        st.markdown("""
        **Phase 1: Foundation (0-3 months)**
        - Set up EKS cluster with managed node groups
        - Implement AWS VPC CNI and Load Balancer Controller
        - Enable CloudWatch Container Insights
        - Configure IAM Roles for Service Accounts (IRSA)
        
        **Phase 2: Security & Governance (3-6 months)**
        - Enable GuardDuty for EKS
        - Implement network policies with Calico
        - Set up OPA Gatekeeper for policy enforcement
        - Implement secrets management with AWS Secrets Manager
        
        **Phase 3: Advanced Operations (6-12 months)**
        - Deploy service mesh (App Mesh or Istio)
        - Implement GitOps with ArgoCD or Flux
        - Set up progressive delivery (Canary/Blue-Green)
        - Implement cost optimization with Karpenter
        """)

# ============================================================================
# FINOPS TAB
# ============================================================================

COST_CATEGORIES = {
    "compute": {"name": "Compute", "icon": "💻", "services": ["EC2", "Lambda", "ECS", "EKS", "Fargate"]},
    "storage": {"name": "Storage", "icon": "💾", "services": ["S3", "EBS", "EFS", "FSx", "Glacier"]},
    "database": {"name": "Database", "icon": "🗄️", "services": ["RDS", "DynamoDB", "ElastiCache", "Redshift"]},
    "network": {"name": "Network", "icon": "🌐", "services": ["VPC", "CloudFront", "Route53", "Direct Connect"]},
    "other": {"name": "Other", "icon": "📦", "services": ["Support", "Marketplace", "Other"]}
}

def render_finops_tab():
    """Render FinOps tab"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1b5e20 0%, #2e7d32 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #C8E6C9; margin: 0;">💰 FinOps & Cost Optimization</h2>
        <p style="color: #A5D6A7; margin: 0.5rem 0 0 0;">Cloud financial management and optimization strategies</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["📊 Cost Analysis", "💡 Optimization", "📈 Maturity"])
    
    with tab1:
        st.markdown("### Cost Breakdown Simulator")
        st.info("💡 Enter your estimated monthly costs by category")
        
        col1, col2 = st.columns(2)
        costs = {}
        
        with col1:
            costs['compute'] = st.number_input("💻 Compute (EC2, Lambda, etc.)", min_value=0, value=5000)
            costs['storage'] = st.number_input("💾 Storage (S3, EBS, etc.)", min_value=0, value=1500)
            costs['database'] = st.number_input("🗄️ Database (RDS, DynamoDB)", min_value=0, value=2000)
        
        with col2:
            costs['network'] = st.number_input("🌐 Network (Data Transfer)", min_value=0, value=800)
            costs['other'] = st.number_input("📦 Other Services", min_value=0, value=700)
        
        total_cost = sum(costs.values())
        
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Monthly Cost", f"${total_cost:,.0f}")
        with col2:
            st.metric("Annual Projection", f"${total_cost * 12:,.0f}")
        with col3:
            # Estimate potential savings (20-30% typical)
            savings = total_cost * 0.25
            st.metric("Potential Savings", f"${savings:,.0f}/mo", delta="-25%")
    
    with tab2:
        st.markdown("### Cost Optimization Strategies")
        
        strategies = [
            {"name": "Reserved Instances / Savings Plans", "savings": "Up to 72%", "effort": "Low", "description": "Commit to 1-3 year usage for steady-state workloads"},
            {"name": "Right-sizing", "savings": "10-30%", "effort": "Medium", "description": "Match instance sizes to actual utilization"},
            {"name": "Spot Instances", "savings": "Up to 90%", "effort": "Medium", "description": "Use for fault-tolerant, flexible workloads"},
            {"name": "Auto Scaling", "savings": "15-40%", "effort": "Medium", "description": "Scale resources based on demand"},
            {"name": "Storage Tiering", "savings": "20-50%", "effort": "Low", "description": "Move infrequent data to cheaper storage classes"},
            {"name": "Idle Resource Cleanup", "savings": "5-20%", "effort": "Low", "description": "Remove unattached EBS, unused EIPs, old snapshots"},
            {"name": "Graviton Migration", "savings": "20-40%", "effort": "Medium", "description": "Use ARM-based instances for better price-performance"}
        ]
        
        for strategy in strategies:
            with st.expander(f"💡 {strategy['name']} - Save {strategy['savings']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(strategy['description'])
                with col2:
                    st.caption(f"Effort: {strategy['effort']}")
    
    with tab3:
        st.markdown("### FinOps Maturity Assessment")
        
        col1, col2 = st.columns(2)
        
        with col1:
            visibility = st.select_slider("Cost Visibility", options=["None", "Basic", "Detailed", "Real-time"], value="Basic")
            allocation = st.select_slider("Cost Allocation", options=["None", "Account-level", "Tagged", "Chargeback"], value="Account-level")
            forecasting = st.select_slider("Forecasting", options=["None", "Manual", "Automated", "ML-based"], value="Manual")
        
        with col2:
            optimization = st.select_slider("Optimization", options=["Reactive", "Periodic", "Continuous", "Automated"], value="Periodic")
            governance = st.select_slider("Governance", options=["None", "Policies", "Budgets", "Guardrails"], value="Policies")
            culture = st.select_slider("FinOps Culture", options=["Siloed", "Aware", "Collaborative", "Embedded"], value="Aware")
        
        scores = {"None": 0, "Reactive": 1, "Siloed": 1, "Basic": 1, "Account-level": 1, "Manual": 1, "Policies": 1, "Aware": 1,
                  "Detailed": 2, "Tagged": 2, "Automated": 2, "Periodic": 2, "Budgets": 2, "Collaborative": 2,
                  "Real-time": 3, "Chargeback": 3, "ML-based": 3, "Continuous": 3, "Guardrails": 3, "Embedded": 3,
                  "Automated": 4}
        
        total = sum(scores.get(v, 0) for v in [visibility, allocation, forecasting, optimization, governance, culture])
        maturity_pct = int((total / 18) * 100)
        
        st.markdown("---")
        phase = "Run" if maturity_pct >= 66 else "Walk" if maturity_pct >= 33 else "Crawl"
        st.metric("FinOps Phase", phase, help="Crawl → Walk → Run")

# ============================================================================
# COMPLIANCE TAB
# ============================================================================

COMPLIANCE_FRAMEWORKS = {
    "soc2": {"name": "SOC 2", "icon": "🔐", "focus": "Security, Availability, Confidentiality"},
    "hipaa": {"name": "HIPAA", "icon": "🏥", "focus": "Healthcare data protection"},
    "pci_dss": {"name": "PCI DSS", "icon": "💳", "focus": "Payment card data security"},
    "gdpr": {"name": "GDPR", "icon": "🇪🇺", "focus": "EU data privacy"},
    "iso27001": {"name": "ISO 27001", "icon": "📋", "focus": "Information security management"},
    "fedramp": {"name": "FedRAMP", "icon": "🏛️", "focus": "US federal cloud security"},
    "nist": {"name": "NIST CSF", "icon": "🔬", "focus": "Cybersecurity framework"},
    "cis": {"name": "CIS Benchmarks", "icon": "📊", "focus": "Security configuration"}
}

def render_compliance_tab():
    """Render Compliance tab"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #4a148c 0%, #7b1fa2 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #E1BEE7; margin: 0;">📋 Compliance & Governance</h2>
        <p style="color: #CE93D8; margin: 0.5rem 0 0 0;">Regulatory compliance assessment and control mapping</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🎯 Framework Selection", "📊 Gap Analysis", "🔧 Controls"])
    
    with tab1:
        st.markdown("### Select Applicable Compliance Frameworks")
        
        selected_frameworks = []
        cols = st.columns(4)
        
        for idx, (key, framework) in enumerate(COMPLIANCE_FRAMEWORKS.items()):
            with cols[idx % 4]:
                if st.checkbox(f"{framework['icon']} {framework['name']}", key=f"fw_{key}"):
                    selected_frameworks.append(key)
                st.caption(framework['focus'])
        
        if selected_frameworks:
            st.success(f"Selected {len(selected_frameworks)} framework(s)")
            st.session_state['selected_frameworks'] = selected_frameworks
    
    with tab2:
        st.markdown("### Compliance Gap Analysis")
        
        if not st.session_state.get('selected_frameworks'):
            st.info("Select frameworks in the previous tab to run gap analysis")
        else:
            st.markdown("Rate your current compliance posture:")
            
            control_areas = [
                "Access Control", "Data Encryption", "Logging & Monitoring",
                "Network Security", "Incident Response", "Data Backup",
                "Vulnerability Management", "Change Management"
            ]
            
            scores = {}
            cols = st.columns(2)
            
            for idx, area in enumerate(control_areas):
                with cols[idx % 2]:
                    scores[area] = st.slider(area, 0, 100, 60, key=f"gap_{area}")
            
            avg_score = sum(scores.values()) / len(scores)
            
            st.markdown("---")
            col1, col2, col3 = st.columns(3)
            with col1:
                color = "green" if avg_score >= 80 else "orange" if avg_score >= 60 else "red"
                st.metric("Overall Compliance Score", f"{avg_score:.0f}%")
            with col2:
                gaps = [k for k, v in scores.items() if v < 60]
                st.metric("Critical Gaps", len(gaps))
            with col3:
                st.metric("Frameworks", len(st.session_state.get('selected_frameworks', [])))
    
    with tab3:
        st.markdown("### AWS Security Controls")
        
        controls = [
            {"service": "AWS IAM", "control": "MFA for all users", "status": "🟡 Partial"},
            {"service": "AWS CloudTrail", "control": "Multi-region enabled", "status": "🟢 Compliant"},
            {"service": "AWS Config", "control": "Rules configured", "status": "🟡 Partial"},
            {"service": "AWS KMS", "control": "CMK for encryption", "status": "🟢 Compliant"},
            {"service": "AWS GuardDuty", "control": "Threat detection enabled", "status": "🔴 Gap"},
            {"service": "AWS Security Hub", "control": "Findings aggregation", "status": "🔴 Gap"},
            {"service": "VPC", "control": "Flow logs enabled", "status": "🟡 Partial"},
            {"service": "S3", "control": "Public access blocked", "status": "🟢 Compliant"},
        ]
        
        for control in controls:
            col1, col2, col3 = st.columns([2, 3, 1])
            with col1:
                st.markdown(f"**{control['service']}**")
            with col2:
                st.markdown(control['control'])
            with col3:
                st.markdown(control['status'])

# ============================================================================
# MIGRATION & DR TAB
# ============================================================================

MIGRATION_STRATEGIES = {
    "rehost": {"name": "Rehost (Lift & Shift)", "icon": "🏗️", "effort": "Low", "description": "Move as-is to cloud"},
    "replatform": {"name": "Replatform", "icon": "🔧", "effort": "Medium", "description": "Minor optimizations during migration"},
    "repurchase": {"name": "Repurchase", "icon": "🛒", "effort": "Low", "description": "Move to SaaS solution"},
    "refactor": {"name": "Refactor", "icon": "⚙️", "effort": "High", "description": "Re-architect for cloud-native"},
    "retire": {"name": "Retire", "icon": "🗑️", "effort": "Low", "description": "Decommission application"},
    "retain": {"name": "Retain", "icon": "📌", "effort": "None", "description": "Keep on-premises"}
}

DR_PATTERNS = {
    "backup_restore": {"name": "Backup & Restore", "rto": "24+ hours", "rpo": "Hours", "cost": "$"},
    "pilot_light": {"name": "Pilot Light", "rto": "Hours", "rpo": "Minutes", "cost": "$$"},
    "warm_standby": {"name": "Warm Standby", "rto": "Minutes", "rpo": "Seconds", "cost": "$$$"},
    "active_active": {"name": "Active-Active", "rto": "Near Zero", "rpo": "Near Zero", "cost": "$$$$"}
}

def render_migration_dr_tab():
    """Render Migration & DR tab"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #bf360c 0%, #e64a19 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #FFCCBC; margin: 0;">🔄 Migration & Disaster Recovery</h2>
        <p style="color: #FFAB91; margin: 0.5rem 0 0 0;">Cloud migration strategies and DR planning</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🚀 Migration (7Rs)", "🛡️ DR Planning", "📋 Assessment"])
    
    with tab1:
        st.markdown("### Migration Strategy Selection (7Rs)")
        
        for key, strategy in MIGRATION_STRATEGIES.items():
            with st.expander(f"{strategy['icon']} {strategy['name']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(strategy['description'])
                    st.markdown(f"**Best for:** ", unsafe_allow_html=True)
                    if key == "rehost":
                        st.markdown("Quick migrations, legacy apps, time-sensitive moves")
                    elif key == "replatform":
                        st.markdown("Apps needing minor cloud optimizations")
                    elif key == "refactor":
                        st.markdown("Apps requiring scalability, microservices")
                    elif key == "repurchase":
                        st.markdown("Apps with good SaaS alternatives (CRM, HR)")
                    elif key == "retire":
                        st.markdown("Redundant or unused applications")
                    else:
                        st.markdown("Apps with compliance/latency requirements")
                with col2:
                    st.metric("Effort", strategy['effort'])
    
    with tab2:
        st.markdown("### Disaster Recovery Patterns")
        
        col1, col2 = st.columns(2)
        
        with col1:
            rto_req = st.selectbox("Required RTO", ["24+ hours", "4-24 hours", "1-4 hours", "< 1 hour", "Near zero"])
            rpo_req = st.selectbox("Required RPO", ["24+ hours", "1-24 hours", "1 hour", "Minutes", "Near zero"])
        
        with col2:
            budget = st.selectbox("DR Budget Level", ["Minimal ($)", "Moderate ($$)", "Significant ($$$)", "Premium ($$$$)"])
            criticality = st.selectbox("Application Criticality", ["Low", "Medium", "High", "Mission Critical"])
        
        st.markdown("---")
        st.markdown("### Recommended DR Patterns")
        
        for key, pattern in DR_PATTERNS.items():
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown(f"**{pattern['name']}**")
            with col2:
                st.markdown(f"RTO: {pattern['rto']}")
            with col3:
                st.markdown(f"RPO: {pattern['rpo']}")
            with col4:
                st.markdown(f"Cost: {pattern['cost']}")
    
    with tab3:
        st.markdown("### Migration Readiness Assessment")
        
        st.markdown("Rate your organization's readiness:")
        
        areas = {
            "Technical Readiness": ["Infrastructure documentation", "Application inventory", "Dependency mapping"],
            "Organizational Readiness": ["Executive sponsorship", "Cloud skills", "Change management"],
            "Operational Readiness": ["Monitoring strategy", "Security baseline", "Compliance requirements"]
        }
        
        total_score = 0
        max_score = 0
        
        for area, items in areas.items():
            st.markdown(f"**{area}**")
            for item in items:
                score = st.slider(item, 0, 100, 50, key=f"mig_{item}")
                total_score += score
                max_score += 100
        
        readiness_pct = int((total_score / max_score) * 100)
        
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            status = "Ready" if readiness_pct >= 75 else "Preparing" if readiness_pct >= 50 else "Early Stage"
            st.metric("Migration Readiness", status)
        with col2:
            st.metric("Readiness Score", f"{readiness_pct}%")
        with col3:
            weeks = max(4, int((100 - readiness_pct) / 5))
            st.metric("Est. Prep Time", f"{weeks} weeks")

# ============================================================================
# MAIN APP
# ============================================================================

def main():
    """Main application"""
    init_session_state()
    render_sidebar()
    
    # Mode indicator
    is_demo = st.session_state.get('app_mode', 'demo') == 'demo'
    mode_badge = "🎭 Demo Mode" if is_demo else "🔴 Live Mode"
    mode_color = "#1565C0" if is_demo else "#2E7D32"
    
    # Header with mode indicator
    st.markdown(f"""
    <div class="main-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🏗️ AWS Well-Architected Framework Advisor</h1>
                <p>AI-Powered Architecture Review & Risk Assessment</p>
            </div>
            <div style="background: {mode_color}; padding: 0.5rem 1rem; border-radius: 20px; color: white; font-weight: 600;">
                {mode_badge}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Build all 8 tabs
    tab_names = [
        "🎯 AWS Scanner",
        "📤 Architecture Review", 
        "📊 WAF Results",
        "🚀 EKS & CI/CD",
        "💰 FinOps",
        "📋 Compliance",
        "🔄 Migration & DR",
        "📚 Knowledge Base"
    ]
    
    tabs = st.tabs(tab_names)
    
    with tabs[0]:
        render_aws_scanner_tab()
    
    with tabs[1]:
        render_upload_tab()
    
    with tabs[2]:
        render_results_tab()
    
    with tabs[3]:
        render_eks_tab()
    
    with tabs[4]:
        render_finops_tab()
    
    with tabs[5]:
        render_compliance_tab()
    
    with tabs[6]:
        render_migration_dr_tab()
    
    with tabs[7]:
        render_knowledge_base_tab()

if __name__ == "__main__":
    main()
