"""
AWS Landscape Auto-Scanner
One-Touch Comprehensive AWS Well-Architected Review

Automatically pulls data from 15+ AWS services to generate
a complete Well-Architected Framework assessment.

AWS Services Leveraged:
- AWS Well-Architected Tool (existing reviews)
- AWS Trusted Advisor (best practices)
- AWS Security Hub (security posture)
- AWS Config (compliance & inventory)
- AWS Compute Optimizer (right-sizing)
- AWS Cost Explorer (cost optimization)
- AWS IAM Access Analyzer (security)
- AWS Inspector (vulnerabilities)
- AWS GuardDuty (threat detection)
- AWS CloudTrail (audit trail)
- AWS Backup (data protection)
- AWS Health (service events)
- AWS Support API (Trusted Advisor checks)
- Resource Groups (tagging compliance)
- AWS Organizations (governance)
"""

import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import concurrent.futures
from collections import defaultdict

# Boto3 config
BOTO_CONFIG = Config(
    retries={'max_attempts': 3, 'mode': 'adaptive'},
    connect_timeout=10,
    read_timeout=30
)


# ============================================================================
# WAF PILLAR MAPPING
# ============================================================================

class WAFPillar(Enum):
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    PERFORMANCE_EFFICIENCY = "Performance Efficiency"
    COST_OPTIMIZATION = "Cost Optimization"
    SUSTAINABILITY = "Sustainability"


# Map AWS service findings to WAF pillars
SERVICE_TO_PILLAR_MAP = {
    "security_hub": [WAFPillar.SECURITY],
    "guardduty": [WAFPillar.SECURITY],
    "iam_analyzer": [WAFPillar.SECURITY],
    "inspector": [WAFPillar.SECURITY, WAFPillar.RELIABILITY],
    "config": [WAFPillar.SECURITY, WAFPillar.OPERATIONAL_EXCELLENCE],
    "trusted_advisor_security": [WAFPillar.SECURITY],
    "trusted_advisor_fault_tolerance": [WAFPillar.RELIABILITY],
    "trusted_advisor_performance": [WAFPillar.PERFORMANCE_EFFICIENCY],
    "trusted_advisor_cost": [WAFPillar.COST_OPTIMIZATION],
    "trusted_advisor_service_limits": [WAFPillar.RELIABILITY],
    "cost_explorer": [WAFPillar.COST_OPTIMIZATION, WAFPillar.SUSTAINABILITY],
    "compute_optimizer": [WAFPillar.COST_OPTIMIZATION, WAFPillar.PERFORMANCE_EFFICIENCY, WAFPillar.SUSTAINABILITY],
    "cloudtrail": [WAFPillar.SECURITY, WAFPillar.OPERATIONAL_EXCELLENCE],
    "backup": [WAFPillar.RELIABILITY],
    "health": [WAFPillar.RELIABILITY, WAFPillar.OPERATIONAL_EXCELLENCE],
    "tagging": [WAFPillar.OPERATIONAL_EXCELLENCE, WAFPillar.COST_OPTIMIZATION],
}

# Trusted Advisor check categories to WAF pillars
TA_CATEGORY_MAP = {
    "security": WAFPillar.SECURITY,
    "fault_tolerance": WAFPillar.RELIABILITY,
    "performance": WAFPillar.PERFORMANCE_EFFICIENCY,
    "cost_optimizing": WAFPillar.COST_OPTIMIZATION,
    "service_limits": WAFPillar.RELIABILITY,
}


@dataclass
class Finding:
    """Represents a WAF-related finding from any AWS service"""
    id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    pillar: WAFPillar
    source_service: str
    affected_resources: List[str] = field(default_factory=list)
    recommendation: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    aws_doc_link: str = ""
    account_id: str = ""
    region: str = ""
    compliance_status: str = ""
    estimated_savings: float = 0.0
    effort: str = "Medium"  # Low, Medium, High


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
    snapshots: int = 0
    iam_users: int = 0
    iam_users_no_mfa: int = 0
    iam_roles: int = 0
    cloudfront_distributions: int = 0
    api_gateways: int = 0
    dynamodb_tables: int = 0
    sqs_queues: int = 0
    sns_topics: int = 0


@dataclass 
class PillarScore:
    """Score for a single WAF pillar"""
    pillar: WAFPillar
    score: int  # 0-100
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class LandscapeAssessment:
    """Complete AWS Landscape Assessment"""
    assessment_id: str
    timestamp: datetime
    organization_id: str = ""
    accounts_scanned: List[str] = field(default_factory=list)
    regions_scanned: List[str] = field(default_factory=list)
    
    # Overall scores
    overall_score: int = 0
    overall_risk: str = "Unknown"
    
    # Resource inventory
    inventory: ResourceInventory = field(default_factory=ResourceInventory)
    
    # Cost data
    monthly_cost: float = 0.0
    cost_trend: str = ""
    savings_opportunities: float = 0.0
    
    # Pillar scores
    pillar_scores: Dict[str, PillarScore] = field(default_factory=dict)
    
    # All findings
    findings: List[Finding] = field(default_factory=list)
    
    # Service scan status
    services_scanned: Dict[str, bool] = field(default_factory=dict)
    scan_errors: Dict[str, str] = field(default_factory=dict)


# ============================================================================
# AWS SERVICE SCANNERS
# ============================================================================

class AWSLandscapeScanner:
    """Comprehensive AWS Landscape Scanner"""
    
    def __init__(self, session: boto3.Session):
        self.session = session
        self.account_id = None
        self.findings: List[Finding] = []
        self.inventory = ResourceInventory()
        self.scan_status = {}
        self.scan_errors = {}
        
        # Get account ID
        try:
            sts = session.client('sts', config=BOTO_CONFIG)
            self.account_id = sts.get_caller_identity()['Account']
        except Exception:
            pass
    
    def run_full_scan(self, regions: List[str] = None, 
                      progress_callback=None) -> LandscapeAssessment:
        """Run comprehensive scan across all services"""
        
        regions = regions or ['us-east-1']
        
        assessment = LandscapeAssessment(
            assessment_id=f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now(),
            accounts_scanned=[self.account_id] if self.account_id else [],
            regions_scanned=regions
        )
        
        # Define scan tasks
        scan_tasks = [
            ("Trusted Advisor", self._scan_trusted_advisor),
            ("Security Hub", lambda: self._scan_security_hub(regions[0])),
            ("GuardDuty", lambda: self._scan_guardduty(regions[0])),
            ("IAM Access Analyzer", self._scan_iam_analyzer),
            ("AWS Config", lambda: self._scan_config(regions[0])),
            ("Compute Optimizer", self._scan_compute_optimizer),
            ("Cost Explorer", self._scan_cost_explorer),
            ("Inspector", lambda: self._scan_inspector(regions[0])),
            ("CloudTrail", lambda: self._scan_cloudtrail(regions[0])),
            ("AWS Backup", lambda: self._scan_backup(regions[0])),
            ("AWS Health", self._scan_health),
            ("IAM Analysis", self._scan_iam),
            ("Resource Inventory", lambda: self._scan_resources(regions)),
            ("Tagging Compliance", self._scan_tagging),
            ("Well-Architected Tool", self._scan_wellarchitected),
        ]
        
        total_tasks = len(scan_tasks)
        
        for idx, (name, scan_func) in enumerate(scan_tasks):
            if progress_callback:
                progress_callback(idx / total_tasks, f"Scanning {name}...")
            
            try:
                scan_func()
                self.scan_status[name] = True
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['AccessDeniedException', 'UnauthorizedAccess']:
                    self.scan_errors[name] = f"Access denied - check permissions"
                else:
                    self.scan_errors[name] = str(e)
                self.scan_status[name] = False
            except Exception as e:
                self.scan_errors[name] = str(e)
                self.scan_status[name] = False
        
        if progress_callback:
            progress_callback(1.0, "Calculating scores...")
        
        # Populate assessment
        assessment.findings = self.findings
        assessment.inventory = self.inventory
        assessment.services_scanned = self.scan_status
        assessment.scan_errors = self.scan_errors
        
        # Calculate pillar scores
        assessment.pillar_scores = self._calculate_pillar_scores()
        
        # Calculate overall score
        assessment.overall_score = self._calculate_overall_score(assessment.pillar_scores)
        assessment.overall_risk = self._determine_risk_level(assessment.overall_score)
        
        return assessment
    
    # -------------------------------------------------------------------------
    # Individual Service Scanners
    # -------------------------------------------------------------------------
    
    def _scan_trusted_advisor(self):
        """Scan AWS Trusted Advisor for recommendations"""
        try:
            support = self.session.client('support', region_name='us-east-1', config=BOTO_CONFIG)
            
            # Get all checks
            checks = support.describe_trusted_advisor_checks(language='en')['checks']
            
            for check in checks:
                check_id = check['id']
                category = check['category']
                
                try:
                    result = support.describe_trusted_advisor_check_result(
                        checkId=check_id,
                        language='en'
                    )['result']
                    
                    status = result.get('status', 'ok')
                    
                    if status in ['warning', 'error']:
                        pillar = TA_CATEGORY_MAP.get(category, WAFPillar.OPERATIONAL_EXCELLENCE)
                        severity = 'HIGH' if status == 'error' else 'MEDIUM'
                        
                        flagged_resources = result.get('flaggedResources', [])
                        
                        finding = Finding(
                            id=f"ta-{check_id}",
                            title=check['name'],
                            description=check.get('description', ''),
                            severity=severity,
                            pillar=pillar,
                            source_service="Trusted Advisor",
                            affected_resources=[r.get('resourceId', 'N/A') for r in flagged_resources[:10]],
                            recommendation=check.get('description', ''),
                            account_id=self.account_id,
                            effort="Medium"
                        )
                        
                        # Extract savings if cost-related
                        if category == 'cost_optimizing':
                            for resource in flagged_resources:
                                if 'estimatedMonthlySavings' in str(resource):
                                    try:
                                        finding.estimated_savings += float(resource.get('metadata', [0])[-1] or 0)
                                    except (ValueError, IndexError):
                                        pass
                        
                        self.findings.append(finding)
                        
                except ClientError:
                    continue
                    
        except ClientError as e:
            if 'SubscriptionRequiredException' in str(e):
                raise Exception("Trusted Advisor requires Business or Enterprise Support plan")
            raise
    
    def _scan_security_hub(self, region: str):
        """Scan AWS Security Hub findings"""
        securityhub = self.session.client('securityhub', region_name=region, config=BOTO_CONFIG)
        
        paginator = securityhub.get_paginator('get_findings')
        
        for page in paginator.paginate(
            Filters={
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                'WorkflowStatus': [
                    {'Value': 'NEW', 'Comparison': 'EQUALS'},
                    {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
                ]
            },
            MaxResults=100
        ):
            for finding in page['Findings']:
                severity_label = finding.get('Severity', {}).get('Label', 'MEDIUM')
                
                # Skip low/informational unless critical mass
                if severity_label in ['INFORMATIONAL', 'LOW']:
                    continue
                
                resources = finding.get('Resources', [])
                
                f = Finding(
                    id=finding['Id'],
                    title=finding.get('Title', 'Security Hub Finding'),
                    description=finding.get('Description', ''),
                    severity=severity_label,
                    pillar=WAFPillar.SECURITY,
                    source_service="Security Hub",
                    affected_resources=[r.get('Id', '') for r in resources],
                    recommendation=finding.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                    aws_doc_link=finding.get('Remediation', {}).get('Recommendation', {}).get('Url', ''),
                    account_id=finding.get('AwsAccountId', ''),
                    region=region,
                    compliance_status=finding.get('Compliance', {}).get('Status', '')
                )
                
                self.findings.append(f)
    
    def _scan_guardduty(self, region: str):
        """Scan GuardDuty for threat findings"""
        guardduty = self.session.client('guardduty', region_name=region, config=BOTO_CONFIG)
        
        # Get detector
        detectors = guardduty.list_detectors()['DetectorIds']
        
        for detector_id in detectors:
            findings_ids = guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'service.archived': {'Eq': ['false']}
                    }
                },
                MaxResults=50
            )['FindingIds']
            
            if findings_ids:
                findings = guardduty.get_findings(
                    DetectorId=detector_id,
                    FindingIds=findings_ids
                )['Findings']
                
                for gd_finding in findings:
                    severity_value = gd_finding.get('Severity', 0)
                    
                    if severity_value >= 7:
                        severity = 'CRITICAL'
                    elif severity_value >= 4:
                        severity = 'HIGH'
                    else:
                        severity = 'MEDIUM'
                    
                    f = Finding(
                        id=gd_finding['Id'],
                        title=gd_finding.get('Title', 'GuardDuty Finding'),
                        description=gd_finding.get('Description', ''),
                        severity=severity,
                        pillar=WAFPillar.SECURITY,
                        source_service="GuardDuty",
                        affected_resources=[gd_finding.get('Resource', {}).get('ResourceType', '')],
                        recommendation=f"Investigate {gd_finding.get('Type', 'threat')} activity",
                        account_id=gd_finding.get('AccountId', ''),
                        region=region
                    )
                    
                    self.findings.append(f)
    
    def _scan_iam_analyzer(self):
        """Scan IAM Access Analyzer findings"""
        analyzer = self.session.client('accessanalyzer', region_name='us-east-1', config=BOTO_CONFIG)
        
        # List analyzers
        analyzers = analyzer.list_analyzers()['analyzers']
        
        for az in analyzers:
            if az['status'] == 'ACTIVE':
                findings_list = analyzer.list_findings(
                    analyzerArn=az['arn'],
                    filter={
                        'status': {'eq': ['ACTIVE']}
                    },
                    maxResults=50
                )['findings']
                
                for iaa_finding in findings_list:
                    f = Finding(
                        id=iaa_finding['id'],
                        title=f"External access to {iaa_finding.get('resourceType', 'resource')}",
                        description=f"Resource {iaa_finding.get('resource', '')} allows external access",
                        severity='HIGH',
                        pillar=WAFPillar.SECURITY,
                        source_service="IAM Access Analyzer",
                        affected_resources=[iaa_finding.get('resource', '')],
                        recommendation="Review and restrict external access",
                        account_id=self.account_id
                    )
                    
                    self.findings.append(f)
    
    def _scan_config(self, region: str):
        """Scan AWS Config for compliance"""
        config = self.session.client('config', region_name=region, config=BOTO_CONFIG)
        
        # Get compliance summary
        try:
            compliance = config.describe_compliance_by_config_rule(
                ComplianceTypes=['NON_COMPLIANT']
            )['ComplianceByConfigRules']
            
            for rule in compliance:
                rule_name = rule['ConfigRuleName']
                
                # Get rule details
                try:
                    rule_detail = config.describe_config_rules(
                        ConfigRuleNames=[rule_name]
                    )['ConfigRules'][0]
                    
                    f = Finding(
                        id=f"config-{rule_name}",
                        title=f"Config Rule Violation: {rule_name}",
                        description=rule_detail.get('Description', f"Non-compliant with {rule_name}"),
                        severity='MEDIUM',
                        pillar=WAFPillar.SECURITY,
                        source_service="AWS Config",
                        recommendation=f"Remediate resources to comply with {rule_name}",
                        account_id=self.account_id,
                        region=region,
                        compliance_status='NON_COMPLIANT'
                    )
                    
                    self.findings.append(f)
                    
                except ClientError:
                    continue
                    
        except ClientError:
            pass
    
    def _scan_compute_optimizer(self):
        """Scan Compute Optimizer for right-sizing"""
        optimizer = self.session.client('compute-optimizer', region_name='us-east-1', config=BOTO_CONFIG)
        
        # EC2 recommendations
        try:
            ec2_recs = optimizer.get_ec2_instance_recommendations(
                filters=[{'name': 'Finding', 'values': ['Overprovisioned', 'Underprovisioned']}],
                maxResults=50
            )['instanceRecommendations']
            
            for rec in ec2_recs:
                finding_type = rec.get('finding', 'Unknown')
                instance_id = rec.get('instanceArn', '').split('/')[-1]
                
                current_type = rec.get('currentInstanceType', '')
                rec_options = rec.get('recommendationOptions', [])
                recommended_type = rec_options[0].get('instanceType', '') if rec_options else ''
                
                savings = 0
                if rec_options:
                    current_price = rec.get('utilizationMetrics', [{}])[0].get('value', 0)
                    rec_price = rec_options[0].get('projectedUtilizationMetrics', [{}])[0].get('value', 0)
                    # Rough savings estimate
                    savings = abs(float(current_price) - float(rec_price)) * 730  # Monthly hours
                
                f = Finding(
                    id=f"co-ec2-{instance_id}",
                    title=f"EC2 {finding_type}: {instance_id}",
                    description=f"Instance {instance_id} ({current_type}) is {finding_type.lower()}",
                    severity='MEDIUM' if finding_type == 'Overprovisioned' else 'LOW',
                    pillar=WAFPillar.COST_OPTIMIZATION,
                    source_service="Compute Optimizer",
                    affected_resources=[instance_id],
                    recommendation=f"Consider changing to {recommended_type}" if recommended_type else "Review instance sizing",
                    estimated_savings=savings,
                    effort="Low"
                )
                
                self.findings.append(f)
                
        except ClientError:
            pass
        
        # EBS recommendations
        try:
            ebs_recs = optimizer.get_ebs_volume_recommendations(
                filters=[{'name': 'Finding', 'values': ['Overprovisioned']}],
                maxResults=50
            )['volumeRecommendations']
            
            for rec in ebs_recs:
                volume_id = rec.get('volumeArn', '').split('/')[-1]
                
                f = Finding(
                    id=f"co-ebs-{volume_id}",
                    title=f"EBS Volume Overprovisioned: {volume_id}",
                    description=f"Volume {volume_id} has more capacity than needed",
                    severity='LOW',
                    pillar=WAFPillar.COST_OPTIMIZATION,
                    source_service="Compute Optimizer",
                    affected_resources=[volume_id],
                    recommendation="Consider reducing volume size or changing type",
                    effort="Medium"
                )
                
                self.findings.append(f)
                
        except ClientError:
            pass
    
    def _scan_cost_explorer(self):
        """Scan Cost Explorer for cost insights"""
        ce = self.session.client('ce', region_name='us-east-1', config=BOTO_CONFIG)
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=30)
        
        # Get cost and usage
        try:
            response = ce.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost']
            )
            
            for result in response['ResultsByTime']:
                cost = float(result['Total']['UnblendedCost']['Amount'])
                self.inventory.monthly_cost = cost
                
        except ClientError:
            pass
        
        # Get reservation recommendations
        try:
            ri_recs = ce.get_reservation_purchase_recommendation(
                Service='Amazon Elastic Compute Cloud - Compute',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT'
            )
            
            for rec in ri_recs.get('Recommendations', []):
                for detail in rec.get('RecommendationDetails', []):
                    savings = float(detail.get('EstimatedMonthlySavingsAmount', 0))
                    
                    if savings > 100:  # Only significant savings
                        f = Finding(
                            id=f"ce-ri-{detail.get('InstanceDetails', {}).get('EC2InstanceDetails', {}).get('InstanceType', 'unknown')}",
                            title="Reserved Instance Opportunity",
                            description=f"Consider purchasing Reserved Instances for cost savings",
                            severity='INFO',
                            pillar=WAFPillar.COST_OPTIMIZATION,
                            source_service="Cost Explorer",
                            recommendation=f"Purchase RI for {detail.get('RecommendedNumberOfInstancesToPurchase', 0)} instances",
                            estimated_savings=savings * 12,  # Annual
                            effort="Low"
                        )
                        
                        self.findings.append(f)
                        
        except ClientError:
            pass
        
        # Get Savings Plans recommendations
        try:
            sp_recs = ce.get_savings_plans_purchase_recommendation(
                SavingsPlansType='COMPUTE_SP',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
                LookbackPeriodInDays='THIRTY_DAYS'
            )
            
            if sp_recs.get('SavingsPlansPurchaseRecommendation'):
                rec = sp_recs['SavingsPlansPurchaseRecommendation']
                savings = float(rec.get('EstimatedMonthlySavingsAmount', 0))
                
                if savings > 100:
                    f = Finding(
                        id="ce-sp-compute",
                        title="Savings Plan Opportunity",
                        description="Compute Savings Plan could reduce costs",
                        severity='INFO',
                        pillar=WAFPillar.COST_OPTIMIZATION,
                        source_service="Cost Explorer",
                        recommendation=f"Consider Compute Savings Plan commitment",
                        estimated_savings=savings * 12,
                        effort="Low"
                    )
                    
                    self.findings.append(f)
                    
        except ClientError:
            pass
    
    def _scan_inspector(self, region: str):
        """Scan Amazon Inspector for vulnerabilities"""
        inspector = self.session.client('inspector2', region_name=region, config=BOTO_CONFIG)
        
        try:
            findings_list = inspector.list_findings(
                filterCriteria={
                    'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}],
                    'severity': [
                        {'comparison': 'EQUALS', 'value': 'CRITICAL'},
                        {'comparison': 'EQUALS', 'value': 'HIGH'}
                    ]
                },
                maxResults=50
            )['findings']
            
            for insp_finding in findings_list:
                f = Finding(
                    id=insp_finding['findingArn'],
                    title=insp_finding.get('title', 'Vulnerability Found'),
                    description=insp_finding.get('description', ''),
                    severity=insp_finding.get('severity', 'HIGH'),
                    pillar=WAFPillar.SECURITY,
                    source_service="Inspector",
                    affected_resources=[insp_finding.get('resources', [{}])[0].get('id', '')],
                    recommendation=insp_finding.get('remediation', {}).get('recommendation', {}).get('text', ''),
                    account_id=self.account_id,
                    region=region
                )
                
                self.findings.append(f)
                
        except ClientError:
            pass
    
    def _scan_cloudtrail(self, region: str):
        """Check CloudTrail configuration"""
        cloudtrail = self.session.client('cloudtrail', region_name=region, config=BOTO_CONFIG)
        
        try:
            trails = cloudtrail.describe_trails()['trailList']
            
            if not trails:
                f = Finding(
                    id="ct-no-trails",
                    title="No CloudTrail Configured",
                    description="CloudTrail is not configured for audit logging",
                    severity='HIGH',
                    pillar=WAFPillar.SECURITY,
                    source_service="CloudTrail",
                    recommendation="Enable CloudTrail for all regions",
                    effort="Medium"
                )
                self.findings.append(f)
            else:
                # Check for multi-region trail
                has_multi_region = any(t.get('IsMultiRegionTrail', False) for t in trails)
                
                if not has_multi_region:
                    f = Finding(
                        id="ct-no-multiregion",
                        title="No Multi-Region CloudTrail",
                        description="CloudTrail is not configured for all regions",
                        severity='MEDIUM',
                        pillar=WAFPillar.SECURITY,
                        source_service="CloudTrail",
                        recommendation="Enable multi-region CloudTrail",
                        effort="Low"
                    )
                    self.findings.append(f)
                    
        except ClientError:
            pass
    
    def _scan_backup(self, region: str):
        """Check AWS Backup configuration"""
        backup = self.session.client('backup', region_name=region, config=BOTO_CONFIG)
        
        try:
            # Check for backup plans
            plans = backup.list_backup_plans()['BackupPlansList']
            
            if not plans:
                f = Finding(
                    id="backup-no-plans",
                    title="No Backup Plans Configured",
                    description="AWS Backup has no backup plans configured",
                    severity='HIGH',
                    pillar=WAFPillar.RELIABILITY,
                    source_service="AWS Backup",
                    recommendation="Create backup plans for critical resources",
                    effort="Medium"
                )
                self.findings.append(f)
            
            # Check for backup vault lock
            vaults = backup.list_backup_vaults()['BackupVaultList']
            for vault in vaults:
                if not vault.get('Locked', False):
                    f = Finding(
                        id=f"backup-vault-{vault['BackupVaultName']}",
                        title=f"Backup Vault Not Locked: {vault['BackupVaultName']}",
                        description="Backup vault does not have vault lock enabled",
                        severity='LOW',
                        pillar=WAFPillar.RELIABILITY,
                        source_service="AWS Backup",
                        recommendation="Enable vault lock for immutable backups",
                        effort="Low"
                    )
                    self.findings.append(f)
                    
        except ClientError:
            pass
    
    def _scan_health(self):
        """Scan AWS Health for events"""
        health = self.session.client('health', region_name='us-east-1', config=BOTO_CONFIG)
        
        try:
            events = health.describe_events(
                filter={
                    'eventStatusCodes': ['open', 'upcoming'],
                    'eventTypeCategories': ['issue', 'scheduledChange']
                }
            )['events']
            
            for event in events:
                severity = 'HIGH' if event.get('eventTypeCategory') == 'issue' else 'MEDIUM'
                
                f = Finding(
                    id=event['arn'],
                    title=event.get('eventTypeCode', 'AWS Health Event'),
                    description=f"AWS Health event affecting {event.get('service', 'AWS services')}",
                    severity=severity,
                    pillar=WAFPillar.RELIABILITY,
                    source_service="AWS Health",
                    recommendation="Review AWS Health dashboard for details",
                    region=event.get('region', 'global')
                )
                
                self.findings.append(f)
                
        except ClientError:
            pass
    
    def _scan_iam(self):
        """Scan IAM for security issues"""
        iam = self.session.client('iam', config=BOTO_CONFIG)
        
        try:
            # Get credential report
            try:
                iam.generate_credential_report()
                import time
                time.sleep(2)
                report = iam.get_credential_report()
                
                import csv
                import io
                
                reader = csv.DictReader(io.StringIO(report['Content'].decode('utf-8')))
                
                for row in reader:
                    user = row['user']
                    
                    # Check MFA
                    if row.get('mfa_active', 'false') == 'false' and user != '<root_account>':
                        self.inventory.iam_users_no_mfa += 1
                        
                        f = Finding(
                            id=f"iam-nomfa-{user}",
                            title=f"IAM User Without MFA: {user}",
                            description=f"User {user} does not have MFA enabled",
                            severity='HIGH',
                            pillar=WAFPillar.SECURITY,
                            source_service="IAM",
                            affected_resources=[user],
                            recommendation="Enable MFA for this user",
                            effort="Low"
                        )
                        self.findings.append(f)
                    
                    # Check root account
                    if user == '<root_account>':
                        if row.get('mfa_active', 'false') == 'false':
                            f = Finding(
                                id="iam-root-nomfa",
                                title="Root Account Without MFA",
                                description="The root account does not have MFA enabled",
                                severity='CRITICAL',
                                pillar=WAFPillar.SECURITY,
                                source_service="IAM",
                                recommendation="Enable MFA on root account immediately",
                                effort="Low"
                            )
                            self.findings.append(f)
                        
                        # Check root access keys
                        if row.get('access_key_1_active', 'false') == 'true':
                            f = Finding(
                                id="iam-root-accesskey",
                                title="Root Account Has Access Keys",
                                description="The root account has active access keys",
                                severity='CRITICAL',
                                pillar=WAFPillar.SECURITY,
                                source_service="IAM",
                                recommendation="Delete root account access keys",
                                effort="Low"
                            )
                            self.findings.append(f)
                            
            except ClientError:
                pass
            
            # Count users and roles
            users = iam.list_users()['Users']
            self.inventory.iam_users = len(users)
            
            roles = iam.list_roles()['Roles']
            self.inventory.iam_roles = len(roles)
            
            # Check password policy
            try:
                iam.get_account_password_policy()
            except iam.exceptions.NoSuchEntityException:
                f = Finding(
                    id="iam-no-password-policy",
                    title="No IAM Password Policy",
                    description="Account does not have a custom password policy",
                    severity='MEDIUM',
                    pillar=WAFPillar.SECURITY,
                    source_service="IAM",
                    recommendation="Configure a strong password policy",
                    effort="Low"
                )
                self.findings.append(f)
                
        except ClientError:
            pass
    
    def _scan_resources(self, regions: List[str]):
        """Scan for resource inventory"""
        
        for region in regions:
            # EC2
            try:
                ec2 = self.session.client('ec2', region_name=region, config=BOTO_CONFIG)
                
                instances = ec2.describe_instances()
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        self.inventory.ec2_instances += 1
                        if instance['State']['Name'] == 'running':
                            self.inventory.ec2_running += 1
                
                # VPCs
                vpcs = ec2.describe_vpcs()['Vpcs']
                self.inventory.vpcs += len(vpcs)
                
                # EBS Volumes
                volumes = ec2.describe_volumes()['Volumes']
                for vol in volumes:
                    self.inventory.ebs_volumes += 1
                    if vol['State'] == 'available':
                        self.inventory.ebs_unattached += 1
                        
                        f = Finding(
                            id=f"ec2-unattached-{vol['VolumeId']}",
                            title=f"Unattached EBS Volume: {vol['VolumeId']}",
                            description=f"EBS volume {vol['VolumeId']} is not attached to any instance",
                            severity='LOW',
                            pillar=WAFPillar.COST_OPTIMIZATION,
                            source_service="EC2",
                            affected_resources=[vol['VolumeId']],
                            recommendation="Delete or attach this volume",
                            region=region,
                            effort="Low"
                        )
                        self.findings.append(f)
                
            except ClientError:
                pass
            
            # RDS
            try:
                rds = self.session.client('rds', region_name=region, config=BOTO_CONFIG)
                
                dbs = rds.describe_db_instances()['DBInstances']
                for db in dbs:
                    self.inventory.rds_instances += 1
                    if db.get('MultiAZ', False):
                        self.inventory.rds_multi_az += 1
                    else:
                        f = Finding(
                            id=f"rds-no-multiaz-{db['DBInstanceIdentifier']}",
                            title=f"RDS Not Multi-AZ: {db['DBInstanceIdentifier']}",
                            description=f"Database {db['DBInstanceIdentifier']} is not configured for Multi-AZ",
                            severity='MEDIUM',
                            pillar=WAFPillar.RELIABILITY,
                            source_service="RDS",
                            affected_resources=[db['DBInstanceIdentifier']],
                            recommendation="Enable Multi-AZ for production databases",
                            region=region,
                            effort="Medium"
                        )
                        self.findings.append(f)
                        
            except ClientError:
                pass
            
            # Lambda
            try:
                lambda_client = self.session.client('lambda', region_name=region, config=BOTO_CONFIG)
                functions = lambda_client.list_functions()['Functions']
                self.inventory.lambda_functions += len(functions)
            except ClientError:
                pass
            
            # EKS
            try:
                eks = self.session.client('eks', region_name=region, config=BOTO_CONFIG)
                clusters = eks.list_clusters()['clusters']
                self.inventory.eks_clusters += len(clusters)
            except ClientError:
                pass
            
            # Load Balancers
            try:
                elbv2 = self.session.client('elbv2', region_name=region, config=BOTO_CONFIG)
                lbs = elbv2.describe_load_balancers()['LoadBalancers']
                self.inventory.load_balancers += len(lbs)
            except ClientError:
                pass
        
        # S3 (global)
        try:
            s3 = self.session.client('s3', config=BOTO_CONFIG)
            buckets = s3.list_buckets()['Buckets']
            self.inventory.s3_buckets = len(buckets)
            
            # Check for public buckets
            for bucket in buckets[:20]:  # Limit to avoid timeout
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI', '') in [
                            'http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                        ]:
                            self.inventory.s3_public += 1
                            
                            f = Finding(
                                id=f"s3-public-{bucket['Name']}",
                                title=f"Public S3 Bucket: {bucket['Name']}",
                                description=f"Bucket {bucket['Name']} has public access",
                                severity='HIGH',
                                pillar=WAFPillar.SECURITY,
                                source_service="S3",
                                affected_resources=[bucket['Name']],
                                recommendation="Remove public access unless required",
                                effort="Low"
                            )
                            self.findings.append(f)
                            break
                except ClientError:
                    pass
                    
        except ClientError:
            pass
    
    def _scan_tagging(self):
        """Scan for tagging compliance"""
        
        # Use Resource Groups Tagging API
        try:
            tagging = self.session.client('resourcegroupstaggingapi', region_name='us-east-1', config=BOTO_CONFIG)
            
            # Get all resources
            paginator = tagging.get_paginator('get_resources')
            
            untagged_count = 0
            required_tags = ['Environment', 'Owner', 'Project', 'CostCenter']
            
            for page in paginator.paginate():
                for resource in page['ResourceTagMappingList']:
                    tags = {t['Key']: t['Value'] for t in resource.get('Tags', [])}
                    
                    missing_tags = [t for t in required_tags if t not in tags]
                    
                    if len(missing_tags) == len(required_tags):
                        untagged_count += 1
            
            if untagged_count > 10:
                f = Finding(
                    id="tagging-compliance",
                    title=f"{untagged_count} Resources Missing Standard Tags",
                    description=f"Found {untagged_count} resources without required tags (Environment, Owner, Project, CostCenter)",
                    severity='MEDIUM',
                    pillar=WAFPillar.OPERATIONAL_EXCELLENCE,
                    source_service="Resource Groups",
                    recommendation="Implement tagging policy and remediate untagged resources",
                    effort="Medium"
                )
                self.findings.append(f)
                
        except ClientError:
            pass
    
    def _scan_wellarchitected(self):
        """Scan existing Well-Architected Tool workloads"""
        try:
            wa = self.session.client('wellarchitected', region_name='us-east-1', config=BOTO_CONFIG)
            
            workloads = wa.list_workloads()['WorkloadSummaries']
            
            for workload in workloads:
                risk_counts = workload.get('RiskCounts', {})
                
                high_risks = risk_counts.get('HIGH', 0)
                medium_risks = risk_counts.get('MEDIUM', 0)
                
                if high_risks > 0:
                    f = Finding(
                        id=f"wa-{workload['WorkloadId']}",
                        title=f"Well-Architected Review: {workload['WorkloadName']}",
                        description=f"Workload has {high_risks} high-risk items and {medium_risks} medium-risk items",
                        severity='HIGH' if high_risks > 5 else 'MEDIUM',
                        pillar=WAFPillar.OPERATIONAL_EXCELLENCE,
                        source_service="Well-Architected Tool",
                        recommendation="Address high-risk items in Well-Architected Tool",
                        effort="High"
                    )
                    self.findings.append(f)
                    
        except ClientError:
            pass
    
    # -------------------------------------------------------------------------
    # Score Calculation
    # -------------------------------------------------------------------------
    
    def _calculate_pillar_scores(self) -> Dict[str, PillarScore]:
        """Calculate scores for each WAF pillar"""
        pillar_findings = defaultdict(list)
        
        # Group findings by pillar
        for finding in self.findings:
            pillar_findings[finding.pillar.value].append(finding)
        
        pillar_scores = {}
        
        for pillar in WAFPillar:
            findings_list = pillar_findings.get(pillar.value, [])
            
            critical = sum(1 for f in findings_list if f.severity == 'CRITICAL')
            high = sum(1 for f in findings_list if f.severity == 'HIGH')
            medium = sum(1 for f in findings_list if f.severity == 'MEDIUM')
            low = sum(1 for f in findings_list if f.severity in ['LOW', 'INFO'])
            
            # Score calculation (100 base, deduct for findings)
            score = 100
            score -= critical * 15
            score -= high * 8
            score -= medium * 3
            score -= low * 1
            score = max(0, min(100, score))
            
            # Get top findings
            sorted_findings = sorted(
                findings_list,
                key=lambda f: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(f.severity, 5)
            )
            
            pillar_scores[pillar.value] = PillarScore(
                pillar=pillar,
                score=score,
                findings_count=len(findings_list),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
                top_findings=sorted_findings[:5],
                recommendations=[f.recommendation for f in sorted_findings[:3] if f.recommendation]
            )
        
        return pillar_scores
    
    def _calculate_overall_score(self, pillar_scores: Dict[str, PillarScore]) -> int:
        """Calculate overall WAF score"""
        if not pillar_scores:
            return 0
        
        # Weighted average (Security weighted higher)
        weights = {
            WAFPillar.SECURITY.value: 1.5,
            WAFPillar.RELIABILITY.value: 1.2,
            WAFPillar.OPERATIONAL_EXCELLENCE.value: 1.0,
            WAFPillar.PERFORMANCE_EFFICIENCY.value: 1.0,
            WAFPillar.COST_OPTIMIZATION.value: 1.0,
            WAFPillar.SUSTAINABILITY.value: 0.8,
        }
        
        total_weight = 0
        weighted_score = 0
        
        for pillar_name, score in pillar_scores.items():
            weight = weights.get(pillar_name, 1.0)
            weighted_score += score.score * weight
            total_weight += weight
        
        return int(weighted_score / total_weight) if total_weight > 0 else 0
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine overall risk level from score"""
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"


# ============================================================================
# STREAMLIT UI
# ============================================================================

def render_one_touch_scanner():
    """Render one-touch scanner UI"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a472a 0%, #2d5a3d 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #98FB98; margin: 0;">🎯 One-Touch AWS Landscape Scanner</h2>
        <p style="color: #90EE90; margin: 0.5rem 0 0 0;">Comprehensive Well-Architected Review from 15+ AWS Services</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check for AWS connection
    if not st.session_state.get('aws_connected'):
        st.warning("⚠️ Connect to AWS first using the AWS Connector tab")
        return
    
    # Services we'll scan
    st.markdown("### 📋 Services to Scan")
    
    services = [
        ("🛡️ Trusted Advisor", "Best practices across all pillars"),
        ("🔒 Security Hub", "Consolidated security findings"),
        ("👁️ GuardDuty", "Threat detection"),
        ("🔑 IAM Access Analyzer", "External access findings"),
        ("⚙️ AWS Config", "Configuration compliance"),
        ("📊 Compute Optimizer", "Right-sizing recommendations"),
        ("💰 Cost Explorer", "Cost optimization insights"),
        ("🔍 Inspector", "Vulnerability assessments"),
        ("📝 CloudTrail", "Audit configuration"),
        ("💾 AWS Backup", "Data protection status"),
        ("❤️ AWS Health", "Service events"),
        ("👤 IAM Analysis", "User security posture"),
        ("📦 Resource Inventory", "Complete resource count"),
        ("🏷️ Tagging Compliance", "Tag governance"),
        ("🏗️ Well-Architected Tool", "Existing reviews"),
    ]
    
    cols = st.columns(3)
    for idx, (name, desc) in enumerate(services):
        with cols[idx % 3]:
            st.markdown(f"**{name}**")
            st.caption(desc)
    
    st.markdown("---")
    
    # Region selection
    col1, col2 = st.columns(2)
    
    with col1:
        selected_regions = st.multiselect(
            "Select Regions to Scan",
            ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"],
            default=["us-east-1"],
            help="Primary region for scanning"
        )
    
    with col2:
        generate_pdf = st.checkbox("📄 Generate PDF Report", value=True)
    
    # Scan button
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        scan_btn = st.button(
            "🚀 Run One-Touch Assessment",
            type="primary",
            use_container_width=True
        )
    
    if scan_btn:
        # Get AWS session
        connector = st.session_state.get('aws_connector')
        if not connector or not connector.session_manager.master_session:
            st.error("AWS session not available")
            return
        
        session = connector.session_manager.master_session
        
        # Create progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(progress, message):
            progress_bar.progress(progress)
            status_text.text(message)
        
        # Run scan
        scanner = AWSLandscapeScanner(session)
        
        with st.spinner("Running comprehensive AWS landscape scan..."):
            assessment = scanner.run_full_scan(
                regions=selected_regions,
                progress_callback=update_progress
            )
        
        progress_bar.progress(1.0)
        status_text.text("✅ Scan complete!")
        
        # Store in session
        st.session_state.landscape_assessment = assessment
        
        st.success(f"✅ Scanned {len(assessment.services_scanned)} services, found {len(assessment.findings)} findings")
        
        # Show results
        render_assessment_results(assessment)
        
        # Generate PDF if requested
        if generate_pdf:
            st.markdown("---")
            st.markdown("### 📄 Download Report")
            
            try:
                from .pdf_report_generator import generate_waf_pdf_report
                
                pdf_bytes = generate_waf_pdf_report(assessment)
                
                st.download_button(
                    "📥 Download PDF Report",
                    pdf_bytes,
                    file_name=f"AWS_WAF_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
            except ImportError:
                st.warning("PDF generator module not available")
            except Exception as e:
                st.error(f"Failed to generate PDF: {e}")


def render_assessment_results(assessment: LandscapeAssessment):
    """Render assessment results"""
    
    st.markdown("---")
    st.markdown("### 📊 Assessment Results")
    
    # Overall metrics
    col1, col2, col3, col4 = st.columns(4)
    
    score_color = "#388E3C" if assessment.overall_score >= 80 else "#FBC02D" if assessment.overall_score >= 60 else "#D32F2F"
    
    with col1:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: white; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 3rem; font-weight: bold; color: {score_color};">{assessment.overall_score}</div>
            <div style="color: #666;">Overall WAF Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        risk_colors = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        st.metric("Risk Level", f"{risk_colors.get(assessment.overall_risk, '⚪')} {assessment.overall_risk}")
    
    with col3:
        st.metric("Total Findings", len(assessment.findings))
    
    with col4:
        critical = sum(1 for f in assessment.findings if f.severity == 'CRITICAL')
        st.metric("Critical Issues", critical)
    
    # Pillar breakdown
    st.markdown("### 📈 Pillar Scores")
    
    pillar_cols = st.columns(6)
    pillar_icons = {
        "Operational Excellence": "⚙️",
        "Security": "🔒",
        "Reliability": "🛡️",
        "Performance Efficiency": "⚡",
        "Cost Optimization": "💰",
        "Sustainability": "🌱"
    }
    
    for idx, (pillar_name, score) in enumerate(assessment.pillar_scores.items()):
        with pillar_cols[idx]:
            icon = pillar_icons.get(pillar_name, "📊")
            color = "#388E3C" if score.score >= 80 else "#FBC02D" if score.score >= 60 else "#D32F2F"
            
            st.markdown(f"""
            <div style="text-align: center; padding: 0.5rem; background: white; border-radius: 8px; margin-bottom: 0.5rem;">
                <div style="font-size: 1.5rem;">{icon}</div>
                <div style="font-size: 1.5rem; font-weight: bold; color: {color};">{score.score}</div>
                <div style="font-size: 0.7rem; color: #666;">{pillar_name.split()[0]}</div>
            </div>
            """, unsafe_allow_html=True)
    
    # Service scan status
    with st.expander("📋 Service Scan Status"):
        success_count = sum(1 for v in assessment.services_scanned.values() if v)
        total_count = len(assessment.services_scanned)
        
        st.markdown(f"**{success_count}/{total_count} services scanned successfully**")
        
        for service, success in assessment.services_scanned.items():
            if success:
                st.markdown(f"✅ {service}")
            else:
                error = assessment.scan_errors.get(service, "Unknown error")
                st.markdown(f"❌ {service}: {error}")
    
    # Top findings
    st.markdown("### 🚨 Top Findings")
    
    critical_findings = [f for f in assessment.findings if f.severity == 'CRITICAL']
    high_findings = [f for f in assessment.findings if f.severity == 'HIGH']
    
    top_findings = (critical_findings + high_findings)[:10]
    
    for finding in top_findings:
        severity_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️'
        }
        
        with st.expander(f"{severity_colors.get(finding.severity, '⚪')} {finding.title}"):
            st.markdown(f"**Source:** {finding.source_service}")
            st.markdown(f"**Pillar:** {finding.pillar.value}")
            st.markdown(f"**Description:** {finding.description}")
            
            if finding.affected_resources:
                st.markdown(f"**Affected Resources:** {', '.join(finding.affected_resources[:5])}")
            
            if finding.recommendation:
                st.markdown(f"**Recommendation:** {finding.recommendation}")
            
            if finding.estimated_savings > 0:
                st.markdown(f"**Potential Savings:** ${finding.estimated_savings:,.2f}/year")
    
    # Resource inventory
    with st.expander("📦 Resource Inventory"):
        inv = assessment.inventory
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("EC2 Instances", f"{inv.ec2_running}/{inv.ec2_instances} running")
            st.metric("Lambda Functions", inv.lambda_functions)
            st.metric("EKS Clusters", inv.eks_clusters)
        
        with col2:
            st.metric("RDS Databases", f"{inv.rds_multi_az}/{inv.rds_instances} Multi-AZ")
            st.metric("S3 Buckets", f"{inv.s3_buckets} ({inv.s3_public} public)")
            st.metric("DynamoDB Tables", inv.dynamodb_tables)
        
        with col3:
            st.metric("VPCs", inv.vpcs)
            st.metric("Load Balancers", inv.load_balancers)
            st.metric("EBS Volumes", f"{inv.ebs_volumes} ({inv.ebs_unattached} unattached)")
        
        with col4:
            st.metric("IAM Users", f"{inv.iam_users} ({inv.iam_users_no_mfa} no MFA)")
            st.metric("IAM Roles", inv.iam_roles)


# Export
__all__ = [
    'AWSLandscapeScanner',
    'LandscapeAssessment',
    'Finding',
    'WAFPillar',
    'render_one_touch_scanner'
]
