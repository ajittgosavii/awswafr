"""
Enterprise Compliance & Governance Module
Multi-framework compliance assessment, policy management, and audit preparation

Features:
- Multi-Framework Compliance (SOC2, HIPAA, PCI-DSS, GDPR, ISO27001, NIST, FedRAMP)
- Automated Compliance Scoring
- Policy-as-Code Management
- Audit Trail & Evidence Collection
- Control Mapping & Gap Analysis
- Remediation Tracking
- Compliance Dashboard & Reporting
- AWS Config Rules Integration
- Security Hub Integration
"""

import streamlit as st
import anthropic
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# ============================================================================
# COMPLIANCE FRAMEWORKS
# ============================================================================

COMPLIANCE_FRAMEWORKS = {
    "soc2": {
        "name": "SOC 2 Type II",
        "icon": "🔒",
        "description": "Service Organization Control 2",
        "trust_service_criteria": [
            "Security", "Availability", "Processing Integrity",
            "Confidentiality", "Privacy"
        ],
        "control_count": 64,
        "audit_frequency": "Annual",
        "relevance": ["SaaS", "Cloud Services", "Data Processing"]
    },
    "hipaa": {
        "name": "HIPAA",
        "icon": "🏥",
        "description": "Health Insurance Portability and Accountability Act",
        "categories": [
            "Administrative Safeguards", "Physical Safeguards",
            "Technical Safeguards", "Organizational Requirements"
        ],
        "control_count": 54,
        "audit_frequency": "Annual",
        "relevance": ["Healthcare", "Health Data", "Insurance"]
    },
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "icon": "💳",
        "description": "Payment Card Industry Data Security Standard",
        "requirements": [
            "Build and Maintain a Secure Network",
            "Protect Cardholder Data",
            "Maintain a Vulnerability Management Program",
            "Implement Strong Access Control",
            "Monitor and Test Networks",
            "Maintain Information Security Policy"
        ],
        "control_count": 78,
        "audit_frequency": "Quarterly/Annual",
        "relevance": ["E-commerce", "Payment Processing", "Financial"]
    },
    "gdpr": {
        "name": "GDPR",
        "icon": "🇪🇺",
        "description": "General Data Protection Regulation",
        "principles": [
            "Lawfulness", "Purpose Limitation", "Data Minimization",
            "Accuracy", "Storage Limitation", "Integrity & Confidentiality",
            "Accountability"
        ],
        "control_count": 45,
        "audit_frequency": "Continuous",
        "relevance": ["EU Citizens Data", "International Business"]
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "icon": "📋",
        "description": "Information Security Management System",
        "domains": [
            "Organizational Controls", "People Controls",
            "Physical Controls", "Technological Controls"
        ],
        "control_count": 93,
        "audit_frequency": "Annual",
        "relevance": ["Enterprise", "International", "B2B"]
    },
    "nist_csf": {
        "name": "NIST CSF 2.0",
        "icon": "🏛️",
        "description": "Cybersecurity Framework",
        "functions": [
            "Govern", "Identify", "Protect", "Detect", "Respond", "Recover"
        ],
        "control_count": 108,
        "audit_frequency": "Continuous",
        "relevance": ["Critical Infrastructure", "Government", "Enterprise"]
    },
    "fedramp": {
        "name": "FedRAMP",
        "icon": "🇺🇸",
        "description": "Federal Risk and Authorization Management Program",
        "impact_levels": ["Low", "Moderate", "High"],
        "control_count": 325,
        "audit_frequency": "Annual + Continuous",
        "relevance": ["Federal Government", "Government Contractors"]
    },
    "cis": {
        "name": "CIS Benchmarks",
        "icon": "📊",
        "description": "Center for Internet Security Benchmarks",
        "categories": [
            "Identity & Access", "Logging & Monitoring",
            "Networking", "Storage", "Compute"
        ],
        "control_count": 85,
        "audit_frequency": "Continuous",
        "relevance": ["All Industries", "Security Baseline"]
    }
}

# AWS Control Mapping
AWS_COMPLIANCE_CONTROLS = {
    "identity": {
        "name": "Identity & Access Management",
        "controls": [
            {"id": "IAM-001", "name": "MFA for Root Account", "services": ["IAM"], "frameworks": ["soc2", "pci_dss", "hipaa", "nist_csf"]},
            {"id": "IAM-002", "name": "MFA for All Users", "services": ["IAM"], "frameworks": ["soc2", "pci_dss", "hipaa", "nist_csf"]},
            {"id": "IAM-003", "name": "Password Policy Enforcement", "services": ["IAM"], "frameworks": ["soc2", "pci_dss", "nist_csf"]},
            {"id": "IAM-004", "name": "Principle of Least Privilege", "services": ["IAM"], "frameworks": ["soc2", "hipaa", "pci_dss", "iso27001"]},
            {"id": "IAM-005", "name": "Access Key Rotation", "services": ["IAM"], "frameworks": ["soc2", "pci_dss", "nist_csf"]},
            {"id": "IAM-006", "name": "SSO Integration", "services": ["IAM Identity Center"], "frameworks": ["soc2", "iso27001"]}
        ]
    },
    "encryption": {
        "name": "Data Encryption",
        "controls": [
            {"id": "ENC-001", "name": "S3 Encryption at Rest", "services": ["S3", "KMS"], "frameworks": ["soc2", "hipaa", "pci_dss", "gdpr"]},
            {"id": "ENC-002", "name": "EBS Encryption", "services": ["EC2", "KMS"], "frameworks": ["soc2", "hipaa", "pci_dss"]},
            {"id": "ENC-003", "name": "RDS Encryption", "services": ["RDS", "KMS"], "frameworks": ["soc2", "hipaa", "pci_dss", "gdpr"]},
            {"id": "ENC-004", "name": "Encryption in Transit (TLS)", "services": ["ACM", "CloudFront"], "frameworks": ["soc2", "hipaa", "pci_dss"]},
            {"id": "ENC-005", "name": "KMS Key Management", "services": ["KMS"], "frameworks": ["soc2", "pci_dss", "iso27001"]}
        ]
    },
    "logging": {
        "name": "Logging & Monitoring",
        "controls": [
            {"id": "LOG-001", "name": "CloudTrail Enabled", "services": ["CloudTrail"], "frameworks": ["soc2", "hipaa", "pci_dss", "iso27001", "nist_csf"]},
            {"id": "LOG-002", "name": "CloudTrail Log Integrity", "services": ["CloudTrail"], "frameworks": ["soc2", "pci_dss"]},
            {"id": "LOG-003", "name": "VPC Flow Logs", "services": ["VPC"], "frameworks": ["soc2", "pci_dss", "nist_csf"]},
            {"id": "LOG-004", "name": "CloudWatch Alarms", "services": ["CloudWatch"], "frameworks": ["soc2", "nist_csf"]},
            {"id": "LOG-005", "name": "GuardDuty Enabled", "services": ["GuardDuty"], "frameworks": ["soc2", "nist_csf"]},
            {"id": "LOG-006", "name": "Security Hub Enabled", "services": ["Security Hub"], "frameworks": ["soc2", "nist_csf", "cis"]}
        ]
    },
    "network": {
        "name": "Network Security",
        "controls": [
            {"id": "NET-001", "name": "Security Groups - No Open Ingress", "services": ["VPC"], "frameworks": ["soc2", "pci_dss", "cis"]},
            {"id": "NET-002", "name": "NACLs Configured", "services": ["VPC"], "frameworks": ["soc2", "pci_dss"]},
            {"id": "NET-003", "name": "WAF Protection", "services": ["WAF"], "frameworks": ["soc2", "pci_dss"]},
            {"id": "NET-004", "name": "DDoS Protection", "services": ["Shield"], "frameworks": ["soc2", "nist_csf"]},
            {"id": "NET-005", "name": "Private Subnets for Data", "services": ["VPC"], "frameworks": ["pci_dss", "hipaa"]}
        ]
    },
    "data_protection": {
        "name": "Data Protection",
        "controls": [
            {"id": "DAT-001", "name": "S3 Block Public Access", "services": ["S3"], "frameworks": ["soc2", "hipaa", "pci_dss", "gdpr"]},
            {"id": "DAT-002", "name": "S3 Versioning", "services": ["S3"], "frameworks": ["soc2", "iso27001"]},
            {"id": "DAT-003", "name": "Backup Policies", "services": ["Backup"], "frameworks": ["soc2", "hipaa", "iso27001"]},
            {"id": "DAT-004", "name": "Data Classification Tags", "services": ["Resource Groups"], "frameworks": ["gdpr", "hipaa", "iso27001"]},
            {"id": "DAT-005", "name": "Data Retention Policies", "services": ["S3", "RDS"], "frameworks": ["gdpr", "hipaa"]}
        ]
    },
    "incident_response": {
        "name": "Incident Response",
        "controls": [
            {"id": "INC-001", "name": "Incident Response Plan", "services": ["Documentation"], "frameworks": ["soc2", "hipaa", "pci_dss", "iso27001", "nist_csf"]},
            {"id": "INC-002", "name": "Automated Alerting", "services": ["CloudWatch", "SNS"], "frameworks": ["soc2", "nist_csf"]},
            {"id": "INC-003", "name": "Forensic Capabilities", "services": ["CloudTrail", "VPC Flow Logs"], "frameworks": ["pci_dss", "nist_csf"]},
            {"id": "INC-004", "name": "Communication Plan", "services": ["Documentation"], "frameworks": ["soc2", "gdpr"]}
        ]
    }
}


def build_compliance_analysis_prompt(environment_data: Dict, frameworks: List[str]) -> str:
    """Build the compliance analysis prompt"""
    
    framework_details = []
    for fw in frameworks:
        if fw in COMPLIANCE_FRAMEWORKS:
            framework_details.append(f"- {COMPLIANCE_FRAMEWORKS[fw]['name']}: {COMPLIANCE_FRAMEWORKS[fw]['description']}")
    
    prompt = f"""You are an expert cloud compliance auditor with deep knowledge of AWS security best practices and regulatory frameworks.

Analyze the following AWS environment against the specified compliance frameworks.

## Environment Data:
{json.dumps(environment_data, indent=2)}

## Target Frameworks:
{chr(10).join(framework_details)}

## Provide your analysis in the following JSON structure:

```json
{{
    "overall_compliance_score": <0-100>,
    "risk_rating": "<Critical|High|Medium|Low>",
    "executive_summary": "<2-3 sentence summary>",
    "framework_assessments": [
        {{
            "framework": "<framework_id>",
            "framework_name": "<full name>",
            "compliance_score": <0-100>,
            "status": "<Compliant|Partially Compliant|Non-Compliant>",
            "controls_assessed": <number>,
            "controls_compliant": <number>,
            "controls_non_compliant": <number>,
            "critical_gaps": ["<gap1>", "<gap2>"],
            "key_findings": ["<finding1>", "<finding2>"]
        }}
    ],
    "control_findings": [
        {{
            "control_id": "<id>",
            "control_name": "<name>",
            "category": "<category>",
            "status": "<Compliant|Non-Compliant|Partial>",
            "severity": "<Critical|High|Medium|Low>",
            "finding": "<detailed finding>",
            "affected_resources": ["<resource1>", "<resource2>"],
            "frameworks_impacted": ["<framework1>", "<framework2>"],
            "remediation": "<specific remediation steps>",
            "remediation_effort": "<Low|Medium|High>",
            "aws_config_rule": "<rule if applicable>",
            "evidence_required": ["<evidence1>", "<evidence2>"]
        }}
    ],
    "remediation_roadmap": [
        {{
            "priority": <1-5>,
            "phase": "<Immediate|Short-term|Medium-term|Long-term>",
            "actions": ["<action1>", "<action2>"],
            "controls_addressed": ["<control_id1>", "<control_id2>"],
            "estimated_effort_days": <number>,
            "responsible_team": "<team>",
            "dependencies": ["<dependency1>"]
        }}
    ],
    "audit_preparation": {{
        "readiness_score": <0-100>,
        "evidence_gaps": ["<gap1>", "<gap2>"],
        "documentation_needed": ["<doc1>", "<doc2>"],
        "recommended_timeline_weeks": <number>,
        "key_stakeholders": ["<stakeholder1>", "<stakeholder2>"]
    }},
    "aws_service_recommendations": [
        {{
            "service": "<AWS service>",
            "purpose": "<compliance purpose>",
            "implementation_priority": "<High|Medium|Low>",
            "cost_estimate": "<monthly cost>"
        }}
    ]
}}
```

Focus on specific, actionable findings with clear remediation steps.
Map findings to specific AWS services and Config rules where possible.
"""
    return prompt


def analyze_compliance_with_ai(client: anthropic.Anthropic, environment_data: Dict,
                               frameworks: List[str]) -> Dict:
    """Analyze compliance using Claude AI"""
    
    prompt = build_compliance_analysis_prompt(environment_data, frameworks)
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = response.content[0].text
        
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        return json.loads(response_text)
        
    except Exception as e:
        return {"error": str(e)}


def render_compliance_dashboard(results: Dict):
    """Render compliance assessment dashboard"""
    
    if "error" in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    # Overall Score
    score = results.get('overall_compliance_score', 0)
    risk = results.get('risk_rating', 'Unknown')
    
    st.markdown("### 📊 Compliance Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    score_color = "#388E3C" if score >= 80 else "#FBC02D" if score >= 60 else "#D32F2F"
    
    with col1:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: white; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 2.5rem; font-weight: bold; color: {score_color};">{score}</div>
            <div style="color: #666;">Compliance Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        risk_colors = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        st.metric("Risk Rating", f"{risk_colors.get(risk, '⚪')} {risk}")
    
    with col3:
        audit_ready = results.get('audit_preparation', {}).get('readiness_score', 0)
        st.metric("Audit Readiness", f"{audit_ready}%")
    
    with col4:
        frameworks_count = len(results.get('framework_assessments', []))
        st.metric("Frameworks Assessed", frameworks_count)
    
    st.info(results.get('executive_summary', ''))


def render_framework_details(results: Dict):
    """Render detailed framework assessments"""
    
    st.markdown("### 📋 Framework Assessments")
    
    for assessment in results.get('framework_assessments', []):
        fw_id = assessment.get('framework', '')
        fw_name = assessment.get('framework_name', fw_id)
        fw_score = assessment.get('compliance_score', 0)
        status = assessment.get('status', 'Unknown')
        
        status_icon = {"Compliant": "✅", "Partially Compliant": "⚠️", "Non-Compliant": "❌"}.get(status, "❓")
        
        with st.expander(f"{status_icon} {fw_name} - {fw_score}% Compliant"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Controls Assessed", assessment.get('controls_assessed', 0))
            with col2:
                st.metric("Compliant", assessment.get('controls_compliant', 0))
            with col3:
                st.metric("Non-Compliant", assessment.get('controls_non_compliant', 0))
            
            st.progress(fw_score / 100)
            
            if assessment.get('critical_gaps'):
                st.markdown("**Critical Gaps:**")
                for gap in assessment['critical_gaps']:
                    st.markdown(f"- 🚨 {gap}")
            
            if assessment.get('key_findings'):
                st.markdown("**Key Findings:**")
                for finding in assessment['key_findings']:
                    st.markdown(f"- 📌 {finding}")


def render_control_findings(results: Dict):
    """Render detailed control findings"""
    
    st.markdown("### 🔍 Control Findings")
    
    findings = results.get('control_findings', [])
    
    # Group by severity
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        severity_findings = [f for f in findings if f.get('severity') == severity]
        
        if severity_findings:
            severity_icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
            
            with st.expander(f"{severity_icon} {severity} ({len(severity_findings)})", expanded=(severity in ['Critical', 'High'])):
                for finding in severity_findings:
                    st.markdown(f"""
                    <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 0.5rem 0; border-left: 4px solid {'#D32F2F' if severity == 'Critical' else '#F57C00' if severity == 'High' else '#FBC02D' if severity == 'Medium' else '#388E3C'};">
                        <strong>{finding.get('control_id', '')} - {finding.get('control_name', '')}</strong><br>
                        <small>Category: {finding.get('category', 'N/A')} | Status: {finding.get('status', 'N/A')}</small>
                        <p>{finding.get('finding', '')}</p>
                        <p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>
                        <small>Effort: {finding.get('remediation_effort', 'N/A')} | Frameworks: {', '.join(finding.get('frameworks_impacted', []))}</small>
                    </div>
                    """, unsafe_allow_html=True)


def render_remediation_roadmap(results: Dict):
    """Render remediation roadmap"""
    
    st.markdown("### 🗺️ Remediation Roadmap")
    
    roadmap = results.get('remediation_roadmap', [])
    
    for item in sorted(roadmap, key=lambda x: x.get('priority', 999)):
        priority = item.get('priority', 0)
        phase = item.get('phase', 'Unknown')
        
        phase_colors = {
            'Immediate': '#D32F2F',
            'Short-term': '#F57C00',
            'Medium-term': '#FBC02D',
            'Long-term': '#388E3C'
        }
        
        with st.expander(f"Priority {priority}: {phase} ({item.get('estimated_effort_days', 0)} days)"):
            st.markdown("**Actions:**")
            for action in item.get('actions', []):
                st.markdown(f"- 📌 {action}")
            
            st.markdown(f"**Controls Addressed:** {', '.join(item.get('controls_addressed', []))}")
            st.markdown(f"**Responsible Team:** {item.get('responsible_team', 'TBD')}")
            
            if item.get('dependencies'):
                st.markdown(f"**Dependencies:** {', '.join(item['dependencies'])}")


def render_compliance_module(client: Optional[anthropic.Anthropic]):
    """Main renderer for the Compliance & Governance module"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1565C0 0%, #1976D2 100%); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: white; margin: 0;">📋 Compliance & Governance Center</h2>
        <p style="color: #90CAF9; margin: 0.5rem 0 0 0;">Multi-Framework Compliance Assessment & Audit Preparation</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if "compliance_results" not in st.session_state:
        st.session_state.compliance_results = None
    
    # Create tabs
    tabs = st.tabs([
        "📊 Assessment",
        "📋 Framework Details",
        "🔍 Control Findings",
        "🗺️ Remediation",
        "📚 Framework Reference"
    ])
    
    # Tab 1: Assessment
    with tabs[0]:
        st.markdown("### 🎯 Compliance Assessment")
        
        # Framework Selection
        st.markdown("**Select Compliance Frameworks:**")
        
        selected_frameworks = []
        cols = st.columns(4)
        
        for idx, (fw_id, fw) in enumerate(COMPLIANCE_FRAMEWORKS.items()):
            with cols[idx % 4]:
                if st.checkbox(f"{fw['icon']} {fw['name']}", key=f"fw_{fw_id}"):
                    selected_frameworks.append(fw_id)
        
        st.markdown("---")
        
        # Environment Input
        st.markdown("### 📝 Environment Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            env_name = st.text_input("Environment Name", value="Production AWS")
            account_count = st.number_input("AWS Account Count", value=5)
            regions = st.multiselect(
                "Active Regions",
                ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
                default=["us-east-1", "us-west-2"]
            )
        
        with col2:
            mfa_enabled = st.selectbox("MFA Status", ["All Users", "Partial", "Root Only"])
            encryption_status = st.selectbox("Encryption at Rest", ["All Services", "Partial", "Limited"])
            logging_status = st.selectbox("CloudTrail Status", ["All Regions", "Partial", "Disabled"])
        
        # Build environment data
        environment_data = {
            "name": env_name,
            "account_count": account_count,
            "regions": regions,
            "security_posture": {
                "mfa_status": mfa_enabled,
                "encryption_at_rest": encryption_status,
                "cloudtrail_status": logging_status,
                "guardduty_enabled": st.checkbox("GuardDuty Enabled", value=True),
                "security_hub_enabled": st.checkbox("Security Hub Enabled", value=True),
                "config_enabled": st.checkbox("AWS Config Enabled", value=True),
                "waf_enabled": st.checkbox("WAF Enabled", value=True)
            },
            "data_classification": {
                "pii_processed": st.checkbox("Processes PII", value=True),
                "phi_processed": st.checkbox("Processes PHI (Health)", value=False),
                "payment_data": st.checkbox("Processes Payment Data", value=False)
            }
        }
        
        # Analyze Button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            analyze_btn = st.button(
                "🔍 Run Compliance Assessment",
                type="primary",
                use_container_width=True,
                disabled=not (selected_frameworks and client)
            )
        
        if analyze_btn and selected_frameworks and client:
            with st.spinner("🔍 Analyzing compliance posture..."):
                results = analyze_compliance_with_ai(client, environment_data, selected_frameworks)
                if "error" not in results:
                    st.session_state.compliance_results = results
                    st.success("✅ Assessment complete!")
                else:
                    st.error(f"Assessment failed: {results['error']}")
        
        # Show results
        if st.session_state.compliance_results:
            render_compliance_dashboard(st.session_state.compliance_results)
    
    # Tab 2: Framework Details
    with tabs[1]:
        if st.session_state.compliance_results:
            render_framework_details(st.session_state.compliance_results)
        else:
            st.info("👆 Run an assessment first to see framework details")
    
    # Tab 3: Control Findings
    with tabs[2]:
        if st.session_state.compliance_results:
            render_control_findings(st.session_state.compliance_results)
        else:
            st.info("👆 Run an assessment first to see control findings")
    
    # Tab 4: Remediation
    with tabs[3]:
        if st.session_state.compliance_results:
            render_remediation_roadmap(st.session_state.compliance_results)
        else:
            st.info("👆 Run an assessment first to see remediation roadmap")
    
    # Tab 5: Framework Reference
    with tabs[4]:
        st.markdown("### 📚 Compliance Framework Reference")
        
        for fw_id, fw in COMPLIANCE_FRAMEWORKS.items():
            with st.expander(f"{fw['icon']} {fw['name']}"):
                st.markdown(f"**Description:** {fw['description']}")
                st.markdown(f"**Control Count:** {fw['control_count']}")
                st.markdown(f"**Audit Frequency:** {fw['audit_frequency']}")
                st.markdown(f"**Relevance:** {', '.join(fw['relevance'])}")


# Export
__all__ = ['render_compliance_module', 'COMPLIANCE_FRAMEWORKS', 'AWS_COMPLIANCE_CONTROLS']
