"""
Multi-Account Well-Architected Review Scanner
Comprehensive WAR analysis across AWS Organization

Features:
- Multi-account resource scanning
- Automated WAF pillar assessment
- Cross-account security analysis
- Cost optimization across accounts
- Compliance consolidation
- AI-powered recommendations
"""

import streamlit as st
import anthropic
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import concurrent.futures

# Import connector
try:
    from .aws_connector import (
        AWSOrganizationConnector,
        AWSSessionManager,
        AWS_REGIONS
    )
    AWS_CONNECTOR_AVAILABLE = True
except ImportError:
    try:
        from modules.aws_connector import (
            AWSOrganizationConnector,
            AWSSessionManager,
            AWS_REGIONS
        )
        AWS_CONNECTOR_AVAILABLE = True
    except ImportError:
        AWS_CONNECTOR_AVAILABLE = False


# ============================================================================
# WAR ASSESSMENT CATEGORIES
# ============================================================================

WAR_ASSESSMENT_AREAS = {
    "security": {
        "name": "Security Posture",
        "icon": "🔒",
        "checks": [
            "IAM Configuration",
            "Encryption at Rest",
            "Encryption in Transit", 
            "Network Security",
            "Logging & Monitoring",
            "Incident Response",
            "Data Protection"
        ]
    },
    "reliability": {
        "name": "Reliability & Resilience",
        "icon": "🛡️",
        "checks": [
            "Multi-AZ Deployments",
            "Backup & Recovery",
            "Auto Scaling",
            "Health Checks",
            "Disaster Recovery",
            "Change Management"
        ]
    },
    "performance": {
        "name": "Performance Efficiency",
        "icon": "⚡",
        "checks": [
            "Right-Sizing",
            "Caching Strategy",
            "Database Optimization",
            "CDN Usage",
            "Compute Selection",
            "Storage Optimization"
        ]
    },
    "cost": {
        "name": "Cost Optimization",
        "icon": "💰",
        "checks": [
            "Reserved Instances",
            "Savings Plans",
            "Unused Resources",
            "Right-Sizing",
            "Storage Tiering",
            "Data Transfer"
        ]
    },
    "operations": {
        "name": "Operational Excellence",
        "icon": "⚙️",
        "checks": [
            "IaC Coverage",
            "CI/CD Pipelines",
            "Monitoring & Alerting",
            "Runbooks",
            "Tagging Strategy",
            "Documentation"
        ]
    },
    "sustainability": {
        "name": "Sustainability",
        "icon": "🌱",
        "checks": [
            "Region Selection",
            "Instance Efficiency",
            "Storage Lifecycle",
            "Resource Utilization",
            "Graviton Usage"
        ]
    }
}


def build_multi_account_war_prompt(landscape_data: Dict, selected_pillars: List[str] = None) -> str:
    """Build comprehensive WAR analysis prompt from landscape data"""
    
    pillars = selected_pillars or list(WAR_ASSESSMENT_AREAS.keys())
    
    pillar_descriptions = "\n".join([
        f"- **{WAR_ASSESSMENT_AREAS[p]['name']}**: {', '.join(WAR_ASSESSMENT_AREAS[p]['checks'])}"
        for p in pillars if p in WAR_ASSESSMENT_AREAS
    ])
    
    prompt = f"""You are a senior AWS Solutions Architect performing a comprehensive Well-Architected Review 
across an AWS Organization with multiple accounts.

## AWS Organization Landscape Data:
{json.dumps(landscape_data, indent=2, default=str)}

## Assessment Focus Areas:
{pillar_descriptions}

## Provide a comprehensive Well-Architected Review in the following JSON structure:

```json
{{
    "executive_summary": {{
        "overall_score": <0-100>,
        "risk_level": "<Critical|High|Medium|Low>",
        "summary": "<2-3 sentence executive summary>",
        "key_strengths": ["<strength1>", "<strength2>"],
        "critical_gaps": ["<gap1>", "<gap2>"],
        "immediate_actions": ["<action1>", "<action2>"]
    }},
    "organization_assessment": {{
        "total_accounts_reviewed": <number>,
        "accounts_at_risk": <number>,
        "highest_risk_accounts": [
            {{
                "account_id": "<id>",
                "account_name": "<n>",
                "risk_score": <0-100>,
                "primary_concerns": ["<concern1>", "<concern2>"]
            }}
        ],
        "organization_wide_issues": ["<issue1>", "<issue2>"]
    }},
    "pillar_assessments": [
        {{
            "pillar": "<pillar_name>",
            "score": <0-100>,
            "status": "<Excellent|Good|Needs Improvement|Critical>",
            "findings": [
                {{
                    "finding_id": "<unique_id>",
                    "title": "<finding title>",
                    "severity": "<Critical|High|Medium|Low|Info>",
                    "description": "<detailed description>",
                    "affected_accounts": ["<account_id1>", "<account_id2>"],
                    "affected_resources": ["<resource1>", "<resource2>"],
                    "business_impact": "<impact description>",
                    "recommendation": "<specific recommendation>",
                    "implementation_steps": ["<step1>", "<step2>"],
                    "aws_services": ["<service1>", "<service2>"],
                    "effort": "<Low|Medium|High>",
                    "estimated_cost_impact": "<cost impact>",
                    "compliance_frameworks": ["<framework1>", "<framework2>"]
                }}
            ],
            "quick_wins": ["<quick_win1>", "<quick_win2>"],
            "long_term_improvements": ["<improvement1>", "<improvement2>"]
        }}
    ],
    "cross_account_analysis": {{
        "shared_vulnerabilities": [
            {{
                "vulnerability": "<description>",
                "affected_accounts": ["<account1>", "<account2>"],
                "remediation": "<fix>"
            }}
        ],
        "inconsistent_configurations": [
            {{
                "configuration": "<what>",
                "variance": "<description>",
                "recommendation": "<standardization approach>"
            }}
        ],
        "governance_gaps": ["<gap1>", "<gap2>"]
    }},
    "cost_optimization_opportunities": {{
        "total_monthly_savings_potential": <number>,
        "by_category": [
            {{
                "category": "<category>",
                "current_spend": <number>,
                "potential_savings": <number>,
                "recommendations": ["<rec1>", "<rec2>"]
            }}
        ],
        "top_opportunities": [
            {{
                "opportunity": "<description>",
                "accounts_affected": ["<account1>"],
                "monthly_savings": <number>,
                "implementation_effort": "<Low|Medium|High>"
            }}
        ]
    }},
    "security_posture": {{
        "overall_security_score": <0-100>,
        "critical_security_findings": [
            {{
                "finding": "<description>",
                "severity": "<Critical|High>",
                "accounts_affected": ["<account1>"],
                "immediate_action": "<action>"
            }}
        ],
        "compliance_status": {{
            "frameworks_assessed": ["<framework1>", "<framework2>"],
            "overall_compliance": <percentage>,
            "gaps_by_framework": {{
                "<framework>": ["<gap1>", "<gap2>"]
            }}
        }}
    }},
    "remediation_roadmap": {{
        "immediate": {{
            "timeframe": "0-30 days",
            "actions": [
                {{
                    "action": "<action>",
                    "priority": <1-5>,
                    "accounts": ["<account1>"],
                    "owner": "<team/role>",
                    "effort_days": <number>
                }}
            ]
        }},
        "short_term": {{
            "timeframe": "30-90 days",
            "actions": [
                {{
                    "action": "<action>",
                    "priority": <1-5>,
                    "accounts": ["<account1>"],
                    "owner": "<team/role>",
                    "effort_days": <number>
                }}
            ]
        }},
        "medium_term": {{
            "timeframe": "90-180 days",
            "actions": [
                {{
                    "action": "<action>",
                    "priority": <1-5>,
                    "accounts": ["<account1>"],
                    "owner": "<team/role>",
                    "effort_days": <number>
                }}
            ]
        }},
        "long_term": {{
            "timeframe": "180+ days",
            "actions": [
                {{
                    "action": "<action>",
                    "priority": <1-5>,
                    "accounts": ["<account1>"],
                    "owner": "<team/role>",
                    "effort_days": <number>
                }}
            ]
        }}
    }},
    "architecture_recommendations": [
        {{
            "current_pattern": "<what exists>",
            "recommended_pattern": "<target state>",
            "benefits": ["<benefit1>", "<benefit2>"],
            "implementation_approach": "<how to implement>",
            "accounts_affected": ["<account1>"]
        }}
    ]
}}
```

Provide specific, actionable findings based on the actual resource inventory and configuration data.
Include account-specific recommendations where relevant.
Prioritize findings by business impact and implementation effort.
"""
    return prompt


def analyze_landscape_with_ai(client: anthropic.Anthropic, landscape_data: Dict,
                              selected_pillars: List[str] = None) -> Dict:
    """Analyze landscape data using Claude AI"""
    
    prompt = build_multi_account_war_prompt(landscape_data, selected_pillars)
    
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


def render_war_executive_summary(results: Dict):
    """Render WAR executive summary"""
    
    if "error" in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    summary = results.get('executive_summary', {})
    
    st.markdown("### 📊 Executive Summary")
    
    # Score and Risk
    col1, col2, col3, col4 = st.columns(4)
    
    score = summary.get('overall_score', 0)
    score_color = "#388E3C" if score >= 80 else "#FBC02D" if score >= 60 else "#D32F2F"
    
    with col1:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: white; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 3rem; font-weight: bold; color: {score_color};">{score}</div>
            <div style="color: #666;">Overall WAR Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        risk = summary.get('risk_level', 'Unknown')
        risk_colors = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        st.metric("Risk Level", f"{risk_colors.get(risk, '⚪')} {risk}")
    
    with col3:
        org = results.get('organization_assessment', {})
        st.metric("Accounts Reviewed", org.get('total_accounts_reviewed', 0))
    
    with col4:
        st.metric("Accounts at Risk", org.get('accounts_at_risk', 0))
    
    st.info(summary.get('summary', ''))
    
    # Key points
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**✅ Key Strengths:**")
        for strength in summary.get('key_strengths', []):
            st.markdown(f"- {strength}")
    
    with col2:
        st.markdown("**⚠️ Critical Gaps:**")
        for gap in summary.get('critical_gaps', []):
            st.markdown(f"- {gap}")
    
    if summary.get('immediate_actions'):
        st.markdown("**🚨 Immediate Actions Required:**")
        for action in summary['immediate_actions']:
            st.markdown(f"- 🔴 {action}")


def render_pillar_assessments(results: Dict):
    """Render pillar-by-pillar assessments"""
    
    st.markdown("### 📋 Pillar Assessments")
    
    for pillar in results.get('pillar_assessments', []):
        pillar_name = pillar.get('pillar', 'Unknown')
        score = pillar.get('score', 0)
        status = pillar.get('status', 'Unknown')
        
        status_icons = {
            "Excellent": "✅",
            "Good": "🟢",
            "Needs Improvement": "🟡",
            "Critical": "🔴"
        }
        
        with st.expander(f"{status_icons.get(status, '⚪')} {pillar_name} - Score: {score}/100 ({status})"):
            st.progress(score / 100)
            
            # Findings
            findings = pillar.get('findings', [])
            
            if findings:
                st.markdown("**Findings:**")
                
                for finding in findings:
                    severity = finding.get('severity', 'Medium')
                    severity_color = {
                        'Critical': '🔴',
                        'High': '🟠', 
                        'Medium': '🟡',
                        'Low': '🟢',
                        'Info': 'ℹ️'
                    }.get(severity, '⚪')
                    
                    with st.expander(f"{severity_color} {finding.get('title', 'Finding')}"):
                        st.markdown(f"**Description:** {finding.get('description', '')}")
                        st.markdown(f"**Business Impact:** {finding.get('business_impact', 'N/A')}")
                        st.markdown(f"**Recommendation:** {finding.get('recommendation', 'N/A')}")
                        
                        if finding.get('affected_accounts'):
                            st.markdown(f"**Affected Accounts:** {', '.join(finding['affected_accounts'])}")
                        
                        if finding.get('implementation_steps'):
                            st.markdown("**Implementation Steps:**")
                            for step in finding['implementation_steps']:
                                st.markdown(f"- {step}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"**Effort:** {finding.get('effort', 'N/A')}")
                        with col2:
                            st.markdown(f"**AWS Services:** {', '.join(finding.get('aws_services', []))}")
            
            # Quick wins
            if pillar.get('quick_wins'):
                st.markdown("**💡 Quick Wins:**")
                for win in pillar['quick_wins']:
                    st.markdown(f"- ✨ {win}")


def render_cost_optimization(results: Dict):
    """Render cost optimization section"""
    
    cost_data = results.get('cost_optimization_opportunities', {})
    
    if not cost_data:
        return
    
    st.markdown("### 💰 Cost Optimization Opportunities")
    
    col1, col2 = st.columns(2)
    
    with col1:
        total_savings = cost_data.get('total_monthly_savings_potential', 0)
        st.metric("Monthly Savings Potential", f"${total_savings:,.0f}")
        st.metric("Annual Savings", f"${total_savings * 12:,.0f}")
    
    with col2:
        # Top opportunities
        st.markdown("**Top Opportunities:**")
        for opp in cost_data.get('top_opportunities', [])[:5]:
            st.markdown(f"- 💰 {opp.get('opportunity', '')} (${opp.get('monthly_savings', 0):,.0f}/mo)")


def render_remediation_roadmap(results: Dict):
    """Render remediation roadmap"""
    
    roadmap = results.get('remediation_roadmap', {})
    
    if not roadmap:
        return
    
    st.markdown("### 🗺️ Remediation Roadmap")
    
    phases = [
        ('immediate', 'Immediate (0-30 days)', '🚨'),
        ('short_term', 'Short-term (30-90 days)', '⚡'),
        ('medium_term', 'Medium-term (90-180 days)', '📅'),
        ('long_term', 'Long-term (180+ days)', '🎯')
    ]
    
    for phase_key, phase_name, phase_icon in phases:
        phase_data = roadmap.get(phase_key, {})
        actions = phase_data.get('actions', [])
        
        if actions:
            with st.expander(f"{phase_icon} {phase_name} ({len(actions)} actions)"):
                for action in sorted(actions, key=lambda x: x.get('priority', 999)):
                    st.markdown(f"""
                    **Priority {action.get('priority', 'N/A')}:** {action.get('action', '')}
                    - Accounts: {', '.join(action.get('accounts', ['All']))}
                    - Owner: {action.get('owner', 'TBD')}
                    - Effort: {action.get('effort_days', 'N/A')} days
                    """)


def render_multi_account_war_scanner(client: Optional[anthropic.Anthropic]):
    """Main renderer for multi-account WAR scanner"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #FF9900 0%, #FFB84D 100%); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #232F3E; margin: 0;">🔍 Multi-Account Well-Architected Review</h2>
        <p style="color: #37475A; margin: 0.5rem 0 0 0;">Comprehensive WAR Analysis Across Your AWS Organization</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if "war_results" not in st.session_state:
        st.session_state.war_results = None
    
    # Check for AWS connection
    if not st.session_state.get('aws_connected'):
        st.warning("⚠️ Connect to AWS Organization first using the AWS Connector tab")
        
        # Allow manual data input as fallback
        st.markdown("---")
        st.markdown("### 📥 Or Upload Landscape Data")
        
        uploaded = st.file_uploader("Upload AWS landscape JSON", type=['json'])
        if uploaded:
            try:
                landscape_data = json.load(uploaded)
                st.session_state.aws_landscape = landscape_data
                st.success("✅ Landscape data loaded!")
            except Exception as e:
                st.error(f"Failed to parse file: {e}")
    
    # Show analysis options if we have data
    if st.session_state.get('aws_landscape'):
        landscape = st.session_state.aws_landscape
        
        st.markdown("### ⚙️ Analysis Configuration")
        
        # Pillar selection
        st.markdown("**Select WAF Pillars to Assess:**")
        
        cols = st.columns(3)
        selected_pillars = []
        
        for idx, (pillar_key, pillar) in enumerate(WAR_ASSESSMENT_AREAS.items()):
            with cols[idx % 3]:
                if st.checkbox(f"{pillar['icon']} {pillar['name']}", value=True, key=f"pillar_{pillar_key}"):
                    selected_pillars.append(pillar_key)
        
        st.markdown("---")
        
        # Show data summary
        st.markdown("### 📊 Data Summary")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            accounts = landscape.get('accounts', [])
            st.metric("Accounts in Scope", len(accounts))
        
        with col2:
            costs = landscape.get('costs', {})
            if costs and 'error' not in costs:
                st.metric("Total Monthly Cost", f"${costs.get('total_cost', 0):,.0f}")
            else:
                st.metric("Cost Data", "Not Available")
        
        with col3:
            security = landscape.get('security', {})
            if security and 'error' not in security:
                st.metric("Security Findings", security.get('total_findings', 0))
            else:
                st.metric("Security Data", "Not Available")
        
        # Run Analysis
        st.markdown("---")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            analyze_btn = st.button(
                "🔍 Run Well-Architected Review",
                type="primary",
                use_container_width=True,
                disabled=not (client and selected_pillars)
            )
        
        if analyze_btn:
            with st.spinner("🤖 AI analyzing your AWS landscape... This may take a few minutes."):
                results = analyze_landscape_with_ai(client, landscape, selected_pillars)
                
                if "error" not in results:
                    st.session_state.war_results = results
                    st.success("✅ Analysis complete!")
                else:
                    st.error(f"Analysis failed: {results['error']}")
        
        # Show results
        if st.session_state.war_results:
            results = st.session_state.war_results
            
            # Create result tabs
            result_tabs = st.tabs([
                "📊 Executive Summary",
                "📋 Pillar Details",
                "💰 Cost Optimization",
                "🗺️ Roadmap",
                "📥 Export"
            ])
            
            with result_tabs[0]:
                render_war_executive_summary(results)
            
            with result_tabs[1]:
                render_pillar_assessments(results)
            
            with result_tabs[2]:
                render_cost_optimization(results)
            
            with result_tabs[3]:
                render_remediation_roadmap(results)
            
            with result_tabs[4]:
                st.markdown("### 📥 Export WAR Results")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        "📄 Download JSON Report",
                        json.dumps(results, indent=2, default=str),
                        file_name=f"war_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                
                with col2:
                    # Generate markdown report
                    md_report = generate_war_markdown_report(results)
                    st.download_button(
                        "📝 Download Markdown Report",
                        md_report,
                        file_name=f"war_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )
    else:
        st.info("👆 Connect to AWS or upload landscape data to begin WAR analysis")


def generate_war_markdown_report(results: Dict) -> str:
    """Generate a markdown report from WAR results"""
    
    summary = results.get('executive_summary', {})
    
    report = f"""# AWS Well-Architected Review Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

**Overall Score:** {summary.get('overall_score', 'N/A')}/100
**Risk Level:** {summary.get('risk_level', 'N/A')}

{summary.get('summary', '')}

### Key Strengths
"""
    
    for strength in summary.get('key_strengths', []):
        report += f"- ✅ {strength}\n"
    
    report += "\n### Critical Gaps\n"
    
    for gap in summary.get('critical_gaps', []):
        report += f"- ⚠️ {gap}\n"
    
    report += "\n### Immediate Actions Required\n"
    
    for action in summary.get('immediate_actions', []):
        report += f"- 🚨 {action}\n"
    
    # Pillar assessments
    report += "\n## Pillar Assessments\n\n"
    
    for pillar in results.get('pillar_assessments', []):
        report += f"### {pillar.get('pillar', 'Unknown')} - Score: {pillar.get('score', 0)}/100\n\n"
        report += f"**Status:** {pillar.get('status', 'Unknown')}\n\n"
        
        for finding in pillar.get('findings', []):
            report += f"""
#### {finding.get('title', 'Finding')}

- **Severity:** {finding.get('severity', 'N/A')}
- **Description:** {finding.get('description', '')}
- **Business Impact:** {finding.get('business_impact', '')}
- **Recommendation:** {finding.get('recommendation', '')}
- **Effort:** {finding.get('effort', 'N/A')}

"""
    
    return report


# Export
__all__ = [
    'render_multi_account_war_scanner',
    'analyze_landscape_with_ai',
    'WAR_ASSESSMENT_AREAS'
]
