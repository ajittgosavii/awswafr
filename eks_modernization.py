"""
EKS Modernization & CI/CD Enhancement Planner Module
Provides design and implementation planning for Kubernetes tooling
"""

import streamlit as st
import anthropic
import json
from datetime import datetime
from typing import Dict, List, Optional

# EKS Modernization Categories
EKS_TOOLS_CATALOG = {
    "autoscaling": {
        "name": "Autoscaling & Node Management",
        "icon": "📈",
        "tools": {
            "karpenter": {
                "name": "Karpenter",
                "description": "Just-in-time node provisioning for Kubernetes",
                "complexity": "Medium",
                "implementation_days": "5-10",
                "prerequisites": ["EKS 1.21+", "IAM OIDC Provider", "AWS Load Balancer Controller"],
                "benefits": ["Cost optimization", "Faster scaling", "Right-sized nodes", "Spot instance support"],
                "considerations": ["Migration from Cluster Autoscaler", "NodePool configuration", "Consolidation policies"]
            },
            "cluster_autoscaler": {
                "name": "Cluster Autoscaler",
                "description": "Traditional Kubernetes node autoscaling",
                "complexity": "Low",
                "implementation_days": "2-3",
                "prerequisites": ["EKS cluster", "IAM permissions"],
                "benefits": ["Mature solution", "Simple setup", "Wide adoption"],
                "considerations": ["Slower than Karpenter", "ASG-based scaling"]
            },
            "keda": {
                "name": "KEDA",
                "description": "Kubernetes Event-driven Autoscaling",
                "complexity": "Medium",
                "implementation_days": "3-5",
                "prerequisites": ["Metrics server", "Event sources configured"],
                "benefits": ["Event-driven scaling", "Scale to zero", "Multiple scalers"],
                "considerations": ["Scaler configuration", "Integration with existing HPA"]
            }
        }
    },
    "gitops": {
        "name": "GitOps & Continuous Delivery",
        "icon": "🔄",
        "tools": {
            "argocd": {
                "name": "ArgoCD",
                "description": "Declarative GitOps continuous delivery for Kubernetes",
                "complexity": "Medium",
                "implementation_days": "5-7",
                "prerequisites": ["Git repository", "Kubernetes manifests or Helm charts"],
                "benefits": ["Visual UI", "Multi-cluster support", "SSO integration", "Sync policies"],
                "considerations": ["RBAC setup", "Secret management", "Application structure"]
            },
            "fluxcd": {
                "name": "Flux CD",
                "description": "GitOps toolkit for Kubernetes",
                "complexity": "Medium",
                "implementation_days": "4-6",
                "prerequisites": ["Git repository", "CLI access"],
                "benefits": ["CNCF graduated", "Lightweight", "Helm controller", "Image automation"],
                "considerations": ["CLI-focused", "Less visual than ArgoCD"]
            },
            "crossplane": {
                "name": "Crossplane",
                "description": "Cloud-native control plane for infrastructure",
                "complexity": "High",
                "implementation_days": "10-15",
                "prerequisites": ["Kubernetes cluster", "Provider credentials"],
                "benefits": ["Infrastructure as Code in K8s", "Multi-cloud", "Compositions"],
                "considerations": ["Learning curve", "Provider maturity varies"]
            }
        }
    },
    "cicd": {
        "name": "CI/CD Pipeline Enhancement",
        "icon": "🚀",
        "tools": {
            "tekton": {
                "name": "Tekton Pipelines",
                "description": "Cloud-native CI/CD pipelines for Kubernetes",
                "complexity": "High",
                "implementation_days": "7-14",
                "prerequisites": ["Kubernetes cluster", "Persistent storage"],
                "benefits": ["Kubernetes-native", "Reusable tasks", "Triggers support"],
                "considerations": ["Steeper learning curve", "YAML heavy"]
            },
            "github_actions_arc": {
                "name": "GitHub Actions + ARC",
                "description": "Self-hosted runners on Kubernetes with Actions Runner Controller",
                "complexity": "Medium",
                "implementation_days": "3-5",
                "prerequisites": ["GitHub repository", "EKS cluster"],
                "benefits": ["Native GitHub integration", "Auto-scaling runners", "Cost control"],
                "considerations": ["Runner management", "Security configurations"]
            },
            "jenkins_kubernetes": {
                "name": "Jenkins on Kubernetes",
                "description": "Jenkins with Kubernetes plugin for dynamic agents",
                "complexity": "Medium",
                "implementation_days": "5-7",
                "prerequisites": ["Persistent storage", "Jenkins experience"],
                "benefits": ["Mature ecosystem", "Plugin rich", "Dynamic agents"],
                "considerations": ["Resource intensive", "Maintenance overhead"]
            },
            "aws_codepipeline": {
                "name": "AWS CodePipeline + CodeBuild",
                "description": "AWS-native CI/CD with EKS deployment",
                "complexity": "Low-Medium",
                "implementation_days": "3-5",
                "prerequisites": ["AWS account", "CodeCommit/GitHub connection"],
                "benefits": ["AWS integrated", "Managed service", "IAM integration"],
                "considerations": ["AWS lock-in", "Limited customization"]
            }
        }
    },
    "service_mesh": {
        "name": "Service Mesh",
        "icon": "🕸️",
        "tools": {
            "istio": {
                "name": "Istio",
                "description": "Full-featured service mesh with traffic management",
                "complexity": "High",
                "implementation_days": "10-20",
                "prerequisites": ["EKS cluster", "Sufficient resources"],
                "benefits": ["Traffic management", "Security (mTLS)", "Observability", "Policy enforcement"],
                "considerations": ["Resource overhead", "Complexity", "Learning curve"]
            },
            "linkerd": {
                "name": "Linkerd",
                "description": "Lightweight, security-focused service mesh",
                "complexity": "Medium",
                "implementation_days": "5-7",
                "prerequisites": ["EKS cluster"],
                "benefits": ["Lightweight", "Easy setup", "mTLS by default", "Low overhead"],
                "considerations": ["Fewer features than Istio", "Less traffic control"]
            },
            "aws_app_mesh": {
                "name": "AWS App Mesh",
                "description": "AWS-managed service mesh using Envoy",
                "complexity": "Medium",
                "implementation_days": "5-10",
                "prerequisites": ["EKS cluster", "AWS account"],
                "benefits": ["AWS managed", "Envoy-based", "AWS integration"],
                "considerations": ["AWS specific", "Feature limitations"]
            }
        }
    },
    "observability": {
        "name": "Observability Stack",
        "icon": "📊",
        "tools": {
            "prometheus_grafana": {
                "name": "Prometheus + Grafana Stack",
                "description": "Industry-standard metrics and visualization",
                "complexity": "Medium",
                "implementation_days": "5-7",
                "prerequisites": ["Persistent storage", "Resource allocation"],
                "benefits": ["Industry standard", "Rich ecosystem", "Alertmanager", "Custom dashboards"],
                "considerations": ["Storage management", "High availability setup"]
            },
            "amazon_managed_prometheus": {
                "name": "Amazon Managed Prometheus (AMP)",
                "description": "AWS-managed Prometheus-compatible monitoring",
                "complexity": "Low-Medium",
                "implementation_days": "2-4",
                "prerequisites": ["EKS cluster", "AWS account"],
                "benefits": ["Managed service", "Auto-scaling", "AWS integration"],
                "considerations": ["Cost at scale", "Limited customization"]
            },
            "opentelemetry": {
                "name": "OpenTelemetry",
                "description": "Unified observability framework",
                "complexity": "Medium-High",
                "implementation_days": "7-14",
                "prerequisites": ["Backend storage", "Application instrumentation"],
                "benefits": ["Vendor neutral", "Traces/metrics/logs", "Auto-instrumentation"],
                "considerations": ["Implementation complexity", "Backend choice"]
            },
            "datadog": {
                "name": "Datadog",
                "description": "Full-stack observability platform",
                "complexity": "Low",
                "implementation_days": "2-3",
                "prerequisites": ["Datadog account", "API key"],
                "benefits": ["All-in-one", "Easy setup", "APM included", "Log management"],
                "considerations": ["Cost", "Vendor lock-in"]
            },
            "aws_cloudwatch_container_insights": {
                "name": "CloudWatch Container Insights",
                "description": "AWS-native container monitoring",
                "complexity": "Low",
                "implementation_days": "1-2",
                "prerequisites": ["EKS cluster", "IAM permissions"],
                "benefits": ["AWS native", "Easy setup", "Integrated dashboards"],
                "considerations": ["Limited compared to Prometheus", "Cost at scale"]
            }
        }
    },
    "security": {
        "name": "Security & Policy",
        "icon": "🔒",
        "tools": {
            "falco": {
                "name": "Falco",
                "description": "Runtime security and threat detection",
                "complexity": "Medium",
                "implementation_days": "3-5",
                "prerequisites": ["EKS cluster", "Kernel access"],
                "benefits": ["Runtime detection", "Custom rules", "Integration options"],
                "considerations": ["Rule tuning", "Alert fatigue potential"]
            },
            "opa_gatekeeper": {
                "name": "OPA Gatekeeper",
                "description": "Policy enforcement for Kubernetes",
                "complexity": "Medium",
                "implementation_days": "5-7",
                "prerequisites": ["EKS cluster"],
                "benefits": ["Policy as code", "Admission control", "Audit mode"],
                "considerations": ["Rego learning curve", "Policy management"]
            },
            "kyverno": {
                "name": "Kyverno",
                "description": "Kubernetes-native policy management",
                "complexity": "Low-Medium",
                "implementation_days": "3-5",
                "prerequisites": ["EKS cluster"],
                "benefits": ["YAML-based policies", "Easy to learn", "Generate/mutate resources"],
                "considerations": ["Newer than OPA", "Growing ecosystem"]
            },
            "trivy_operator": {
                "name": "Trivy Operator",
                "description": "Continuous vulnerability scanning for Kubernetes",
                "complexity": "Low",
                "implementation_days": "1-2",
                "prerequisites": ["EKS cluster"],
                "benefits": ["Automated scanning", "CRD-based reports", "Multi-scanner"],
                "considerations": ["Resource usage", "Report management"]
            },
            "aws_guardduty_eks": {
                "name": "GuardDuty for EKS",
                "description": "AWS-managed threat detection for EKS",
                "complexity": "Low",
                "implementation_days": "1",
                "prerequisites": ["EKS cluster", "GuardDuty enabled"],
                "benefits": ["Managed service", "ML-based detection", "AWS integration"],
                "considerations": ["Cost", "Limited customization"]
            }
        }
    },
    "networking": {
        "name": "Networking & Ingress",
        "icon": "🌐",
        "tools": {
            "aws_load_balancer_controller": {
                "name": "AWS Load Balancer Controller",
                "description": "Manages AWS ALB/NLB for Kubernetes",
                "complexity": "Low-Medium",
                "implementation_days": "2-3",
                "prerequisites": ["EKS cluster", "IAM OIDC provider"],
                "benefits": ["Native ALB/NLB", "Target group binding", "WAF integration"],
                "considerations": ["AWS specific", "Annotation-heavy"]
            },
            "nginx_ingress": {
                "name": "NGINX Ingress Controller",
                "description": "Popular ingress controller for Kubernetes",
                "complexity": "Low",
                "implementation_days": "1-2",
                "prerequisites": ["EKS cluster", "Load balancer"],
                "benefits": ["Feature rich", "Wide adoption", "Good documentation"],
                "considerations": ["Resource usage", "Configuration complexity"]
            },
            "cilium": {
                "name": "Cilium",
                "description": "eBPF-based networking, security, and observability",
                "complexity": "High",
                "implementation_days": "7-14",
                "prerequisites": ["EKS cluster", "Kernel 4.9+"],
                "benefits": ["High performance", "Network policies", "Hubble observability"],
                "considerations": ["Replaces VPC CNI", "Complexity"]
            },
            "external_dns": {
                "name": "External DNS",
                "description": "Automatic DNS management for Kubernetes",
                "complexity": "Low",
                "implementation_days": "1-2",
                "prerequisites": ["Route53 or other DNS provider", "IAM permissions"],
                "benefits": ["Automated DNS", "Multi-provider", "Easy setup"],
                "considerations": ["DNS propagation", "Security considerations"]
            }
        }
    },
    "secrets_config": {
        "name": "Secrets & Configuration",
        "icon": "🔑",
        "tools": {
            "external_secrets_operator": {
                "name": "External Secrets Operator",
                "description": "Sync secrets from external stores to Kubernetes",
                "complexity": "Low-Medium",
                "implementation_days": "2-3",
                "prerequisites": ["Secret store (AWS Secrets Manager, etc.)"],
                "benefits": ["Central secret management", "Auto-sync", "Multiple providers"],
                "considerations": ["Secret store dependency", "RBAC setup"]
            },
            "sealed_secrets": {
                "name": "Sealed Secrets",
                "description": "Encrypt secrets for safe Git storage",
                "complexity": "Low",
                "implementation_days": "1-2",
                "prerequisites": ["EKS cluster"],
                "benefits": ["GitOps friendly", "Simple concept", "No external dependency"],
                "considerations": ["Key management", "Rotation complexity"]
            },
            "vault": {
                "name": "HashiCorp Vault",
                "description": "Enterprise secret management",
                "complexity": "High",
                "implementation_days": "10-14",
                "prerequisites": ["Storage backend", "PKI understanding"],
                "benefits": ["Dynamic secrets", "PKI", "Audit logging", "Enterprise features"],
                "considerations": ["Operational complexity", "High availability setup"]
            },
            "aws_secrets_csi_driver": {
                "name": "AWS Secrets Manager CSI Driver",
                "description": "Mount AWS secrets as volumes",
                "complexity": "Low",
                "implementation_days": "1-2",
                "prerequisites": ["AWS Secrets Manager", "IAM OIDC"],
                "benefits": ["AWS native", "Easy setup", "Auto-rotation"],
                "considerations": ["AWS specific", "Volume-based access only"]
            }
        }
    }
}

# CI/CD Maturity Levels
CICD_MATURITY_MODEL = {
    "level_1": {
        "name": "Initial",
        "description": "Manual deployments, minimal automation",
        "characteristics": [
            "Manual build and deploy processes",
            "No version control for infrastructure",
            "Ad-hoc testing",
            "No deployment pipeline"
        ],
        "target_improvements": [
            "Implement basic CI pipeline",
            "Version control all code",
            "Automated unit testing",
            "Basic deployment automation"
        ]
    },
    "level_2": {
        "name": "Managed",
        "description": "Basic automation, some standardization",
        "characteristics": [
            "Basic CI pipeline exists",
            "Manual approval gates",
            "Some automated testing",
            "Environment inconsistencies"
        ],
        "target_improvements": [
            "Infrastructure as Code",
            "Automated integration testing",
            "Environment parity",
            "Deployment automation"
        ]
    },
    "level_3": {
        "name": "Defined",
        "description": "Standardized processes, CD implemented",
        "characteristics": [
            "CI/CD pipeline defined",
            "IaC for infrastructure",
            "Automated testing suite",
            "Consistent environments"
        ],
        "target_improvements": [
            "GitOps adoption",
            "Progressive delivery",
            "Security scanning in pipeline",
            "Observability integration"
        ]
    },
    "level_4": {
        "name": "Quantitatively Managed",
        "description": "Metrics-driven, advanced automation",
        "characteristics": [
            "Deployment metrics tracked",
            "Automated rollbacks",
            "Security gates",
            "Multi-environment pipelines"
        ],
        "target_improvements": [
            "Canary deployments",
            "Feature flags",
            "Chaos engineering",
            "Full observability"
        ]
    },
    "level_5": {
        "name": "Optimizing",
        "description": "Continuous improvement, self-healing",
        "characteristics": [
            "Continuous deployment",
            "Self-healing systems",
            "AI/ML in pipelines",
            "Zero-downtime always"
        ],
        "target_improvements": [
            "Maintain excellence",
            "Innovate continuously",
            "Share learnings",
            "Industry leadership"
        ]
    }
}


def build_modernization_prompt(current_state: Dict, selected_tools: List[str], 
                               goals: str, constraints: str) -> str:
    """Build the prompt for modernization planning"""
    
    # Build tool details
    tool_details = []
    for category_key, category in EKS_TOOLS_CATALOG.items():
        for tool_key, tool in category["tools"].items():
            if tool_key in selected_tools:
                tool_details.append(f"""
**{tool['name']}** ({category['name']}):
- Description: {tool['description']}
- Complexity: {tool['complexity']}
- Implementation Time: {tool['implementation_days']} days
- Prerequisites: {', '.join(tool['prerequisites'])}
- Benefits: {', '.join(tool['benefits'])}
- Considerations: {', '.join(tool['considerations'])}
""")
    
    prompt = f"""You are an expert Kubernetes/EKS architect and DevOps engineer. 
Create a comprehensive implementation plan for modernizing an EKS environment.

## Current State Assessment:
{json.dumps(current_state, indent=2)}

## Selected Tools for Implementation:
{''.join(tool_details)}

## Business Goals:
{goals}

## Constraints & Considerations:
{constraints}

## Provide your response in the following JSON structure:

```json
{{
    "executive_summary": {{
        "total_implementation_weeks": <number>,
        "complexity_rating": "<Low|Medium|High|Very High>",
        "risk_level": "<Low|Medium|High>",
        "estimated_team_size": <number>,
        "summary": "<executive summary paragraph>"
    }},
    "current_state_analysis": {{
        "maturity_level": "<Initial|Managed|Defined|Quantitatively Managed|Optimizing>",
        "strengths": ["<current strengths>"],
        "gaps": ["<identified gaps>"],
        "risks": ["<current risks>"]
    }},
    "architecture_design": {{
        "target_architecture": "<description of target state>",
        "components": [
            {{
                "name": "<component name>",
                "purpose": "<purpose>",
                "integration_points": ["<integration points>"],
                "aws_services": ["<AWS services involved>"]
            }}
        ],
        "data_flows": ["<key data flow descriptions>"],
        "security_considerations": ["<security items>"]
    }},
    "implementation_phases": [
        {{
            "phase": <phase number>,
            "name": "<phase name>",
            "duration_weeks": <number>,
            "objectives": ["<objectives>"],
            "tools_implemented": ["<tools>"],
            "tasks": [
                {{
                    "task": "<task description>",
                    "owner": "<suggested role>",
                    "duration_days": <number>,
                    "dependencies": ["<dependencies>"],
                    "deliverables": ["<deliverables>"]
                }}
            ],
            "success_criteria": ["<measurable criteria>"],
            "risks": [
                {{
                    "risk": "<risk description>",
                    "impact": "<High|Medium|Low>",
                    "mitigation": "<mitigation strategy>"
                }}
            ]
        }}
    ],
    "tool_specific_guidance": [
        {{
            "tool": "<tool name>",
            "configuration_recommendations": ["<recommendations>"],
            "best_practices": ["<best practices>"],
            "common_pitfalls": ["<pitfalls to avoid>"],
            "sample_configuration": "<YAML or code snippet>"
        }}
    ],
    "cicd_enhancement_plan": {{
        "current_maturity": "<level>",
        "target_maturity": "<level>",
        "pipeline_design": {{
            "stages": ["<pipeline stages>"],
            "quality_gates": ["<quality gates>"],
            "security_checks": ["<security integrations>"],
            "deployment_strategy": "<strategy description>"
        }},
        "toolchain_recommendations": ["<toolchain items>"]
    }},
    "resource_requirements": {{
        "team_skills": ["<required skills>"],
        "training_needs": ["<training recommendations>"],
        "infrastructure_costs": {{
            "monthly_estimate_usd": <number>,
            "cost_breakdown": ["<breakdown items>"]
        }},
        "tooling_costs": ["<tool licensing if any>"]
    }},
    "success_metrics": {{
        "deployment_frequency": "<target>",
        "lead_time_for_changes": "<target>",
        "change_failure_rate": "<target>",
        "mttr": "<target>",
        "custom_metrics": ["<additional metrics>"]
    }},
    "maintenance_operations": {{
        "day_2_operations": ["<operational tasks>"],
        "upgrade_strategy": "<strategy>",
        "backup_recovery": ["<backup considerations>"],
        "monitoring_alerts": ["<key alerts to configure>"]
    }}
}}
```

Provide detailed, actionable guidance that a DevOps team can immediately use to begin implementation.
Include specific configurations, commands, and best practices for each tool.
"""
    return prompt


def analyze_modernization_plan(client: anthropic.Anthropic, current_state: Dict,
                               selected_tools: List[str], goals: str, 
                               constraints: str) -> Dict:
    """Generate modernization plan using Claude"""
    
    prompt = build_modernization_prompt(current_state, selected_tools, goals, constraints)
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        response_text = response.content[0].text
        
        # Extract JSON
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        else:
            return json.loads(response_text)
            
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse response: {e}", "raw_response": response_text}
    except Exception as e:
        return {"error": str(e)}


def render_tool_selector():
    """Render the tool selection interface"""
    st.markdown("### 🛠️ Select Tools for Implementation")
    
    selected_tools = []
    
    # Create columns for tool categories
    cols = st.columns(2)
    
    for idx, (category_key, category) in enumerate(EKS_TOOLS_CATALOG.items()):
        with cols[idx % 2]:
            with st.expander(f"{category['icon']} {category['name']}", expanded=True):
                for tool_key, tool in category["tools"].items():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        if st.checkbox(
                            f"**{tool['name']}**",
                            key=f"tool_{tool_key}",
                            help=tool['description']
                        ):
                            selected_tools.append(tool_key)
                    with col2:
                        complexity_color = {
                            "Low": "🟢",
                            "Low-Medium": "🟡",
                            "Medium": "🟠",
                            "Medium-High": "🟠",
                            "High": "🔴",
                            "Very High": "🔴"
                        }
                        st.markdown(f"{complexity_color.get(tool['complexity'], '⚪')} {tool['complexity']}")
    
    return selected_tools


def render_current_state_form() -> Dict:
    """Render form for capturing current state"""
    st.markdown("### 📋 Current Environment Assessment")
    
    current_state = {}
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### EKS Configuration")
        current_state["eks_version"] = st.text_input("EKS Version", placeholder="e.g., 1.29")
        current_state["node_groups"] = st.number_input("Number of Node Groups", min_value=1, value=2)
        current_state["current_autoscaling"] = st.selectbox(
            "Current Autoscaling",
            ["None", "Cluster Autoscaler", "Karpenter", "Manual scaling"]
        )
        current_state["workload_types"] = st.multiselect(
            "Workload Types",
            ["Stateless APIs", "Stateful Applications", "Batch Jobs", "ML Workloads", 
             "Event-driven", "Data Processing"]
        )
        current_state["cluster_count"] = st.number_input("Number of EKS Clusters", min_value=1, value=1)
    
    with col2:
        st.markdown("#### CI/CD & Deployment")
        current_state["current_cicd"] = st.multiselect(
            "Current CI/CD Tools",
            ["Jenkins", "GitHub Actions", "GitLab CI", "AWS CodePipeline", 
             "CircleCI", "ArgoCD", "Flux", "None"]
        )
        current_state["deployment_frequency"] = st.selectbox(
            "Current Deployment Frequency",
            ["Multiple per day", "Daily", "Weekly", "Bi-weekly", "Monthly", "Quarterly"]
        )
        current_state["deployment_method"] = st.selectbox(
            "Current Deployment Method",
            ["Manual kubectl", "Helm", "Kustomize", "GitOps", "CI/CD Pipeline"]
        )
        current_state["environments"] = st.multiselect(
            "Environments",
            ["Development", "Staging", "UAT", "Production", "DR"]
        )
    
    st.markdown("#### Observability & Security")
    col3, col4 = st.columns(2)
    
    with col3:
        current_state["monitoring_tools"] = st.multiselect(
            "Current Monitoring",
            ["CloudWatch", "Prometheus", "Grafana", "Datadog", "New Relic", "None"]
        )
        current_state["logging_solution"] = st.selectbox(
            "Logging Solution",
            ["CloudWatch Logs", "ELK Stack", "Loki", "Splunk", "Datadog", "None"]
        )
    
    with col4:
        current_state["security_tools"] = st.multiselect(
            "Security Tools",
            ["GuardDuty", "Security Hub", "OPA/Gatekeeper", "Kyverno", "Falco", "Trivy", "None"]
        )
        current_state["secrets_management"] = st.selectbox(
            "Secrets Management",
            ["Kubernetes Secrets", "AWS Secrets Manager", "HashiCorp Vault", 
             "External Secrets Operator", "Sealed Secrets"]
        )
    
    st.markdown("#### Team & Organization")
    col5, col6 = st.columns(2)
    
    with col5:
        current_state["team_size"] = st.number_input("DevOps/Platform Team Size", min_value=1, value=3)
        current_state["kubernetes_experience"] = st.selectbox(
            "Team Kubernetes Experience",
            ["Beginner (<1 year)", "Intermediate (1-3 years)", "Advanced (3+ years)", "Expert"]
        )
    
    with col6:
        current_state["change_management"] = st.selectbox(
            "Change Management Process",
            ["Informal", "Basic approval", "CAB review", "Automated with gates"]
        )
        current_state["compliance_requirements"] = st.multiselect(
            "Compliance Requirements",
            ["SOC2", "HIPAA", "PCI-DSS", "FedRAMP", "GDPR", "ISO 27001", "None"]
        )
    
    return current_state


def render_modernization_results(results: Dict):
    """Render the modernization plan results"""
    
    if "error" in results:
        st.error(f"Analysis failed: {results['error']}")
        return
    
    # Executive Summary
    if "executive_summary" in results:
        summary = results["executive_summary"]
        st.markdown("### 📊 Executive Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Implementation Timeline", f"{summary.get('total_implementation_weeks', 'N/A')} weeks")
        with col2:
            st.metric("Complexity", summary.get('complexity_rating', 'N/A'))
        with col3:
            st.metric("Risk Level", summary.get('risk_level', 'N/A'))
        with col4:
            st.metric("Team Size Needed", summary.get('estimated_team_size', 'N/A'))
        
        st.info(summary.get('summary', ''))
    
    # Current State Analysis
    if "current_state_analysis" in results:
        analysis = results["current_state_analysis"]
        st.markdown("### 🔍 Current State Analysis")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Maturity Level:** `{analysis.get('maturity_level', 'N/A')}`")
            st.markdown("**Strengths:**")
            for strength in analysis.get('strengths', []):
                st.markdown(f"- ✅ {strength}")
        with col2:
            st.markdown("**Gaps Identified:**")
            for gap in analysis.get('gaps', []):
                st.markdown(f"- ⚠️ {gap}")
            st.markdown("**Current Risks:**")
            for risk in analysis.get('risks', []):
                st.markdown(f"- 🔴 {risk}")
    
    # Architecture Design
    if "architecture_design" in results:
        arch = results["architecture_design"]
        st.markdown("### 🏗️ Target Architecture Design")
        st.markdown(arch.get('target_architecture', ''))
        
        if arch.get('components'):
            with st.expander("📦 Architecture Components", expanded=True):
                for component in arch['components']:
                    st.markdown(f"""
                    **{component.get('name', 'Component')}**
                    - Purpose: {component.get('purpose', '')}
                    - Integration Points: {', '.join(component.get('integration_points', []))}
                    - AWS Services: {', '.join(component.get('aws_services', []))}
                    ---
                    """)
    
    # Implementation Phases
    if "implementation_phases" in results:
        st.markdown("### 📅 Implementation Roadmap")
        
        for phase in results["implementation_phases"]:
            phase_num = phase.get('phase', 0)
            phase_name = phase.get('name', 'Phase')
            duration = phase.get('duration_weeks', 0)
            
            with st.expander(f"**Phase {phase_num}: {phase_name}** ({duration} weeks)", expanded=(phase_num == 1)):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Objectives:**")
                    for obj in phase.get('objectives', []):
                        st.markdown(f"- 🎯 {obj}")
                    
                    st.markdown("**Tools Implemented:**")
                    for tool in phase.get('tools_implemented', []):
                        st.markdown(f"- 🔧 {tool}")
                
                with col2:
                    st.markdown("**Success Criteria:**")
                    for criteria in phase.get('success_criteria', []):
                        st.markdown(f"- ✓ {criteria}")
                
                # Tasks Table
                if phase.get('tasks'):
                    st.markdown("**Tasks:**")
                    for task in phase['tasks']:
                        st.markdown(f"""
                        <div style="background: #f8f9fa; padding: 0.8rem; border-radius: 6px; margin: 0.5rem 0; border-left: 3px solid #FF9900;">
                            <strong>{task.get('task', '')}</strong><br>
                            <small>👤 {task.get('owner', 'TBD')} | ⏱️ {task.get('duration_days', 0)} days</small><br>
                            <small>📦 Deliverables: {', '.join(task.get('deliverables', []))}</small>
                        </div>
                        """, unsafe_allow_html=True)
                
                # Risks
                if phase.get('risks'):
                    st.markdown("**Risks & Mitigations:**")
                    for risk in phase['risks']:
                        impact_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
                        st.markdown(f"- {impact_color.get(risk.get('impact', ''), '⚪')} **{risk.get('risk', '')}** - {risk.get('mitigation', '')}")
    
    # Tool-Specific Guidance
    if "tool_specific_guidance" in results:
        st.markdown("### 🔧 Tool-Specific Implementation Guidance")
        
        for tool_guide in results["tool_specific_guidance"]:
            with st.expander(f"📘 {tool_guide.get('tool', 'Tool')} Implementation Guide"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Configuration Recommendations:**")
                    for rec in tool_guide.get('configuration_recommendations', []):
                        st.markdown(f"- {rec}")
                    
                    st.markdown("**Best Practices:**")
                    for bp in tool_guide.get('best_practices', []):
                        st.markdown(f"- ✅ {bp}")
                
                with col2:
                    st.markdown("**Common Pitfalls to Avoid:**")
                    for pitfall in tool_guide.get('common_pitfalls', []):
                        st.markdown(f"- ⚠️ {pitfall}")
                
                if tool_guide.get('sample_configuration'):
                    st.markdown("**Sample Configuration:**")
                    st.code(tool_guide['sample_configuration'], language="yaml")
    
    # CI/CD Enhancement Plan
    if "cicd_enhancement_plan" in results:
        cicd = results["cicd_enhancement_plan"]
        st.markdown("### 🚀 CI/CD Enhancement Plan")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Current Maturity:** {cicd.get('current_maturity', 'N/A')}")
            st.markdown(f"**Target Maturity:** {cicd.get('target_maturity', 'N/A')}")
        
        if cicd.get('pipeline_design'):
            pipeline = cicd['pipeline_design']
            with col2:
                st.markdown("**Pipeline Stages:**")
                st.markdown(" → ".join(pipeline.get('stages', [])))
            
            st.markdown("**Quality Gates:**")
            for gate in pipeline.get('quality_gates', []):
                st.markdown(f"- 🚦 {gate}")
            
            st.markdown("**Security Checks:**")
            for check in pipeline.get('security_checks', []):
                st.markdown(f"- 🔐 {check}")
    
    # Resource Requirements
    if "resource_requirements" in results:
        resources = results["resource_requirements"]
        st.markdown("### 💼 Resource Requirements")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Required Skills:**")
            for skill in resources.get('team_skills', []):
                st.markdown(f"- 👤 {skill}")
            
            st.markdown("**Training Needs:**")
            for training in resources.get('training_needs', []):
                st.markdown(f"- 📚 {training}")
        
        with col2:
            if resources.get('infrastructure_costs'):
                costs = resources['infrastructure_costs']
                st.metric("Estimated Monthly Cost", f"${costs.get('monthly_estimate_usd', 0):,.0f}")
                st.markdown("**Cost Breakdown:**")
                for item in costs.get('cost_breakdown', []):
                    st.markdown(f"- {item}")
    
    # Success Metrics
    if "success_metrics" in results:
        metrics = results["success_metrics"]
        st.markdown("### 📈 Success Metrics (DORA)")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Deployment Frequency", metrics.get('deployment_frequency', 'N/A'))
        with col2:
            st.metric("Lead Time for Changes", metrics.get('lead_time_for_changes', 'N/A'))
        with col3:
            st.metric("Change Failure Rate", metrics.get('change_failure_rate', 'N/A'))
        with col4:
            st.metric("MTTR", metrics.get('mttr', 'N/A'))


def generate_modernization_markdown(results: Dict) -> str:
    """Generate markdown report for modernization plan"""
    if not results or "error" in results:
        return "No results to export"
    
    report = f"""# EKS Modernization & CI/CD Enhancement Plan

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

"""
    
    if "executive_summary" in results:
        summary = results["executive_summary"]
        report += f"""
- **Implementation Timeline:** {summary.get('total_implementation_weeks', 'N/A')} weeks
- **Complexity:** {summary.get('complexity_rating', 'N/A')}
- **Risk Level:** {summary.get('risk_level', 'N/A')}
- **Team Size Required:** {summary.get('estimated_team_size', 'N/A')}

{summary.get('summary', '')}

"""
    
    if "implementation_phases" in results:
        report += "## Implementation Roadmap\n\n"
        for phase in results["implementation_phases"]:
            report += f"""### Phase {phase.get('phase', 0)}: {phase.get('name', '')} ({phase.get('duration_weeks', 0)} weeks)

**Objectives:**
"""
            for obj in phase.get('objectives', []):
                report += f"- {obj}\n"
            
            report += "\n**Tasks:**\n"
            for task in phase.get('tasks', []):
                report += f"- {task.get('task', '')} ({task.get('duration_days', 0)} days)\n"
            report += "\n"
    
    return report


def render_modernization_planner(client: Optional[anthropic.Anthropic]):
    """Main renderer for the modernization planner tab"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: white; margin: 0;">🚀 EKS Modernization & CI/CD Enhancement Planner</h2>
        <p style="color: #FF9900; margin: 0.5rem 0 0 0;">Design and plan your Kubernetes tooling implementation</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state for modernization
    if "modernization_results" not in st.session_state:
        st.session_state.modernization_results = None
    
    # Create tabs for different sections
    plan_tab, results_tab, reference_tab = st.tabs([
        "📝 Create Plan", "📊 View Results", "📚 Tool Reference"
    ])
    
    with plan_tab:
        # Current State Assessment
        current_state = render_current_state_form()
        
        st.markdown("---")
        
        # Tool Selection
        selected_tools = render_tool_selector()
        
        st.markdown("---")
        
        # Goals and Constraints
        st.markdown("### 🎯 Goals & Constraints")
        col1, col2 = st.columns(2)
        
        with col1:
            goals = st.text_area(
                "Business & Technical Goals",
                placeholder="""Examples:
- Reduce deployment time from hours to minutes
- Achieve 99.99% availability
- Implement GitOps for all workloads
- Enable self-service for development teams
- Reduce infrastructure costs by 30%""",
                height=150
            )
        
        with col2:
            constraints = st.text_area(
                "Constraints & Considerations",
                placeholder="""Examples:
- Limited budget for new tooling
- Team has minimal Kubernetes experience
- Must maintain compliance with SOC2
- Production freeze in Q4
- Cannot disrupt existing CI/CD pipelines""",
                height=150
            )
        
        st.markdown("---")
        
        # Generate Plan Button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            generate_btn = st.button(
                "🔮 Generate Implementation Plan",
                type="primary",
                use_container_width=True,
                disabled=not (selected_tools and st.session_state.get("api_key_valid", False))
            )
        
        if not selected_tools:
            st.warning("⚠️ Please select at least one tool to generate a plan.")
        
        if generate_btn and selected_tools and client:
            with st.spinner("🔄 Analyzing your environment and generating implementation plan..."):
                results = analyze_modernization_plan(
                    client, current_state, selected_tools, goals, constraints
                )
                
                if "error" not in results:
                    st.session_state.modernization_results = results
                    st.success("✅ Plan generated! View results in the 'View Results' tab.")
                else:
                    st.error(f"Analysis failed: {results.get('error', 'Unknown error')}")
    
    with results_tab:
        if st.session_state.get("modernization_results"):
            render_modernization_results(st.session_state.modernization_results)
            
            st.markdown("---")
            
            # Export options
            st.markdown("### 📥 Export Plan")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                json_export = json.dumps(st.session_state.modernization_results, indent=2)
                st.download_button(
                    "📄 Download JSON",
                    json_export,
                    file_name=f"eks_modernization_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            
            with col2:
                md_export = generate_modernization_markdown(st.session_state.modernization_results)
                st.download_button(
                    "📝 Download Markdown",
                    md_export,
                    file_name=f"eks_modernization_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown"
                )
            
            with col3:
                if st.button("🔄 New Plan"):
                    st.session_state.modernization_results = None
                    st.rerun()
        else:
            st.info("👆 Create a plan in the 'Create Plan' tab to see results here.")
    
    with reference_tab:
        st.markdown("### 📚 EKS Tools Reference Guide")
        
        for category_key, category in EKS_TOOLS_CATALOG.items():
            with st.expander(f"{category['icon']} {category['name']}", expanded=False):
                for tool_key, tool in category["tools"].items():
                    st.markdown(f"""
                    <div style="background: white; padding: 1rem; border-radius: 8px; margin: 0.5rem 0; border-left: 4px solid #FF9900; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                        <h4 style="margin: 0; color: #232F3E;">{tool['name']}</h4>
                        <p style="color: #666; margin: 0.3rem 0;">{tool['description']}</p>
                        <p style="margin: 0.5rem 0;"><strong>Complexity:</strong> {tool['complexity']} | <strong>Time:</strong> {tool['implementation_days']} days</p>
                        <p style="margin: 0.3rem 0;"><strong>Prerequisites:</strong> {', '.join(tool['prerequisites'])}</p>
                        <p style="margin: 0.3rem 0; color: #388E3C;"><strong>Benefits:</strong> {', '.join(tool['benefits'])}</p>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown("### 📊 CI/CD Maturity Model Reference")
        
        for level_key, level in CICD_MATURITY_MODEL.items():
            with st.expander(f"**{level['name']}** - {level['description']}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Characteristics:**")
                    for char in level['characteristics']:
                        st.markdown(f"- {char}")
                with col2:
                    st.markdown("**Target Improvements:**")
                    for imp in level['target_improvements']:
                        st.markdown(f"- 🎯 {imp}")
