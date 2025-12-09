# 🏗️ AWS Well-Architected Framework Advisor - Enterprise Edition

**AI-Powered Architecture Review, FinOps, Compliance & Cloud Transformation Platform**

An enterprise-grade Streamlit application that leverages Anthropic's Claude AI for comprehensive AWS architecture analysis, cost optimization, compliance assessment, and cloud migration planning.

![AWS WAF Advisor](https://img.shields.io/badge/AWS-Well--Architected-FF9900?style=for-the-badge&logo=amazon-aws)
![Powered by Claude](https://img.shields.io/badge/Powered%20by-Claude%20AI-6366F1?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit)
![Enterprise](https://img.shields.io/badge/Enterprise-Grade-gold?style=for-the-badge)

## 🎯 Platform Capabilities

### 1. 🔍 Well-Architected Framework Review
- **All 6 WAF Pillars**: Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization, Sustainability
- **Multi-Input Support**: Architecture diagrams (images), CloudFormation/Terraform, text descriptions, AWS Config exports
- **5-Level Risk Classification**: Critical, High, Medium, Low, Informational
- **AI-Powered Recommendations**: Actionable guidance with implementation steps

### 2. 🚀 EKS Modernization & CI/CD Enhancement Planner
**30+ Tools Across 8 Categories:**

| Category | Tools |
|----------|-------|
| **📈 Autoscaling** | Karpenter, Cluster Autoscaler, KEDA |
| **🔄 GitOps** | ArgoCD, Flux CD, Crossplane |
| **🚀 CI/CD** | Tekton, GitHub Actions + ARC, Jenkins, AWS CodePipeline |
| **🕸️ Service Mesh** | Istio, Linkerd, AWS App Mesh |
| **📊 Observability** | Prometheus/Grafana, AMP, OpenTelemetry, Datadog, CloudWatch |
| **🔒 Security** | Falco, OPA Gatekeeper, Kyverno, Trivy, GuardDuty |
| **🌐 Networking** | AWS LB Controller, NGINX Ingress, Cilium, External DNS |
| **🔑 Secrets** | External Secrets Operator, Sealed Secrets, Vault, AWS CSI |

**Planning Features:**
- Current state assessment with maturity scoring
- Implementation roadmaps with phases and dependencies
- Tool-specific configuration guidance
- DORA metrics planning (Deployment frequency, Lead time, MTTR)

### 3. 💰 Enterprise FinOps & Cost Intelligence
- **AI-Powered Cost Analysis**: Natural language queries about cloud spending
- **Cost Anomaly Detection**: Automatic identification of spending spikes
- **Optimization Recommendations**: Right-sizing, Reserved Instances, Spot usage
- **Budget Management**: Multi-account budget tracking and forecasting
- **Sustainability Tracking**: Carbon footprint estimation and green region recommendations
- **FinOps Maturity Assessment**: Crawl → Walk → Run maturity model

### 4. 📋 Compliance & Governance Center
**8 Compliance Frameworks:**
- SOC 2 Type II
- HIPAA
- PCI-DSS v4.0
- GDPR
- ISO 27001:2022
- NIST CSF 2.0
- FedRAMP
- CIS Benchmarks

**Features:**
- Multi-framework assessment with control mapping
- Gap analysis and remediation prioritization
- Audit preparation scoring
- Evidence collection guidance
- AWS Config rule recommendations

### 5. 🔄 Migration Assessment & Disaster Recovery

**Migration Planning (7Rs):**
- Rehost (Lift & Shift)
- Replatform (Lift & Reshape)
- Repurchase (Drop & Shop)
- Refactor (Re-architect)
- Retain
- Retire
- Relocate (VMware)

**DR Planning:**
- Business Impact Analysis (BIA)
- RTO/RPO planning
- 4 DR patterns: Backup & Restore → Multi-Site Active/Active
- Runbook generation
- Testing plan templates

### 6. 🔌 AWS Organization Connector (NEW!)

**Live AWS Integration for Multi-Account WAR:**

Connect directly to your AWS Organization for real-time landscape assessment:

- **Organization Discovery**: Automatic account enumeration and OU structure mapping
- **Cross-Account Access**: Role assumption to member accounts (OrganizationAccountAccessRole)
- **Resource Inventory**: Comprehensive scanning across all accounts and regions
- **Cost Aggregation**: Organization-wide cost data from Cost Explorer
- **Security Hub Integration**: Consolidated security findings across accounts
- **AWS Config Compliance**: Config rule compliance status
- **Well-Architected Tool Integration**: Import existing workloads

**Authentication Methods:**
- IAM Access Keys (with optional session token)
- AWS Profiles
- Environment Variables / Instance Role

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListTagsForResource",
        "sts:AssumeRole",
        "ce:GetCostAndUsage",
        "ce:GetCostForecast",
        "securityhub:GetFindings",
        "config:DescribeComplianceByConfigRule",
        "wellarchitected:ListWorkloads"
      ],
      "Resource": "*"
    }
  ]
}
```

### 7. 🔍 Multi-Account WAR Scanner (NEW!)

**AI-Powered Cross-Account Well-Architected Review:**

- Automated assessment across all organization accounts
- Pillar-by-pillar scoring with specific findings
- Cross-account vulnerability analysis
- Governance gap identification
- Consolidated remediation roadmap
- Cost optimization opportunities across accounts
- Security posture consolidation
- Compliance status aggregation

### 8. 📚 Knowledge Base
- Complete WAF pillar reference
- Risk level definitions
- AWS documentation links

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Anthropic API Key ([Get one here](https://console.anthropic.com/))

### Local Installation

```bash
# Clone or download the repository
git clone https://github.com/your-repo/aws-waf-advisor.git
cd aws-waf-advisor

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run app.py
```

### Streamlit Cloud Deployment

1. **Fork/Upload to GitHub**: Push the code to a GitHub repository

2. **Connect to Streamlit Cloud**:
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Click "New app"
   - Select your repository
   - Set `app.py` as the main file

3. **Configure Secrets** (Optional):
   - In Streamlit Cloud dashboard, go to App Settings → Secrets
   - Add your Anthropic API key:
   ```toml
   ANTHROPIC_API_KEY = "sk-ant-..."
   ```
   - Or let users enter their own API key via the UI

4. **Deploy**: Click "Deploy" and your app will be live!

## 📖 Usage Guide

### 1. Configure API Key
Enter your Anthropic API key in the sidebar. This enables the AI analysis capabilities.

### 2. Select Analysis Options
- Choose which WAF pillars to analyze
- Set the analysis depth (Quick Scan / Standard / Deep Dive)

### 3. Upload Architecture
Choose one of four input methods:

| Method | Best For |
|--------|----------|
| **Architecture Diagram** | Visual representations (draw.io, Lucidchart, etc.) |
| **CloudFormation/Terraform** | Infrastructure as Code definitions |
| **Text Description** | Quick analysis of architectural concepts |
| **AWS Config Export** | Detailed resource inventories |

### 4. Review Results
- **Executive Summary**: Overall score and key metrics
- **Pillar Assessments**: Detailed findings per pillar
- **Roadmap**: Prioritized implementation plan
- **Patterns**: Architecture pattern analysis
- **Compliance**: Regulatory framework mapping
- **Cost Analysis**: Optimization opportunities

### 5. Export & Share
Download results as JSON or Markdown for team sharing and documentation.

## 🏛️ AWS Well-Architected Framework Pillars

| Pillar | Focus |
|--------|-------|
| ⚙️ **Operational Excellence** | Run and monitor systems to deliver business value |
| 🔐 **Security** | Protect information, systems, and assets |
| 🛡️ **Reliability** | Recover from failures and meet demand |
| ⚡ **Performance Efficiency** | Use computing resources efficiently |
| 💰 **Cost Optimization** | Avoid unnecessary costs |
| 🌱 **Sustainability** | Minimize environmental impacts |

## 🎯 Risk Level Definitions

| Level | Priority | Action Timeline |
|-------|----------|-----------------|
| 🔴 **CRITICAL** | P1 | Immediate action required |
| 🟠 **HIGH** | P2 | Address within 1-2 weeks |
| 🟡 **MEDIUM** | P3 | Address within 1-3 months |
| 🟢 **LOW** | P4 | Consider for future improvements |
| 🔵 **INFO** | P5 | Informational suggestions |

## 🛠️ Technical Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Streamlit Frontend                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Upload     │  │  Analysis    │  │ EKS & CI/CD  │  │  Knowledge   │    │
│  │ Architecture │  │   Results    │  │   Planner    │  │    Base      │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Analysis Engine                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │              Claude AI (claude-sonnet-4-20250514)                     │ │
│  │  • WAF Pillar Assessment      • EKS Tool Recommendations             │ │
│  │  • Risk Classification        • CI/CD Maturity Analysis              │ │
│  │  • Compliance Mapping         • Implementation Roadmaps              │ │
│  │  • Cost Optimization          • DORA Metrics Planning                │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Output Formats                                    │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │    JSON    │  │  Markdown  │  │ Interactive │  │   DORA     │           │
│  │   Export   │  │   Report   │  │  Dashboard  │  │  Metrics   │           │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 📖 Usage Guide

### Tab 1: Upload Architecture (WAF Review)
1. Configure your Anthropic API key in the sidebar
2. Select which WAF pillars to analyze
3. Choose input method (diagram, code, text, or JSON)
4. Add optional context about compliance requirements
5. Click "Analyze Architecture"

### Tab 2: Analysis Results
- View executive summary and risk metrics
- Explore findings by pillar
- Review prioritized roadmap
- Export results as JSON or Markdown

### Tab 3: EKS & CI/CD Planner (NEW!)
1. **Current State Assessment**: Document your existing EKS configuration, CI/CD tools, monitoring, and team capabilities
2. **Tool Selection**: Choose from 30+ tools across 8 categories (autoscaling, GitOps, CI/CD, service mesh, observability, security, networking, secrets)
3. **Goals & Constraints**: Define business objectives and implementation constraints
4. **Generate Plan**: AI creates a comprehensive implementation roadmap with phases, tasks, risks, and success metrics

### Tab 4: Knowledge Base
- Reference guide for all 6 WAF pillars
- Risk level definitions
- Links to AWS documentation

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key | Optional (can use UI) |

### Streamlit Config (.streamlit/config.toml)

```toml
[theme]
primaryColor = "#FF9900"      # AWS Orange
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F8F9FA"
textColor = "#232F3E"         # AWS Dark

[server]
maxUploadSize = 50            # Max file upload size in MB
```

## 📊 Sample Architecture Input

```
Our e-commerce platform runs on AWS with:

Frontend:
- React SPA on S3 + CloudFront
- Route 53 for DNS with health checks

Backend:
- ECS Fargate cluster (3 services)
- Application Load Balancer
- API Gateway for external APIs

Data:
- RDS PostgreSQL (db.r5.xlarge) - Single AZ
- ElastiCache Redis (cache.m5.large)
- S3 for product images

Security:
- WAF on CloudFront
- Security Groups (default VPC)
- No encryption at rest

Monitoring:
- Basic CloudWatch metrics
- No centralized logging
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- New features
- Documentation improvements
- UI/UX enhancements

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Anthropic Claude](https://www.anthropic.com/claude)
- [Streamlit](https://streamlit.io/)

---

**Built with ❤️ for AWS Architects and Cloud Engineers**
