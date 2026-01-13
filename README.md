<div align="center">

# Stratos - Azure Security Assessment MCP Server

[![Version](https://img.shields.io/badge/version-1.8.0-blue.svg)](https://github.com/Jaikumar3/stratos-mcp)
[![Tools](https://img.shields.io/badge/tools-33-green.svg)](https://github.com/Jaikumar3/stratos-mcp)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Azure SDK](https://img.shields.io/badge/Azure%20SDK-v4+-yellow.svg)](https://azure.microsoft.com/en-us/downloads/)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/Jaikumar3/stratos-mcp)

**Enterprise-grade Azure security assessment toolkit with attack path analysis and compliance reporting**

*Designed for security professionals conducting authorized penetration tests, compliance audits, and executive risk reporting*

[Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-tool-reference) • [Examples](#-example-workflows)

</div>

---

## Overview

**Stratos** is a comprehensive Azure security assessment framework built on the Model Context Protocol (MCP). It provides 33 production-ready tools covering enumeration, vulnerability scanning, attack path analysis, AKS/Kubernetes security (including service account analysis and secret hunting), and compliance reporting for Azure cloud environments.

### Use Cases

- **Security Assessments** - Identify misconfigurations and vulnerabilities
- **Executive Reporting** - Generate professional risk assessment reports
- **Compliance Audits** - Map findings to CIS, NIST frameworks
- **Penetration Testing** - Discover attack paths and privilege escalation vectors
- **Kubernetes Security** - AKS cluster, node, and IMDS vulnerability testing
- **DevOps Security** - Detect hardcoded secrets in Azure DevOps

### Key Highlights

- **100% Read-Only** - Safe for production environments  
- **33 Security Tools** - Comprehensive Azure service coverage  
- **Multi-Format Reports** - PDF, HTML, CSV, Markdown, JSON  
- **Attack Path Analysis** - Privilege escalation and lateral movement mapping  
- **AKS/Kubernetes** - 7 specialized container security tools (incl. SA & secret hunting)  
- **Enterprise Ready** - Professional reports for executives and auditors

---

## Key Features

<table>
<tr>
<td width="50%">

### 🔍 Enumeration (7 Tools)
- **Subscriptions** - Map Azure environment structure
- **Resource Groups** - List all resource containers
- **Resources** - Enumerate all resources (filterable)
- **Resource Details** - Get detailed configurations
- **Public IPs** - Identify internet-exposed attack surface
- **RBAC Assignments** - Audit access control permissions
- **Managed Identities** - Track passwordless authentication

</td>
<td width="50%">

### 🛡️ Security Scanning (10 Tools)
- **Storage Security** - Public access, HTTPS, encryption
- **Storage Containers** - Deep scan for sensitive files
- **NSG Rules** - Internet-exposed ports, wildcard rules
- **SQL Databases** - TDE encryption, firewall, auth
- **Key Vaults** - Soft delete, purge protection, secrets
- **Virtual Machines** - Disk encryption, security extensions
- **Cosmos DB** - Public access, firewall, encryption
- **Container Registries** - Admin user, vulnerability scanning
- **Attack Paths** - Privilege escalation chains
- **Service Principals** - Application identity scanning

</td>
</tr>
<tr>
<td width="50%">

### ☸️ Kubernetes/AKS (5 Tools)
- **Cluster Security** - RBAC, network policies, pod security
- **Credentials** - Extract kubeconfig for kubectl access
- **Identity Enumeration** - Cluster and kubelet identities
- **Node Security** - Disk encryption, SSH, public IPs
- **IMDS Testing** - Pod escape vulnerability detection

</td>
<td width="50%">

### 📊 Reporting & DevOps (3 Tools)
- **Security Reports** - PDF/HTML/CSV with CIS/NIST mapping
- **Azure DevOps Scanner** - Hardcoded secrets detection
- **Credential Exposure** - Scan for exposed credentials

**Report Features:**
- Executive summaries with risk statistics
- Color-coded severity (CRITICAL/HIGH/MEDIUM/LOW)
- Compliance framework mapping
- Remediation guidance

</td>
</tr>
</table>

---

## 📋 Tool Reference (25 Tools)

### Naming Convention
| Prefix | Purpose |
|--------|---------|
| `enumerate_*` | List/discover resources |
| `analyze_*` | Deep security analysis |
| `scan_*` | Quick security check |
| `get_*` | Retrieve data/status |
| `test_*` | Vulnerability testing |
| `generate_*` | Create reports |

### Complete Tool List

| # | Tool Name | Category | Description |
|---|-----------|----------|-------------|
| 1 | `help` | Info | Display comprehensive help and examples |
| 2 | `whoami` | Identity | Get current Azure identity information |
| 3 | `enumerate_subscriptions` | Enumeration | List all accessible subscriptions |
| 4 | `enumerate_resource_groups` | Enumeration | List resource groups in subscription |
| 5 | `enumerate_resources` | Enumeration | List all resources (filterable by type) |
| 6 | `get_resource_details` | Enumeration | Get detailed resource configuration |
| 7 | `enumerate_public_ips` | Enumeration | Map internet-exposed attack surface |
| 8 | `enumerate_rbac_assignments` | Enumeration | Audit access control and permissions |
| 9 | `enumerate_managed_identities` | Enumeration | Track passwordless authentication |
| 10 | `analyze_storage_security` | Security | Scan storage accounts for misconfigurations |
| 11 | `scan_storage_containers` | Security | Deep scan for sensitive files in blobs |
| 12 | `analyze_nsg_rules` | Security | Identify risky firewall rules |
| 13 | `scan_sql_databases` | Security | Check SQL security (TDE, firewall, auth) |
| 14 | `analyze_key_vault_security` | Security | Audit Key Vault configuration |
| 15 | `analyze_vm_security` | Security | Check VM disk encryption and patches |
| 16 | `analyze_cosmos_db_security` | Security | Scan Cosmos DB security settings |
| 17 | `scan_container_registries` | Security | Audit ACR security (admin user, scanning) |
| 18 | `scan_service_principals` | Security | Find application identities and risks |
| 19 | `scan_credential_exposure` | Security | Detect exposed credentials |
| 20 | `generate_security_report` | Reporting | Professional reports (PDF/HTML/CSV/JSON) |
| 21 | `analyze_attack_paths` | Analysis | Map privilege escalation chains |
| 22 | `scan_aks_clusters` | Kubernetes | AKS security assessment |
| 23 | `get_aks_credentials` | Kubernetes | Extract kubeconfig credentials |
| 24 | `enumerate_aks_identities` | Kubernetes | Map cluster identities and roles |
| 25 | `scan_aks_node_security` | Kubernetes | Check node security configuration |
| 26 | `test_aks_imds_access` | Kubernetes | Test for pod escape vulnerabilities |
| 27 | `scan_aks_service_accounts` | Kubernetes | Analyze AKS service account security |
| 28 | `hunt_aks_secrets` | Kubernetes | Comprehensive K8s secret hunting guide |
| 29 | `scan_azure_devops` | DevOps | Detect hardcoded secrets in repos/pipelines |

---

## 🚀 Quick Start

### Prerequisites

```powershell
# Login to Azure CLI
az login

# Install dependencies
cd stratos-mcp
npm install
npm run build
```

### VS Code Configuration

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "stratos": {
      "command": "node",
      "args": ["C:\\path\\to\\stratos-mcp\\dist\\index.js"],
      "type": "stdio"
    }
  }
}
```

---

## 📊 Example Workflows

### 1. Generate PDF Security Report
```bash
generate_security_report subscriptionId="YOUR_SUB_ID" format="pdf" outputFile="C:\\reports\\azure-security.pdf"
```

### 2. Analyze Attack Paths
```bash
analyze_attack_paths subscriptionId="YOUR_SUB_ID" startFrom="public-ips"
```

### 3. Scan Azure DevOps for Secrets
```bash
scan_azure_devops organizationUrl="https://dev.azure.com/yourorg" personalAccessToken="YOUR_PAT"
```

### 4. AKS Security Assessment
```bash
scan_aks_clusters subscriptionId="YOUR_SUB_ID"
test_aks_imds_access subscriptionId="YOUR_SUB_ID" resourceGroup="RG-NAME" clusterName="CLUSTER-NAME"
```

### 5. Deep Storage Container Scan
```bash
scan_storage_containers subscriptionId="YOUR_SUB_ID"
```

---

## 📄 Report Formats

| Format | Use Case | Features |
|--------|----------|----------|
| **PDF** | Executive presentations | Color-coded severity, professional layout |
| **HTML** | Interactive dashboards | Modern styling, sortable tables |
| **CSV** | Data analysis, Excel | Structured export for tracking |
| **JSON** | Automation integration | Machine-readable format |
| **Markdown** | Documentation | Human-readable, version control |

---

## 🔧 Technical Details

**Dependencies:**
- Azure SDK v4+ for all services
- Azure DevOps API v13.2.0
- PDFKit, Marked, CSV-Writer for exports
- TypeScript 5.3.3, Node.js 20+
- MCP SDK v1.0.4

**Supported Azure Services:**
- Storage Accounts, Network Security Groups
- SQL Databases, Key Vaults, Virtual Machines
- Cosmos DB, Container Registries
- AKS/Kubernetes, Azure DevOps

---

## ⚠️ Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for security professionals conducting authorized penetration tests. Users must:
- Have explicit written authorization from target organization
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Respect Azure Terms of Service

Unauthorized access to computer systems is illegal.

---

## 📝 License

MIT

## 🤝 Author

**Jaikumar3** - [GitHub](https://github.com/Jaikumar3)

---

<div align="center">

**Made with ❤️ for the security community**

</div>
