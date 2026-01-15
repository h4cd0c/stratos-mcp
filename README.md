<div align="center">

# Stratos - Azure Security Assessment MCP Server

[![Version](https://img.shields.io/badge/version-1.10.3-blue.svg)](https://github.com/Jaikumar3/stratos-mcp)
[![Tools](https://img.shields.io/badge/tools-32-green.svg)](https://github.com/Jaikumar3/stratos-mcp)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Azure SDK](https://img.shields.io/badge/Azure%20SDK-v4+-yellow.svg)](https://azure.microsoft.com/en-us/downloads/)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/Jaikumar3/stratos-mcp)

**Enterprise-grade Azure security assessment toolkit with multi-location scanning, IMDS exploitation, attack path analysis, and compliance reporting**

*Designed for security professionals conducting authorized penetration tests, compliance audits, and executive risk reporting*

[Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-tool-reference) • [Examples](#-example-workflows)

</div>

---

## Overview

**Stratos** is a comprehensive Azure security assessment framework built on the Model Context Protocol (MCP). It provides 32 production-ready tools covering multi-location scanning, enumeration, vulnerability scanning, attack path analysis, AKS/Kubernetes security (including live K8s API scanning and IMDS exploitation), and compliance reporting for Azure cloud environments.

### Use Cases

- **Multi-Location Scanning** - Scan resources across all 45+ Azure regions
- **Security Assessments** - Identify misconfigurations and vulnerabilities
- **IMDS Exploitation** - Token theft, cluster-wide exposure, deep data plane access
- **Executive Reporting** - Generate professional risk assessment reports
- **Compliance Audits** - Map findings to CIS, NIST frameworks
- **Penetration Testing** - Discover attack paths and privilege escalation vectors
- **Kubernetes Security** - AKS cluster, node, and IMDS vulnerability testing
- **DevOps Security** - Detect hardcoded secrets in Azure DevOps

### Key Highlights

- **100% Read-Only** - Safe for production environments  
- **32 Security Tools** - Comprehensive Azure service coverage  
- **Multi-Location** - Scan common (10) or all (45+) Azure regions  
- **Multi-Format Reports** - PDF, HTML, CSV, Markdown, JSON  
- **Attack Path Analysis** - Privilege escalation and lateral movement mapping  
- **AKS/Kubernetes** - 4 consolidated container security tools (ARM + Live K8s + IMDS)  
- **Enterprise Ready** - Professional reports for executives and auditors

---

## Key Features

<table>
<tr>
<td width="50%">

### 🌍 Multi-Location (2 Tools)
- **list_active_locations** - Discover active Azure regions
- **scan_all_locations** - Scan resources across all regions
- Support for 45+ Azure locations globally
- Location filtering on enumeration tools

### 🔍 Enumeration (7 Tools)
- **Subscriptions** - Map Azure environment structure
- **Resource Groups** - List all resource containers (with location filter)
- **Resources** - Enumerate all resources (with location filter)
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

### ☸️ Kubernetes/AKS (4 Tools)
- **scan_aks_full** - Comprehensive ARM-based assessment (30+ CIS checks)
- **scan_aks_live** - Live K8s API scanning (secrets, RBAC, pods, SAs)
- **scan_aks_imds** - IMDS exploitation & token theft (cluster-wide scan, token export, deep data plane)
- **get_aks_credentials** - Extract kubeconfig for kubectl access

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

## 📋 Tool Reference (37 Tools)

### Naming Convention
| Prefix | Purpose |
|--------|---------|
| `enumerate_*` | List/discover resources |
| `analyze_*` | Deep configuration analysis |
| `scan_*` | Security assessment |
| `get_*` | Retrieve specific data |
| `detect_*` | Find threats/issues |
| `generate_*` | Create output/reports |

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
| 10 | `list_active_locations` | Multi-Location | Discover which Azure regions have resources |
| 11 | `scan_all_locations` | Multi-Location | Scan resources across all 45+ Azure regions |
| 12 | `analyze_storage_security` | Security | Scan storage accounts for misconfigurations |
| 13 | `scan_storage_containers` | Security | Deep scan for sensitive files in blobs |
| 14 | `analyze_nsg_rules` | Security | Identify risky firewall rules |
| 15 | `scan_sql_databases` | Security | Check SQL security (TDE, firewall, auth) |
| 16 | `analyze_keyvault_security` | Security | Audit Key Vault configuration |
| 17 | `analyze_vm_security` | Security | Check VM disk encryption and patches |
| 18 | `analyze_cosmosdb_security` | Security | Scan Cosmos DB security settings |
| 19 | `scan_acr_security` | Security | Audit ACR security (admin user, scanning) |
| 20 | `scan_service_principals` | Security | Find application identities and risks |
| 21 | `scan_credential_exposure` | Security | Detect exposed credentials |
| 22 | `generate_security_report` | Reporting | Professional reports (PDF/HTML/CSV/JSON) |
| 23 | `analyze_attack_paths` | Analysis | Map privilege escalation chains |
| 24 | `get_aks_credentials` | Kubernetes | Extract kubeconfig credentials |
| 25 | `scan_aks_full` | Kubernetes | Comprehensive ARM-based AKS assessment (30+ CIS checks) |
| 26 | `scan_aks_live` | Kubernetes | Direct K8s API scanning (secrets, RBAC, pods, SAs) |
| 27 | `scan_aks_imds` | Kubernetes | IMDS exploitation & token theft (cluster-wide, export, deep read) |
| 28 | `scan_azure_devops` | DevOps | Detect hardcoded secrets in repos/pipelines |
| 29 | `analyze_function_apps` | Compute | Function App security analysis |
| 30 | `analyze_app_service_security` | Compute | App Service security assessment |
| 31 | `analyze_firewall_policies` | Network | Azure Firewall policy analysis |
| 32 | `analyze_logic_apps` | Integration | Logic Apps workflow security |

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
# Comprehensive ARM-based scan
scan_aks_full subscriptionId="YOUR_SUB_ID" resourceGroup="RG-NAME" clusterName="CLUSTER-NAME"

# IMDS exploitation with token export
scan_aks_imds subscriptionId="YOUR_SUB_ID" resourceGroup="RG-NAME" clusterName="CLUSTER-NAME" scanAllPods=true exportTokens=true deepDataPlane=true
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
