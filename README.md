<div align="center">

# Stratos - Azure Security Assessment MCP Server

[![Version](https://img.shields.io/badge/version-1.14.0-blue.svg)](https://github.com/h4cd0c/stratos-mcp)
[![Tests](https://img.shields.io/badge/tests-65%20passing-brightgreen.svg)](https://jestjs.io/)
[![Tools](https://img.shields.io/badge/tools-40-green.svg)](https://github.com/h4cd0c/stratos-mcp)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Azure SDK](https://img.shields.io/badge/Azure%20SDK-v4+-yellow.svg)](https://azure.microsoft.com/en-us/downloads/)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/h4cd0c/stratos-mcp)

**Enterprise-grade Azure security assessment toolkit with multi-location scanning, IMDS exploitation, attack path analysis, and compliance reporting**

*Designed for security professionals conducting authorized penetration tests, compliance audits, and executive risk reporting*

[Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-tool-reference) • [Examples](#-example-workflows)

</div>

---

## Overview

**Stratos** is a comprehensive Azure security assessment framework built on the Model Context Protocol (MCP). It provides 40 production-ready tools covering multi-location scanning, enumeration, vulnerability scanning, attack path analysis, AKS/Kubernetes security (including live K8s API scanning and IMDS exploitation), backup security, VNet topology analysis, private endpoint validation, and compliance reporting for Azure cloud environments.

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
- **40 Security Tools** - Comprehensive Azure service coverage (v1.14.0)  
- **Multi-Location** - Scan common (10) or all (45+) Azure regions  
- **Multi-Format Reports** - PDF, HTML, CSV, Markdown, JSON  
- **Attack Path Analysis** - Privilege escalation and lateral movement mapping  
- **AKS/Kubernetes** - 4 consolidated container security tools (ARM + Live K8s + IMDS)  
- **Enterprise Ready** - Professional reports for executives and auditors

### What's New in v1.14.0 🎉

**Critical Security Enhancement - Research-Driven Expansion**

- **6 New Security Tools** - Backup security, VNet peering, Private Endpoints, Diagnostic Settings, Defender coverage, Policy compliance
- **8 Enhanced Tools** - Storage (SAS tokens + WORM), Service Principals (RBAC-focused), Managed Identities (federation), NSG (service endpoints + load balancers), SQL (PostgreSQL + MySQL + Redis), Function Apps (Event Grid + Service Bus)
- **23 New Parameters** - Extended capabilities across existing tools (100% backward compatible)
- **Research Attribution** - Based on Azure Security Benchmark v3, redskycyber/Cloud-Security, CIS Azure Foundations
- **Cloud Infrastructure Focus** - Service principal analysis excludes Azure AD (cloud resources only)

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

### ☸️ Kubernetes/AKS (3 Tools + Enhanced Features)
- **scan_aks_full** - 🚀 **ENHANCED** Comprehensive AKS security with multiple scan modes:
  - `mode: 'full'` - Complete ARM-based assessment (30+ CIS checks)
  - `mode: 'live'` - Live K8s API scanning (secrets, RBAC, pods, SAs)
  - `mode: 'imds'` - IMDS exploitation & token theft (cluster-wide scan, token export)
  - `mode: 'pod_identity'` - Pod Identity/Workload Identity analysis
  - `mode: 'admission'` - Admission controller bypass detection
- **scan_aks_policy_bypass** - OPA/Kyverno policy bypass detection
- **get_aks_credentials** - Extract kubeconfig for kubectl access

**Migration Note (v1.12.0):** Deprecated tools `scan_aks_live`, `scan_aks_imds`, `scan_aks_pod_identity`, and `scan_aks_admission_bypass` are now consolidated into `scan_aks_full` with `scanMode` parameter.

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

## 📋 Tool Reference (40 Tools)

### Naming Convention
| Prefix | Purpose |
|--------|---------|
| `azure_enumerate_*` | List/discover resources |
| `azure_analyze_*` | Deep configuration analysis |
| `azure_scan_*` | Security assessment |
| `azure_get_*` | Retrieve specific data |
| `azure_detect_*` | Find threats/issues |
| `azure_generate_*` | Create output/reports |

### Complete Tool List

| # | Tool Name | Category | Description |
|---|-----------|----------|-------------|
| 1 | `azure_help` | Info | Display comprehensive help and examples |
| 2 | `azure_list_active_locations` | Multi-Location | Discover which Azure regions have resources |
| 3 | `azure_scan_all_locations` | Multi-Location | Scan resources across all 45+ Azure regions |
| 4 | `azure_enumerate_subscriptions` | Enumeration | List all accessible subscriptions |
| 5 | `azure_enumerate_resource_groups` | Enumeration | List resource groups in subscription |
| 6 | `azure_enumerate_resources` | Enumeration | List all resources (filterable by type) |
| 7 | `azure_get_resource_details` | Enumeration | Get detailed resource configuration |
| 8 | `azure_analyze_storage_security` | Security | Scan storage accounts for misconfigurations |
| 9 | `azure_analyze_nsg_rules` | Security | Identify risky firewall rules |
| 10 | `azure_enumerate_public_ips` | Enumeration | Map internet-exposed attack surface |
| 11 | `azure_enumerate_rbac_assignments` | Enumeration | Audit access control and permissions |
| 12 | `azure_scan_sql_databases` | Security | Check SQL security (TDE, firewall, auth) |
| 13 | `azure_analyze_keyvault_security` | Security | Audit Key Vault configuration |
| 14 | `azure_analyze_cosmosdb_security` | Security | Scan Cosmos DB security settings |
| 15 | `azure_analyze_vm_security` | Security | Check VM disk encryption and patches |
| 16 | `azure_scan_acr_security` | Security | **ENHANCED** ACR security & supply chain (scanMode: security/poisoning/all) |
| 17 | `azure_enumerate_service_principals` | Security | Find application identities and risks |
| 18 | `azure_enumerate_managed_identities` | Enumeration | Track passwordless authentication |
| 19 | `azure_scan_storage_containers` | Security | Deep scan for sensitive files in blobs |
| 20 | `azure_generate_security_report` | Reporting | **ENHANCED** Professional reports with fullScan option (PDF/HTML/CSV/JSON) |
| 21 | `azure_analyze_attack_paths` | Analysis | Map privilege escalation chains |
| 22 | `azure_get_aks_credentials` | Kubernetes | Extract kubeconfig credentials |
| 23 | `azure_scan_azure_devops` | DevOps | Detect hardcoded secrets in repos/pipelines |
| 24 | `azure_analyze_function_apps` | Compute | Function App security analysis |
| 25 | `azure_analyze_app_service_security` | Compute | App Service security assessment |
| 26 | `azure_analyze_firewall_policies` | Network | Azure Firewall policy analysis |
| 27 | `azure_analyze_logic_apps` | Integration | Logic Apps workflow security |
| 28 | `azure_analyze_rbac_privesc` | Analysis | Privilege escalation analysis |
| 29 | `azure_detect_persistence_mechanisms` | Analysis | Detect persistence techniques |
| 30 | `azure_scan_aks_full` | Kubernetes | **ENHANCED** Comprehensive AKS security (scanMode: full/live/imds/pod_identity/admission) |
| 31 | `azure_scan_aks_policy_bypass` | Kubernetes | OPA/Kyverno/Azure Policy bypass detection |
| 32 | `azure_scan_container_apps_security` | Containers | Azure Container Apps security scanner |
| 33 | `azure_scan_gitops_security` | DevOps | GitOps/Flux security scanner |
| 34 | `azure_scan_cdn_security` | Network | Azure CDN & Front Door security |
| 35 | `azure_analyze_backup_security` | Security | **NEW v1.14.0** Recovery Services Vault security (soft delete, immutability, ASR) |
| 36 | `azure_analyze_vnet_peering` | Network | **NEW v1.14.0** VNet peering security (gateway transit, cross-tenant) |
| 37 | `azure_validate_private_endpoints` | Network | **NEW v1.14.0** Private Link validation (DNS, connection state) |
| 38 | `azure_validate_diagnostic_settings` | Compliance | **NEW v1.14.0** Logging compliance (NIST/CIS mapping) |
| 39 | `azure_assess_defender_coverage` | Security | **NEW v1.14.0** Defender for Cloud coverage assessment |
| 40 | `azure_validate_policy_compliance` | Compliance | **NEW v1.14.0** Azure Policy governance validation |

---

## 🚀 Quick Start

### Installation

**Option 1: Install from npm (Recommended)**

```bash
# Install globally from npm
npm install -g stratos-mcp
```

**Option 2: Build from source**

```bash
# Clone the repository
git clone https://github.com/h4cd0c/stratos-mcp.git
cd stratos-mcp

# Install dependencies
npm install
npm run build
```

### Prerequisites

```powershell
# Login to Azure CLI
az login
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
## 🛡️ Input Validation & Auto-Completion ⭐ NEW

**Enhanced Security (OWASP MCP-05 Compliance):**
- **Pattern-Based Validation** - Regex validation for all Azure resource identifiers (subscription IDs, resource groups, locations, etc.)
- **Whitelist Validation** - Location names and resource types validated against Azure service catalogs
- **Sanitization** - Automatic removal of control characters and length enforcement
- **Clear Error Messages** - Helpful validation errors guide users to correct input formats

**Improved User Experience:**
- **Auto-Completion Support** - Intelligent suggestions for locations, resource types, formats, and scan modes
- **Prefix Filtering** - Type-ahead suggestions as you enter values
- **Context-Aware** - Suggests relevant values based on the current tool and argument

Supported completions:
- `location`/`locations` - All 60+ Azure locations + "all", "common"
- `resourceType` - VMs, Storage, NSGs, AKS, SQL, Key Vaults, Public IPs, All
- `format` - markdown, json, html, pdf, csv
- `scanMode` - common, all
- `startFrom` - public-ips, storage, vms, identities, all

---
## � Output Format Control ⭐ NEW

All 30 security tools now support flexible output formatting via the optional `format` parameter:

**Markdown (Default)** - Human-readable output, perfect for documentation and reports
```bash
#azure_whoami
# Returns: Clean markdown text (backward compatible)
```

**JSON** - Machine-readable structured data with metadata for automation
```bash
#azure_whoami format: json
# Returns: { "tool": "azure_whoami", "format": "json", "timestamp": "...", "data": {...} }
```

**Key Benefits:**
- ✅ **Backward Compatible** - Existing tools work without changes (defaults to markdown)
- ✅ **API Integration** - JSON format enables programmatic consumption
- ✅ **Automation** - Parse structured data for CI/CD pipelines
- ✅ **Metadata** - JSON includes tool name, timestamp, and versioning
- ✅ **Flexible** - Choose format per-tool based on use case

**Supported Tools:** All security scanners, enumerators, and analyzers (34 tools total)

**Example Use Cases:**
```bash
# Export scan results to JSON for automation
#azure_analyze_storage_security subscriptionId: YOUR_SUB format: json > results.json

# Human-readable documentation output (default)
#azure_scan_sql_databases subscriptionId: YOUR_SUB

# Structured data for API integration
#azure_analyze_attack_paths subscriptionId: YOUR_SUB format: json
```

---

## �📊 Example Workflows

### 1. Generate Security Reports (Quick vs Comprehensive)
```bash
# Quick scan (4 core tools: Storage, NSG, SQL, KeyVault) - 5-10 seconds
generate_security_report subscriptionId="YOUR_SUB_ID" format="pdf" outputFile="C:\\reports\\quick-scan.pdf"

# Comprehensive scan (ALL 34 tools) - 30-60 seconds
generate_security_report subscriptionId="YOUR_SUB_ID" format="pdf" outputFile="C:\\reports\\full-scan.pdf" fullScan=true
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

**h4cd0c** - [GitHub](https://github.com/h4cd0c)

---

<div align="center">

**Made with ❤️ for the security community**

</div>
