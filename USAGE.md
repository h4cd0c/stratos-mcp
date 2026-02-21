# Stratos - Azure Security Assessment MCP Server - Usage Guide

**Version:** 1.14.0 | **Total Tools:** 40

## Quick Start

Get comprehensive help with all 40 tools:
```bash
#mcp_stratos_help
```

## What's New in v1.14.0 🎉

**6 New Security Tools:**
- `azure_analyze_backup_security` - Recovery Services vault security (ransomware protection)
- `azure_analyze_vnet_peering` - VNet peering topology and cross-tenant risks
- `azure_validate_private_endpoints` - Private Link connection validation
- `azure_validate_diagnostic_settings` - Logging compliance (NIST/CIS)
- `azure_assess_defender_coverage` - Defender for Cloud assessment
- `azure_validate_policy_compliance` - Azure Policy governance

**8 Enhanced Tools with 23 New Parameters:**
- Storage Security - SAS tokens + WORM immutability + lifecycle management
- Service Principals - RBAC-focused privilege analysis (cloud-only)
- Managed Identities - Federated credentials + cross-subscription detection
- NSG Rules - Service endpoints + load balancer integration
- SQL Databases - PostgreSQL + MySQL + Redis Cache support
- Function Apps - Event Grid + Service Bus integration security
- Security Report - Updated to 40 tools reference

## Installation

```powershell
# Clone or download the repository
cd stratos-mcp

# Install dependencies
npm install

# Build the server
npm run build
```

## MCP Configuration

Add to your MCP settings file:

**Windows:** `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

```json
{
  "mcpServers": {
    "stratos": {
      "command": "node",
      "args": ["C:\\path\\to\\stratos-mcp\\dist\\index.js"],
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

**After configuration:** Restart VS Code

## Common Resource Types

| Resource Type | Provider/Type String | Security Focus |
|---------------|----------------------|----------------|
| Storage Accounts | Microsoft.Storage/storageAccounts | Public access, encryption, SAS tokens, WORM |
| Network Security Groups | Microsoft.Network/networkSecurityGroups | Firewall rules, open ports, service endpoints |
| Public IPs | Microsoft.Network/publicIPAddresses | Internet exposure |
| SQL Servers | Microsoft.Sql/servers | Authentication, TDE |
| PostgreSQL Servers | Microsoft.DBforPostgreSQL/flexibleServers | SSL enforcement, firewall |
| MySQL Servers | Microsoft.DBforMySQL/flexibleServers | SSL enforcement, firewall |
| Redis Cache | Microsoft.Cache/Redis | Non-SSL ports, TLS version |
| Key Vaults | Microsoft.KeyVault/vaults | Access policies, soft delete |
| AKS Clusters | Microsoft.ContainerService/managedClusters | RBAC, network policies |
| Recovery Services Vaults | Microsoft.RecoveryServices/vaults | Soft delete, immutability, ASR |
| Virtual Network Peerings | Microsoft.Network/virtualNetworks/virtualNetworkPeerings | Gateway transit, cross-tenant |
| Private Endpoints | Microsoft.Network/privateEndpoints | Connection state, DNS config |

## Practical Examples (v1.14.0)

### New Tool Examples

**Backup Security Assessment (Ransomware Protection)**
```bash
# Check all Recovery Services Vaults for immutability and soft delete
#azure_analyze_backup_security subscriptionId: <sub-id> includeASR: true checkImmutability: true

# Focus on production resource group
#azure_analyze_backup_security subscriptionId: <sub-id> resourceGroup: prod-rg checkImmutability: true
```

**VNet Peering Security Analysis**
```bash
# Analyze all VNet peerings for topology and risks
#azure_analyze_vnet_peering subscriptionId: <sub-id> detectTopology: true checkCrossTenant: true

# Quick peering scan
#azure_analyze_vnet_peering subscriptionId: <sub-id>
```

**Private Endpoint Validation**
```bash
# Validate all storage private endpoints
#azure_validate_private_endpoints subscriptionId: <sub-id> serviceType: Storage validateDNS: true

# Check SQL private endpoints
#azure_validate_private_endpoints subscriptionId: <sub-id> serviceType: SQL validateDNS: true

# Validate all private endpoints
#azure_validate_private_endpoints subscriptionId: <sub-id> serviceType: all
```

**Diagnostic Settings Compliance**
```bash
# Check logging compliance across all resources
#azure_validate_diagnostic_settings subscriptionId: <sub-id> resourceType: all checkCompliance: true

# Focus on VMs only
#azure_validate_diagnostic_settings subscriptionId: <sub-id> resourceType: VirtualMachines checkCompliance: true
```

### Enhanced Tool Examples

**Storage Security with SAS Tokens & WORM**
```bash
# Basic storage scan
#azure_analyze_storage_security subscriptionId: <sub-id>

# Deep scan with SAS tokens and immutability
#azure_analyze_storage_security subscriptionId: <sub-id> scanSasTokens: true validateImmutability: true deepSecurityScan: true

# Production storage immutability check
#azure_analyze_storage_security subscriptionId: <sub-id> resourceGroup: prod-data validateImmutability: true
```

**Service Principals with RBAC Privilege Analysis**
```bash
# Basic enumeration
#azure_enumerate_service_principals subscriptionId: <sub-id>

# Full privilege escalation scan (cloud-only, excludes Azure AD)
#azure_enumerate_service_principals subscriptionId: <sub-id> includePrivilegeAnalysis: true validateSecrets: true expiryWarningDays: 30
```

**Managed Identities with Federation**
```bash
# Basic scan
#azure_enumerate_managed_identities subscriptionId: <sub-id>

# Advanced: Federation + cross-subscription + role assignments
#azure_enumerate_managed_identities subscriptionId: <sub-id> analyzeFederatedCredentials: true detectCrossSubscription: true includeRoleAssignments: true
```

**NSG with Service Endpoints & Load Balancers**
```bash
# Standard NSG analysis
#azure_analyze_nsg_rules subscriptionId: <sub-id>

# Enhanced: Service endpoints + load balancer health probes
#azure_analyze_nsg_rules subscriptionId: <sub-id> validateServiceEndpoints: true checkLoadBalancers: true
```

**Multi-Database SQL Scanning**
```bash
# Traditional SQL only
#azure_scan_sql_databases subscriptionId: <sub-id>

# Comprehensive: SQL + PostgreSQL + MySQL + Redis
#azure_scan_sql_databases subscriptionId: <sub-id> includePostgreSQL: true includeMySQL: true includeRedis: true
```

**Function Apps with Integration Security**
```bash
# Basic Function App scan
#azure_analyze_function_apps subscriptionId: <sub-id>

# Full integration security (Event Grid + Service Bus)
#azure_analyze_function_apps subscriptionId: <sub-id> validateEventGrid: true validateServiceBus: true checkIntegrationSecurity: true
```

### Quick Resource Discovery
```bash
# Find all public IPs
#azure_enumerate_resources subscriptionId: <sub-id> resourceType: Microsoft.Network/publicIPAddresses

# Find all storage accounts
#azure_enumerate_resources subscriptionId: <sub-id> resourceType: Microsoft.Storage/storageAccounts

# Find all NSGs
#azure_enumerate_resources subscriptionId: <sub-id> resourceType: Microsoft.Network/networkSecurityGroups

# Find all Recovery Services Vaults
#azure_enumerate_resources subscriptionId: <sub-id> resourceType: Microsoft.RecoveryServices/vaults

# Find all Redis caches
#azure_enumerate_resources subscriptionId: <sub-id> resourceType: Microsoft.Cache/Redis
```

### Deep Dive Analysis
```bash
#azure_get_resource_details
subscriptionId: <YOUR_SUBSCRIPTION_ID>
resourceGroup: <RESOURCE_GROUP>
resourceProvider: Microsoft.Storage
resourceType: storageAccounts
resourceName: <STORAGE_ACCOUNT_NAME>
```

## Security Findings to Look For

### Storage Accounts
- ✅ Check `allowBlobPublicAccess` - Should be false
- ✅ Check `networkAcls` - Should have restrictive firewall rules
- ✅ Check `encryption.services` - All services should be encrypted
- ✅ Check `minimumTlsVersion` - Should be TLS1_2

### Network Security Groups
- ✅ Look for rules with `sourceAddressPrefix: "*"` (any source)
- ✅ Check for open ports: 22 (SSH), 3389 (RDP), 1433 (SQL), 3306 (MySQL)
- ✅ Verify priority values (lower = higher priority)
## Prerequisites

```powershell
# Authenticate with Azure CLI (most common method)
az login

# Verify authentication
az account show
```

**Required Azure Permissions:**
- **Reader** role (minimum) - View resources
- **Security Reader** - View security findings
- **Contributor** - For remediation actions

**After Installation:** Restart VS Code to load the MCP server

## Professional Pentesting Workflow (v1.14.0)

### Phase 1: Discovery & Enumeration
```bash
# List all subscriptions
#azure_enumerate_subscriptions

# Enumerate public attack surface
#azure_enumerate_public_ips subscriptionId: <sub-id>

# Audit RBAC assignments
#azure_enumerate_rbac_assignments subscriptionId: <sub-id>

# NEW: Managed identities with federation analysis
#azure_enumerate_managed_identities subscriptionId: <sub-id> analyzeFederatedCredentials: true detectCrossSubscription: true

# NEW: Service principals (RBAC-focused, cloud-only)
#azure_enumerate_service_principals subscriptionId: <sub-id> includePrivilegeAnalysis: true expiryWarningDays: 30
```

### Phase 2: Security Scanning
```bash
# ENHANCED: Storage with SAS tokens + WORM validation
#azure_analyze_storage_security subscriptionId: <sub-id> scanSasTokens: true validateImmutability: true deepSecurityScan: true

# ENHANCED: NSG with service endpoints + load balancers
#azure_analyze_nsg_rules subscriptionId: <sub-id> validateServiceEndpoints: true checkLoadBalancers: true

# ENHANCED: SQL with PostgreSQL + MySQL + Redis
#azure_scan_sql_databases subscriptionId: <sub-id> includePostgreSQL: true includeMySQL: true includeRedis: true

# ENHANCED: Function Apps with Event Grid + Service Bus
#azure_analyze_function_apps subscriptionId: <sub-id> validateEventGrid: true validateServiceBus: true checkIntegrationSecurity: true
```

### Phase 3: Infrastructure Security (NEW in v1.14.0)
```bash
# NEW: Backup security (ransomware protection)
#azure_analyze_backup_security subscriptionId: <sub-id> includeASR: true checkImmutability: true

# NEW: VNet peering topology
#azure_analyze_vnet_peering subscriptionId: <sub-id> detectTopology: true checkCrossTenant: true

# NEW: Private endpoint validation
#azure_validate_private_endpoints subscriptionId: <sub-id> serviceType: Storage validateDNS: true

# NEW: Diagnostic settings compliance
#azure_validate_diagnostic_settings subscriptionId: <sub-id> resourceType: all checkCompliance: true
```

### Phase 4: Attack Path Analysis
```bash
#azure_analyze_attack_paths subscriptionId: <sub-id> startFrom: public-ips
```

### Phase 5: AKS Security Testing
```bash
# Comprehensive AKS scan with multiple modes
#azure_scan_aks_full subscriptionId: <sub-id> scanMode: full
#azure_scan_aks_full subscriptionId: <sub-id> scanMode: live resourceGroup: <rg> clusterName: <aks>
#azure_scan_aks_full subscriptionId: <sub-id> scanMode: imds resourceGroup: <rg> clusterName: <aks>
```

### Phase 6: Compliance & Governance (NEW)
```bash
# NEW: Azure Policy compliance
#azure_validate_policy_compliance subscriptionId: <sub-id> policyScope: subscription includeExemptions: true

# NEW: Defender for Cloud coverage
#azure_assess_defender_coverage subscriptionId: <sub-id> includeRecommendations: true includeCompliance: true
```

### Phase 7: DevOps Security
```bash
#azure_scan_azure_devops organizationUrl: https://dev.azure.com/yourorg personalAccessToken: <pat>
```

### Phase 8: Generate Comprehensive Report
```bash
# Quick scan (4 core tools)
#azure_generate_security_report subscriptionId: <sub-id> format: markdown

# ENHANCED: Full scan (ALL 40 tools)
#azure_generate_security_report subscriptionId: <sub-id> fullScan: true format: pdf outputFile: C:\reports\security-report-v1.14.0.pdf
```

## Common Security Findings (v1.14.0)

### Storage Accounts
- Public blob access enabled
- **NEW:** SAS tokens with excessive permissions (write/delete on public containers)
- **NEW:** WORM immutability NOT configured (production data at risk)
- Firewall rules not configured
- Missing secure transfer requirement (HTTPS-only)
- **NEW:** Missing lifecycle management policies

### Network Security Groups
- Open management ports (RDP 3389, SSH 22)
- Wildcard source rules (0.0.0.0/0)
- Database ports exposed to Internet
- **NEW:** Service endpoints overly broad (e.g., entire Azure Storage instead of specific accounts)
- **NEW:** Load balancer health probe ports blocked (MEDIUM risk)

### SQL & Database Services
- TDE encryption disabled
- Firewall allows all Azure services
- **NEW:** PostgreSQL public access enabled with weak SSL enforcement
- **NEW:** MySQL flexible servers missing firewall rules
- **NEW:** Redis Cache non-SSL port 6379 exposed (HIGH +30 risk)

### Key Vaults
- Soft delete disabled (data loss risk)
- Public network access enabled
- Missing diagnostic logging

### AKS Clusters
- RBAC not enabled
- API server publicly accessible
- Pods can access Instance Metadata Service (IMDS)

### Backup & Recovery (NEW)
- **Recovery Services Vault soft delete disabled** (30-day retention missing)
- **Immutable vault NOT configured** (CRITICAL +60 risk - ransomware exposure)
- Cross-region restore not enabled
- Azure Site Recovery (ASR) not configured for critical workloads

### Network Topology (NEW)
- **VNet peering with gateway transit enabled** (HIGH +30 risk)
- Cross-subscription peering without proper segmentation
- Cross-tenant peering detected (potential data exfiltration path)

### Private Endpoints (NEW)
- Private endpoint connections in "Pending" state
- Missing DNS configuration for Private Link
- Public access still enabled despite private endpoint deployment

### Logging & Compliance (NEW)
- **Diagnostic settings missing** on critical resources (HIGH +40 risk)
- Log Analytics workspace not configured
- NIST/CIS compliance gaps in logging coverage

### Service Principals & Managed Identities (ENHANCED)
- **Service principals with Owner/Contributor at subscription level** (HIGH risk)
- **Managed identities with cross-subscription access** (MEDIUM +20 risk)
- Federated credentials with overly broad trust policies (GitHub Actions)
- Application secrets expiring within 30 days

### Function Apps (ENHANCED)
- **Event Grid webhooks without batch configuration** (event flooding risk)
- **Service Bus SAS policies with Manage rights** (HIGH +30 risk)
- Plaintext connection strings in app settings (use Key Vault references)
- TLS version below 1.2

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Authentication failed** | Run `az login` and verify with `az account show` |
| **Subscription not found** | Check subscription ID format (GUID) |
| **Permission denied** | Request Reader/Security Reader role |
| **Tool not recognized** | Restart VS Code to reload MCP server |
| **Empty results** | Verify subscription ID, check resource filters |

## Tool Categories (40 Total - v1.14.0)

**Enumeration (7 tools):** enumerate_subscriptions, enumerate_resource_groups, enumerate_resources, enumerate_public_ips, enumerate_managed_identities (ENHANCED), enumerate_service_principals (ENHANCED), enumerate_rbac_assignments, get_resource_details

**Security Scanning (16 tools):**
- Core: analyze_storage_security (ENHANCED), analyze_nsg_rules (ENHANCED), scan_storage_containers, scan_sql_databases (ENHANCED), analyze_keyvault_security, analyze_vm_security, analyze_cosmosdb_security, scan_acr_security
- **NEW:** analyze_backup_security, analyze_vnet_peering, validate_private_endpoints, validate_diagnostic_settings

**Compute & Functions (2 tools):** analyze_function_apps (ENHANCED), analyze_app_service_security

**Network Security (2 tools):** analyze_firewall_policies, scan_cdn_security

**Kubernetes/AKS (3 tools):** scan_aks_full, scan_aks_policy_bypass, get_aks_credentials

**Attack Analysis (2 tools):** analyze_attack_paths, analyze_rbac_privesc

**Compliance & Governance (3 tools):**
- generate_security_report (ENHANCED)
- **NEW:** assess_defender_coverage, validate_policy_compliance

**DevOps Security (3 tools):** scan_azure_devops, scan_gitops_security, scan_container_apps_security

**Detection (2 tools):** detect_persistence_mechanisms, analyze_logic_apps

📚 **Complete tool list:** [README.md](README.md) | **Full changelog:** [CHANGELOG.md](CHANGELOG.md)

---
**Version:** 1.14.0 | **Total Tools:** 40 | **Last Updated:** February 21, 2026  
**MCP SDK Version:** 1.10.0+ | **Research Attribution:** Azure Security Benchmark v3, redskycyber/Cloud-Security
