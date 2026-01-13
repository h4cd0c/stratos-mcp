# Stratos - Azure Security Assessment MCP Server - Usage Guide

**Version:** 1.8.0 | **Total Tools:** 33

## Quick Start

Get comprehensive help with all 33 tools:
```bash
#mcp_stratos_help
```

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
| Storage Accounts | Microsoft.Storage/storageAccounts | Public access, encryption |
| Network Security Groups | Microsoft.Network/networkSecurityGroups | Firewall rules, open ports |
| Public IPs | Microsoft.Network/publicIPAddresses | Internet exposure |
| SQL Servers | Microsoft.Sql/servers | Authentication, TDE |
| Key Vaults | Microsoft.KeyVault/vaults | Access policies, soft delete |
| AKS Clusters | Microsoft.ContainerService/managedClusters | RBAC, network policies |
```bash
# Find all public IPs
#mcp_stratos_enumerate_resources
subscriptionId: <YOUR_SUBSCRIPTION_ID>
resourceType: Microsoft.Network/publicIPAddresses

# Find all storage accounts
#mcp_stratos_enumerate_resources
subscriptionId: <YOUR_SUBSCRIPTION_ID>
resourceType: Microsoft.Storage/storageAccounts

# Find all NSGs
#mcp_stratos_enumerate_resources
subscriptionId: <YOUR_SUBSCRIPTION_ID>
resourceType: Microsoft.Network/networkSecurityGroups
```

### Step 5: Deep Dive Analysis
```bash
#mcp_stratos_get_resource_details
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

## Professional Pentesting Workflow

### Phase 1: Discovery (Enumeration Tools)
```bash
#mcp_stratos_enumerate_subscriptions
#mcp_stratos_enumerate_public_ips subscriptionId: <sub-id>
#mcp_stratos_enumerate_rbac_assignments subscriptionId: <sub-id>
```

### Phase 2: Security Scanning
```bash
#mcp_stratos_analyze_storage_security subscriptionId: <sub-id>
#mcp_stratos_analyze_nsg_rules subscriptionId: <sub-id>
#mcp_stratos_scan_sql_databases subscriptionId: <sub-id>
```

### Phase 3: Attack Path Analysis
```bash
#mcp_stratos_analyze_attack_paths subscriptionId: <sub-id> startFrom: public-ips
```

### Phase 4: AKS Security Testing
```bash
#mcp_stratos_scan_aks_clusters subscriptionId: <sub-id>
#mcp_stratos_test_aks_imds_access subscriptionId: <sub-id> resourceGroup: <rg> clusterName: <aks>
```

### Phase 5: DevOps Security
```bash
#mcp_stratos_scan_azure_devops organizationUrl: https://dev.azure.com/yourorg personalAccessToken: <pat>
```

### Phase 6: Generate Report
```bash
#mcp_stratos_generate_security_report subscriptionId: <sub-id> format: pdf outputFile: C:\reports\security-report.pdf
```

## Common Security Findings

### Storage Accounts
- Public blob access enabled
- Firewall rules not configured
- Missing secure transfer requirement (HTTPS-only)

### Network Security Groups
- Open management ports (RDP 3389, SSH 22)
- Wildcard source rules (0.0.0.0/0)
- Database ports exposed to Internet

### Key Vaults
- Soft delete disabled (data loss risk)
- Public network access enabled
- Missing diagnostic logging

### AKS Clusters
- RBAC not enabled
- API server publicly accessible
- Pods can access Instance Metadata Service (IMDS)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Authentication failed** | Run `az login` and verify with `az account show` |
| **Subscription not found** | Check subscription ID format (GUID) |
| **Permission denied** | Request Reader/Security Reader role |
| **Tool not recognized** | Restart VS Code to reload MCP server |
| **Empty results** | Verify subscription ID, check resource filters |

## Tool Categories (25 Total)

**Enumeration (9 tools):** enumerate_subscriptions, enumerate_resource_groups, enumerate_resources, enumerate_public_ips, enumerate_managed_identities, enumerate_service_principals, enumerate_rbac_assignments, get_resource_details, enumerate_aks_identities

**Security Scanning (12 tools):** analyze_storage_security, analyze_nsg_rules, scan_storage_containers, scan_sql_databases, check_key_vault_security, analyze_vm_security, analyze_cosmos_db_security, check_container_registries, scan_aks_clusters, scan_aks_node_security, test_aks_imds_access, scan_azure_devops

**Attack Analysis (2 tools):** analyze_attack_paths, generate_security_report

**Offensive Tools (2 tools):** get_aks_credentials, test_aks_imds_access

📚 **Complete tool list:** [README.md](README.md)  
🔍 **Report examples:** [REPORT_STRUCTURE_EXAMPLE.md](REPORT_STRUCTURE_EXAMPLE.md)

---
**Version:** 1.8.0 | **Total Tools:** 33 | **Last Updated:** January 2026
- **MCP SDK Version:** 1.0.4
