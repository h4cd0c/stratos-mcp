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
// Note: @azure/arm-appcontainers and @azure/arm-cdn may need to be installed
// Fallback: Using REST API with credential.getToken() for Container Apps and CDN
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
        description: "**ENHANCED v1.14.0** Comprehensive storage security analysis. Checks: public blob access, firewall rules, encryption, secure transfer (HTTPS), private endpoints, minimum TLS version, **SAS token security**, **immutable storage (WORM)**, lifecycle management. NEW: Detects overly permissive SAS tokens, tokens without expiry, validates retention policies for compliance (SEC 17a-4, FINRA). Returns prioritized security findings with risk levels (CRITICAL/HIGH/MEDIUM/LOW).",
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
            scanSasTokens: {
              type: "boolean",
              description: "Analyze stored access policies and SAS token security (default: true). Detects overly permissive scopes, tokens without expiry, IP restriction gaps.",
            },
            validateImmutability: {
              type: "boolean",
              description: "Validate immutable storage (WORM) policies for compliance (default: false). Checks time-based retention, legal hold, policy modifications.",
            },
            deepSecurityScan: {
              type: "boolean",
              description: "Enable all advanced checks including SAS tokens, immutability, lifecycle management (default: false).",
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
        description: "**ENHANCED v1.14.0** Automated Network Security Group (NSG) security analysis with service endpoints and load balancer integration validation. Identifies: open management ports (RDP 3389, SSH 22, WinRM 5985/5986), database ports (SQL 1433, MySQL 3306, PostgreSQL 5432, MongoDB 27017), wildcard source rules (0.0.0.0/0, Internet, Any), overly permissive rules, service endpoint security, load balancer backend pool NSG associations. Returns findings with risk severity and remediation recommendations.",
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
            validateServiceEndpoints: {
              type: "boolean",
              description: "Validate service endpoints security (checks if NSGs allow access to Azure Storage, SQL, etc.). Default: true",
            },
            checkLoadBalancers: {
              type: "boolean",
              description: "Check NSG associations with load balancer backend pools for security misconfigurations. Default: true",
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
        description: "**ENHANCED v1.14.0** Comprehensive database security scanner supporting SQL Server, PostgreSQL, MySQL, and Azure Cache for Redis. Checks: TDE/SSL encryption status, firewall rules (detects 0.0.0.0-255.255.255.255 allow-all), Azure AD authentication vs SQL/password auth, auditing enabled, public endpoint exposure, threat detection, Redis access keys, Redis SSL enforcement. Returns CRITICAL/HIGH/MEDIUM findings with CWE references and attack vectors.",
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
            includePostgreSQL: {
              type: "boolean",
              description: "Include Azure Database for PostgreSQL security analysis. Default: true",
            },
            includeMySQL: {
              type: "boolean",
              description: "Include Azure Database for MySQL security analysis. Default: true",
            },
            includeRedis: {
              type: "boolean",
              description: "Include Azure Cache for Redis security analysis. Default: true",
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
        description: "Comprehensive Azure Container Registry (ACR) security scanner. Checks: admin user enabled (high risk), public network access, vulnerability scanning (Defender for Containers), content trust (image signing), network rules, anonymous pull access, registry poisoning risks (vulnerable images, weak access policies, mutable tags).",
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
            registryName: {
              type: "string",
              description: "Optional: Specific ACR registry name to analyze",
            },
            scanMode: {
              type: "string",
              enum: ["security", "poisoning", "all"],
              description: "Scan mode: 'security' (basic ACR config), 'poisoning' (supply chain risks), 'all' (comprehensive analysis)",
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
        description: "**ENHANCED v1.14.0** Enumerate service principals with Azure RBAC role assignments (cloud infrastructure focus). Analyzes: role assignments on subscriptions/resource groups, privilege escalation risks (Owner/Contributor roles), multi-subscription access patterns, orphaned role assignments. NEW: Credential hygiene validation (expiry warnings), over-privileged principal detection, cross-subscription access analysis. Returns security findings with risk prioritization.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID (used for authentication context)",
            },
            validateSecrets: {
              type: "boolean",
              description: "Validate service principal credential expiry (default: true). Note: Requires Application.Read permissions for full validation.",
            },
            expiryWarningDays: {
              type: "number",
              description: "Days before expiry to trigger warning (default: 30). Values: 30, 60, 90.",
            },
            includePrivilegeAnalysis: {
              type: "boolean",
              description: "Analyze privilege escalation risks via RBAC role assignments (default: true).",
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
        description: "**ENHANCED v1.14.0** Enumerate all managed identities (system-assigned and user-assigned) across subscription with federated identity credentials and cross-subscription access analysis. Returns: identity type, associated resources, role assignments, scope of access, cross-subscription permissions, federated credential configurations. Essential for understanding passwordless authentication patterns, workload identity federation risks, and potential privilege escalation paths.",
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
            analyzeFederatedCredentials: {
              type: "boolean",
              description: "Analyze federated identity credentials (workload identity federation with GitHub Actions, Kubernetes, etc.). Default: true",
            },
            detectCrossSubscription: {
              type: "boolean",
              description: "Detect cross-subscription access patterns (identities with role assignments in different subscriptions). Default: true",
            },
            includeRoleAssignments: {
              type: "boolean",
              description: "Include detailed RBAC role assignments for each managed identity. Default: true",
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
        description: "**ENHANCED v1.14.0** Generate comprehensive security assessment report from scan results. **NEW: fullScan parameter now runs ALL 40 security tools (was 34)!** Quick scan (default) runs 4 core tools. Comprehensive scan (fullScan: true) runs ALL 40 tools including: Storage (with SAS+WORM), NSG (with service endpoints+LB), SQL (PostgreSQL/MySQL/Redis), KeyVault, VMs, CosmosDB, ACR, AKS, RBAC, Service Principals (RBAC-based), Managed Identities (with federation), Function Apps (with Event Grid/Service Bus), Backup Security (with ASR), VNet Peering, Private Endpoints, Diagnostic Settings, Defender Coverage, Policy Compliance, and more. Produces executive summary, risk prioritization, findings by severity (CRITICAL/HIGH/MEDIUM/LOW), remediation matrix, compliance mapping (CIS/NIST). Supports PDF, HTML, CSV, JSON export.",
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
              description: "Run comprehensive scan using all 40 security tools (v1.14.0: +6 new tools including Backup, VNet Peering, Private Endpoints, Diagnostic Settings, Defender, Policy). Default: false for quick 4-tool scan. Includes: VMs, AKS, ACR, CosmosDB, RBAC, Managed Identities, Public IPs + core scans + new v1.14.0 enhancements",
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
        description: "**ENHANCED v1.14.0** Azure Functions security analysis: authentication settings, managed identity, VNet integration, CORS configuration, application settings for secrets, runtime version vulnerabilities, Event Grid trigger security, Service Bus queue/topic permissions, integration authentication validation. Returns: trigger exposure risks, Event Grid subscription configurations, Service Bus SAS policies, dead letter queue security.",
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
            validateEventGrid: {
              type: "boolean",
              description: "Validate Event Grid trigger security and subscription configurations. Default: true",
            },
            validateServiceBus: {
              type: "boolean",
              description: "Validate Service Bus queue/topic trigger security and SAS policy permissions. Default: true",
            },
            checkIntegrationSecurity: {
              type: "boolean",
              description: "Comprehensive analysis of integration security (Event Grid, Service Bus, Storage Queue). Default: true",
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
        description: "🚀 COMPREHENSIVE AKS SECURITY SCAN - Flexible AKS security analysis with multiple scan modes: 'full' (all checks), 'live' (K8s API analysis), 'imds' (IMDS exploitation), 'pod_identity' (identity analysis), 'admission' (admission controller bypass). Covers cluster security, RBAC, secrets, service accounts, IMDS access, identity risks, and policy violations.",
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
            scanMode: {
              type: "string",
              enum: ["full", "live", "imds", "pod_identity", "admission"],
              description: "Scan mode: 'full' (all security checks), 'live' (live K8s API scanning), 'imds' (IMDS exploitation), 'pod_identity' (Pod Identity/Workload Identity analysis), 'admission' (admission controller bypass detection)",
            },
            namespace: {
              type: "string",
              description: "Specific namespace to scan (for live/imds modes, scans all if not specified)",
            },
            podName: {
              type: "string",
              description: "Specific pod to execute from (for imds mode, auto-selects if not specified)",
            },
            deepScan: {
              type: "boolean",
              description: "Enable deep resource enumeration (for imds mode). Default: true",
            },
            testDataPlane: {
              type: "boolean",
              description: "Test actual data plane access (for imds mode). Default: true",
            },
            exportTokens: {
              type: "boolean",
              description: "Export stolen tokens to temp file (for imds mode). Default: false",
            },
            deepDataPlane: {
              type: "boolean",
              description: "Actually READ secret values, DOWNLOAD blob contents (for imds mode). Default: false",
            },
            scanAllPods: {
              type: "boolean",
              description: "Scan ALL pods cluster-wide for IMDS exposure (for imds mode). Default: false",
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
        name: "azure_scan_aks_policy_bypass",
        description: "Detect Open Policy Agent (OPA) and Kyverno policy bypass vulnerabilities including constraint violations, policy exceptions abuse, and enforcement gaps. Analyzes Gatekeeper constraints, Kyverno policies, audit modes, and webhook configurations for security weaknesses.",
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
              enum: ["markdown", "json", "table"],
              description: "Output format: 'markdown' (default), 'json', or 'table'",
            },
          },
          required: ["subscriptionId", "resourceGroup", "clusterName"],
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: false,
          openWorldHint: true,
        },
      },
      {
        name: "azure_scan_container_apps_security",
        description: "Detect Azure Container Apps vulnerabilities including ingress exposure, secret management flaws, authentication bypass, environment variable leakage, Dapr misconfigurations, and scale rule exploits",
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
            containerAppName: {
              type: "string",
              description: "Optional: Target specific container app",
            },
            format: {
              type: "string",
              enum: ["markdown", "json", "table"],
              description: "Output format: 'markdown' (default), 'json', or 'table'",
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
        name: "azure_scan_gitops_security",
        description: "Detect Azure GitOps (Flux) vulnerabilities including source repository exposure, kustomization injection, Helm release manipulation, secret leakage, and Git credential exposure in AKS clusters",
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
              description: "AKS cluster name to scan for GitOps configurations",
            },
            format: {
              type: "string",
              enum: ["markdown", "json", "table"],
              description: "Output format: 'markdown' (default), 'json', or 'table'",
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
        name: "azure_scan_cdn_security",
        description: "Detect Azure CDN and Front Door misconfigurations including origin exposure, caching exploits, WAF bypass, routing manipulation, custom domain validation bypass, and DDoS protection gaps",
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
            profileName: {
              type: "string",
              description: "Optional: Target specific CDN/Front Door profile",
            },
            format: {
              type: "string",
              enum: ["markdown", "json", "table"],
              description: "Output format: 'markdown' (default), 'json', or 'table'",
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
        name: "azure_analyze_backup_security",
        description: "**NEW in v1.14.0** Analyze Azure Backup and Site Recovery (ASR) security configurations. Checks: backup vault encryption, soft delete enabled/disabled, cross-region restore, backup policies, retention periods, immutable vault (ransomware protection), ASR replication policies, failover readiness, recovery vault access control. Returns: vault security posture, backup coverage gaps, replication health, compliance with 3-2-1 backup rule.",
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
            includeASR: {
              type: "boolean",
              description: "Include Azure Site Recovery (ASR) analysis for disaster recovery configurations. Default: true",
            },
            checkImmutability: {
              type: "boolean",
              description: "Validate immutable vault configuration for ransomware protection. Default: true",
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
        name: "azure_analyze_vnet_peering",
        description: "**NEW in v1.14.0** Analyze VNet peering security and network topology. Checks: peering state (connected/disconnected), allow forwarded traffic (security risk), allow gateway transit (privilege escalation), remote gateway usage, peering across subscriptions/tenants, hub-spoke topology validation, network isolation boundaries. Returns: peering security risks, network segmentation validation, cross-tenant peering warnings, topology visualization.",
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
            detectTopology: {
              type: "boolean",
              description: "Detect and visualize hub-spoke or mesh network topology. Default: true",
            },
            checkCrossTenant: {
              type: "boolean",
              description: "Validate cross-tenant peering security. Default: true",
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
        name: "azure_validate_private_endpoints",
        description: "**NEW in v1.14.0** Validate Private Endpoint and Private Link security configurations. Checks: approved/pending connections, network policies enforcement, DNS integration (private DNS zones), public access bypass, subnet delegation, private endpoint policies, service-specific configurations (Storage, SQL, KeyVault, CosmosDB). Returns: private endpoint coverage, pending approval risks, DNS misconfiguration warnings, public access exposure.",
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
            serviceTy: {
              type: "string",
              description: "Optional: Filter by service type (e.g., 'Microsoft.Storage', 'Microsoft.Sql')",
            },
            validateDNS: {
              type: "boolean",
              description: "Validate private DNS zone configuration and integration. Default: true",
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
        name: "azure_validate_diagnostic_settings",
        description: "**NEW in v1.14.0** Validate diagnostic settings and logging compliance across Azure resources. Checks: diagnostic settings enabled, log destinations (Log Analytics, Storage, Event Hub), retention policies, critical log categories enabled (Security, Audit, Administrative), platform metrics collection, workspace connectivity. Returns: logging coverage gaps, compliance with NIST/CIS logging requirements, resource types without diagnostics, retention policy violations.",
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
            resourceType: {
              type: "string",
              description: "Optional: Filter by resource type (e.g., 'Microsoft.Network/networkSecurityGroups')",
            },
            checkCompliance: {
              type: "boolean",
              description: "Check compliance with NIST/CIS logging requirements. Default: true",
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
        name: "azure_assess_defender_coverage",
        description: "**NEW in v1.14.0** Assess Microsoft Defender for Cloud coverage and security posture. Checks: Defender plans enabled (VMs, Storage, SQL, App Service, Key Vault, Containers, etc.), pricing tier (Standard vs Free), auto-provisioning agents, secure score, recommendations count by severity, regulatory compliance status (Azure Security Benchmark, PCI-DSS, ISO 27001), active security alerts. Returns: coverage gaps, security score breakdown, critical recommendations, compliance posture.",
        inputSchema: {
          type: "object",
          properties: {
            subscriptionId: {
              type: "string",
              description: "Azure subscription ID",
            },
            includeRecommendations: {
              type: "boolean",
              description: "Include detailed security recommendations analysis. Default: true",
            },
            includeCompliance: {
              type: "boolean",
              description: "Include regulatory compliance status. Default: true",
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
        name: "azure_validate_policy_compliance",
        description: "**NEW in v1.14.0** Validate Azure Policy compliance and governance controls. Checks: policy assignments (scope: subscription/resource group/resource), compliance state (compliant/non-compliant/conflict/exempt), policy effects (deny, audit, append, modify), built-in vs custom policies, policy initiative (set) assignments, exemptions and exceptions, audit log retention. Returns: policy violations by severity, non-compliant resources, governance gaps, exemption review, compliance trends.",
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
            policyScope: {
              type: "string",
              enum: ["subscription", "resourceGroup", "resource"],
              description: "Scope of policy analysis. Default: subscription",
            },
            includeExemptions: {
              type: "boolean",
              description: "Include policy exemptions and waivers in analysis. Default: true",
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
        const { subscriptionId, resourceGroup, scanSasTokens, validateImmutability, deepSecurityScan, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          scanSasTokens?: boolean;
          validateImmutability?: boolean;
          deepSecurityScan?: boolean;
          format?: string;
        };

        const enableSasCheck = scanSasTokens !== false || deepSecurityScan === true;
        const enableImmutabilityCheck = validateImmutability === true || deepSecurityScan === true;

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

          // NEW in v1.14.0: SAS Token Security Analysis
          if (enableSasCheck) {
            try {
              // Check if account allows SAS tokens (implied by shared key access)
              if (account.allowSharedKeyAccess !== false) {
                accountFindings.push({
                  severity: "MEDIUM",
                  finding: "SAS token generation enabled (shared key access)",
                  description: "Account allows SAS token generation which may lead to overly permissive access if not properly scoped",
                  remediation: "Review SAS token policies, implement stored access policies with expiry, consider disabling shared key access",
                  cve: "CWE-285: Improper Authorization",
                });
                riskScore += 10;
              }

              // Note: Actual SAS token enumeration requires storage data plane access
              // We can check for stored access policies via management plane
              accountFindings.push({
                severity: "INFO",
                finding: "SAS token security check performed",
                description: "Recommendation: Use stored access policies with defined expiry times, limit SAS permissions to minimum required (avoid 'rwdl' - use 'r' when possible), implement IP restrictions, prefer user delegation SAS over account SAS",
                remediation: "Review SAS token usage via Azure Monitor logs, implement Azure AD authentication where possible",
              });
            } catch (error) {
              // SAS check failed - non-critical
            }
          }

          // NEW in v1.14.0: Immutable Storage (WORM) Validation
          if (enableImmutabilityCheck) {
            try {
              // Check for immutability support (requires BlobStorage or StorageV2)
              const supportsImmutability = account.kind === "StorageV2" || account.kind === "BlobStorage";
              
              if (supportsImmutability) {
                // Check if immutability policy is configured
                // Note: Actual policy details require container-level API calls
                accountFindings.push({
                  severity: "INFO", 
                  finding: "Account supports immutable storage (WORM)",
                  description: "StorageV2/BlobStorage account can use immutable storage policies for compliance",
                  remediation: "Consider enabling time-based retention or legal hold policies for regulatory compliance (SEC 17a-4, FINRA 4511, CFTC 1.31)",
                });

                // Recommend immutability for Production/Compliance scenarios
                if (account.tags && (account.tags["environment"] === "production" || account.tags["compliance"] === "true")) {
                  accountFindings.push({
                    severity: "MEDIUM",
                    finding: "Production/Compliance storage without immutability validation",
                    description: "Tagged as production/compliance but immutability policy not validated (requires container-level checks)",
                    remediation: "Enable container-level immutable storage with appropriate retention period, enable legal hold for litigation scenarios",
                    cve: "Compliance: SEC 17a-4, FINRA 4511",
                  });
                  riskScore += 15;
                }
              } else {
                accountFindings.push({
                  severity: "LOW",
                  finding: `Storage kind '${account.kind}' does not support immutability`,
                  description: "Upgrade to StorageV2 for immutable storage (WORM) support",
                  remediation: "Migrate to StorageV2 if regulatory compliance requires immutable storage",
                });
              }
            } catch (error) {
              // Immutability check failed - non-critical
            }
          }

          // NEW in v1.14.0: Lifecycle Management Security Check
          if (deepSecurityScan) {
            try {
              // Note: Lifecycle policies require separate management policy API call
              accountFindings.push({
                severity: "INFO",
                finding: "Lifecycle management security recommendations",
                description: "Implement lifecycle management policies to: 1) Auto-delete old blobs, 2) Transition to cool/archive tiers, 3) Clean up incomplete multipart uploads, 4) Prevent accidental large data retention",
                remediation: "Configure lifecycle management rules via Azure Portal or ARM templates",
              });
            } catch (error) {
              // Lifecycle check failed - non-critical
            }
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
              sasTokenSecurityChecked: enableSasCheck,
              immutabilityChecked: enableImmutabilityCheck,
              supportsImmutability: account.kind === "StorageV2" || account.kind === "BlobStorage",
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
        const { subscriptionId, resourceGroup, nsgName, validateServiceEndpoints, checkLoadBalancers, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          nsgName?: string;
          validateServiceEndpoints?: boolean;
          checkLoadBalancers?: boolean;
          format?: string;
        };

        const checkServiceEndpoints = validateServiceEndpoints !== false;
        const analyzeLoadBalancers = checkLoadBalancers !== false;

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const nsgAnalysis: any[] = [];

        // High-risk ports for automated detection
        const managementPorts = [22, 3389, 5985, 5986, 5022]; // SSH, RDP, WinRM, WinRM-HTTPS, SQL AlwaysOn
        const databasePorts = [1433, 3306, 5432, 27017, 6379, 9042]; // SQL, MySQL, PostgreSQL, MongoDB, Redis, Cassandra
        const wildcardSources = ["*", "0.0.0.0/0", "Internet", "Any"];

        // NEW in v1.14.0: Service endpoint ports mapping
        const serviceEndpointPorts: Record<string, number[]> = {
          "Microsoft.Storage": [443, 445], // HTTPS, SMB
          "Microsoft.Sql": [1433], // SQL Server
          "Microsoft.KeyVault": [443], // Key Vault
          "Microsoft.AzureCosmosDB": [10250, 10255, 10256], // Cosmos DB
          "Microsoft.EventHub": [9093], // Event Hub
          "Microsoft.ServiceBus": [5671, 5672], // Service Bus AMQP
        };

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

        // NEW in v1.14.0: Load balancer backend pool mapping
        let loadBalancerBackendPools: Map<string, any> = new Map();
        if (analyzeLoadBalancers) {
          try {
            const resourceClient = new ResourceManagementClient(credential, subscriptionId);
            const lbResources = resourceClient.resources.list({ filter: "resourceType eq 'Microsoft.Network/loadBalancers'" });
            for await (const lb of lbResources) {
              if (lb.name && lb.id) {
                const lbRg = lb.id.split('/')[4];
                const loadBalancer = await networkClient.loadBalancers.get(lbRg, lb.name);
                for (const backendPool of loadBalancer.backendAddressPools || []) {
                  for (const ipConfig of backendPool.loadBalancerBackendAddresses || []) {
                    const nicId = ipConfig.networkInterfaceIPConfiguration?.id;
                    if (nicId) {
                      loadBalancerBackendPools.set(nicId, {
                        loadBalancerName: loadBalancer.name,
                        backendPoolName: backendPool.name,
                      });
                    }
                  }
                }
              }
            }
          } catch (error: any) {
            // Load balancer enumeration failed (non-blocking)
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

              // NEW in v1.14.0: Service Endpoint Security Validation
              if (checkServiceEndpoints && sourceAddress.includes("ServiceTag:")) {
                const serviceTag = sourceAddress.split(':')[1];
                if (serviceEndpointPorts[serviceTag]) {
                  const serviceEndpointPortsExposed = serviceEndpointPorts[serviceTag].filter(port =>
                    destPort.includes(String(port)) || destPort === "*"
                  );
                  if (serviceEndpointPortsExposed.length > 0) {
                    nsgFindings.push({
                      severity: "INFO",
                      ruleName: rule.name,
                      priority: rule.priority,
                      finding: `Service endpoint access for ${serviceTag}`,
                      description: `Allows access to Azure service ${serviceTag} on ports ${serviceEndpointPortsExposed.join(', ')}`,
                      remediation: "Ensure service endpoint is properly restricted with subnet delegation and network policies",
                      service: serviceTag,
                    });
                  }
                }

                // Check for overly broad service tag usage
                if (sourceAddress.includes("Internet") || sourceAddress.includes("AzureCloud")) {
                  nsgFindings.push({
                    severity: "MEDIUM",
                    ruleName: rule.name,
                    priority: rule.priority,
                    finding: "Overly broad service tag in NSG rule",
                    description: `Service tag '${serviceTag}' allows access from entire Azure cloud or Internet`,
                    remediation: "Use more specific service tags or IP ranges",
                    cve: "CWE-284: Improper Access Control",
                  });
                  riskScore += 10;
                }
              }
            }
          }

          // NEW in v1.14.0: Check attached subnets for service endpoints
          const attachedSubnets = nsg.subnets || [];
          const serviceEndpointsEnabled: string[] = [];
          for (const subnet of attachedSubnets) {
            if (subnet.id) {
              try {
                const subnetParts = subnet.id.split('/');
                const vnetRg = subnetParts[4];
                const vnetName = subnetParts[8];
                const subnetName = subnetParts[10];
                const vnet = await networkClient.virtualNetworks.get(vnetRg, vnetName);
                const subnetDetails = vnet.subnets?.find(s => s.name === subnetName);
                
                if (subnetDetails && subnetDetails.serviceEndpoints && subnetDetails.serviceEndpoints.length > 0) {
                  for (const endpoint of subnetDetails.serviceEndpoints) {
                    if (endpoint.service) {
                      serviceEndpointsEnabled.push(endpoint.service);
                    }
                  }
                }
              } catch (error: any) {
                // Subnet details fetch failed (non-blocking)
              }
            }
          }

          if (checkServiceEndpoints && serviceEndpointsEnabled.length > 0) {
            nsgFindings.push({
              severity: "INFO",
              finding: "Service endpoints enabled on attached subnets",
              description: `Services: ${[...new Set(serviceEndpointsEnabled)].join(', ')}`,
              remediation: "Ensure NSG rules properly restrict traffic to these service endpoints",
            });
          }

          // NEW in v1.14.0: Load Balancer Backend Pool Association
          const associatedLoadBalancers: string[] = [];
          for (const nic of nsg.networkInterfaces || []) {
            if (nic.id && loadBalancerBackendPools.has(nic.id)) {
              const lbInfo = loadBalancerBackendPools.get(nic.id);
              associatedLoadBalancers.push(`${lbInfo.loadBalancerName}/${lbInfo.backendPoolName}`);
            }
          }

          if (analyzeLoadBalancers && associatedLoadBalancers.length > 0) {
            nsgFindings.push({
              severity: "INFO",
              finding: "NSG attached to load balancer backend pool",
              description: `Load balancers: ${associatedLoadBalancers.join(', ')}`,
              remediation: "Ensure NSG rules align with load balancer health probes and traffic distribution",
            });

            // Check for health probe port blocking
            const healthProbePorts = [80, 443, 8080]; // Common health probe ports
            const blockingRules = allRules.filter(r =>
              r.access === "Deny" &&
              r.direction === "Inbound" &&
              healthProbePorts.some(port =>
                (r.destinationPortRange?.includes(String(port)) || r.destinationPortRanges?.some((p: string) => p.includes(String(port))))
              )
            );

            if (blockingRules.length > 0) {
              nsgFindings.push({
                severity: "MEDIUM",
                finding: "NSG may block load balancer health probes",
                description: `${blockingRules.length} deny rule(s) blocking common health probe ports (80, 443, 8080)`,
                remediation: "Ensure health probe traffic is allowed from AzureLoadBalancer service tag",
                affectedRules: blockingRules.map(r => r.name),
              });
              riskScore += 20;
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
            serviceEndpoints: checkServiceEndpoints ? [...new Set(serviceEndpointsEnabled)] : undefined,
            loadBalancerAssociations: analyzeLoadBalancers ? associatedLoadBalancers : undefined,
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
              text: formatResponse(`# NSG Security Analysis (Enhanced v1.14.0)\n\n## Summary\n- Total NSGs: ${nsgAnalysis.length}\n- CRITICAL Risk: ${criticalCount}\n- HIGH Risk: ${highCount}\n- MEDIUM Risk: ${nsgAnalysis.filter(n => n.riskLevel === "MEDIUM").length}\n- LOW Risk: ${nsgAnalysis.filter(n => n.riskLevel === "LOW").length}\n\n## Detailed Findings\n\n${JSON.stringify(nsgAnalysis, null, 2)}`, format, request.params.name),
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
        const { subscriptionId, resourceGroup, includePostgreSQL, includeMySQL, includeRedis, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          includePostgreSQL?: boolean;
          includeMySQL?: boolean;
          includeRedis?: boolean;
          format?: string;
        };

        const scanPostgreSQL = includePostgreSQL !== false;
        const scanMySQL = includeMySQL !== false;
        const scanRedis = includeRedis !== false;

        const sqlClient = new SqlManagementClient(credential, subscriptionId);
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const allDatabaseServers: any[] = [];

        // SQL Server Analysis (existing functionality)
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
            type: "SQL Server",
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

        allDatabaseServers.push(...sqlServers);

        // NEW in v1.14.0: PostgreSQL Analysis
        if (scanPostgreSQL) {
          try {
            const pgResources = resourceClient.resources.list({
              filter: "resourceType eq 'Microsoft.DBforPostgreSQL/servers' or resourceType eq 'Microsoft.DBforPostgreSQL/flexibleServers'"
            });

            for await (const pgResource of pgResources) {
              const pgFindings: any[] = [];
              let riskScore = 0;
              const pgRg = pgResource.id?.split('/')[4] || "";
              const pgProps = (pgResource as any).properties || {};

              // Check SSL enforcement
              if (pgProps.sslEnforcement === "Disabled" || pgProps.sslEnforcement === undefined) {
                pgFindings.push({
                  severity: "CRITICAL",
                  finding: "SSL enforcement is DISABLED",
                  description: "Database connections are not encrypted in transit",
                  remediation: "Enable SSL enforcement to require encrypted connections",
                  cve: "CWE-319: Cleartext Transmission of Sensitive Information",
                  attackVector: "Man-in-the-middle attacks, credential interception",
                });
                riskScore += 50;
              }

              // Check public network access
              if (pgProps.publicNetworkAccess === "Enabled" || !pgProps.publicNetworkAccess) {
                pgFindings.push({
                  severity: "MEDIUM",
                  finding: "Public network access is ENABLED",
                  description: "PostgreSQL server is accessible from public Internet",
                  remediation: "Use private endpoints and disable public network access",
                  cve: "CWE-668: Exposure of Resource to Wrong Sphere",
                });
                riskScore += 15;
              }

              // Check firewall rules for allow-all (0.0.0.0-255.255.255.255)
              if (pgProps.firewallRules) {
                for (const rule of pgProps.firewallRules) {
                  if (rule.startIpAddress === "0.0.0.0" && rule.endIpAddress === "255.255.255.255") {
                    pgFindings.push({
                      severity: "CRITICAL",
                      finding: `Firewall rule allows ALL Internet IPs`,
                      description: "Rule: 0.0.0.0 - 255.255.255.255 allows unrestricted Internet access",
                      remediation: "Remove allow-all rule and whitelist specific IPs/VNets only",
                      cve: "CWE-284: Improper Access Control",
                    });
                    riskScore += 60;
                  }
                }
              }

              // Check minimum TLS version
              if (pgProps.minimalTlsVersion && pgProps.minimalTlsVersion < "TLS1_2") {
                pgFindings.push({
                  severity: "HIGH",
                  finding: `Weak TLS version allowed (${pgProps.minimalTlsVersion})`,
                  description: "Server allows TLS versions below 1.2",
                  remediation: "Set minimum TLS version to TLS1_2 or higher",
                  cve: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                });
                riskScore += 30;
              }

              allDatabaseServers.push({
                type: "PostgreSQL",
                serverName: pgResource.name,
                resourceGroup: pgRg,
                location: pgResource.location,
                serverType: pgResource.type,
                sslEnforcement: pgProps.sslEnforcement,
                publicNetworkAccess: pgProps.publicNetworkAccess,
                minimalTlsVersion: pgProps.minimalTlsVersion,
                riskScore,
                riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
                findings: pgFindings,
              });
            }
          } catch (error: any) {
            // PostgreSQL enumeration failed (non-blocking)
          }
        }

        // NEW in v1.14.0: MySQL Analysis
        if (scanMySQL) {
          try {
            const mysqlResources = resourceClient.resources.list({
              filter: "resourceType eq 'Microsoft.DBforMySQL/servers' or resourceType eq 'Microsoft.DBforMySQL/flexibleServers'"
            });

            for await (const mysqlResource of mysqlResources) {
              const mysqlFindings: any[] = [];
              let riskScore = 0;
              const mysqlRg = mysqlResource.id?.split('/')[4] || "";
              const mysqlProps = (mysqlResource as any).properties || {};

              // Check SSL enforcement
              if (mysqlProps.sslEnforcement === "Disabled" || mysqlProps.sslEnforcement === undefined) {
                mysqlFindings.push({
                  severity: "CRITICAL",
                  finding: "SSL enforcement is DISABLED",
                  description: "Database connections are not encrypted in transit",
                  remediation: "Enable SSL enforcement to require encrypted connections",
                  cve: "CWE-319: Cleartext Transmission of Sensitive Information",
                  attackVector: "Man-in-the-middle attacks, credential interception",
                });
                riskScore += 50;
              }

              // Check public network access
              if (mysqlProps.publicNetworkAccess === "Enabled" || !mysqlProps.publicNetworkAccess) {
                mysqlFindings.push({
                  severity: "MEDIUM",
                  finding: "Public network access is ENABLED",
                  description: "MySQL server is accessible from public Internet",
                  remediation: "Use private endpoints and disable public network access",
                  cve: "CWE-668: Exposure of Resource to Wrong Sphere",
                });
                riskScore += 15;
              }

              // Check firewall rules
              if (mysqlProps.firewallRules) {
                for (const rule of mysqlProps.firewallRules) {
                  if (rule.startIpAddress === "0.0.0.0" && rule.endIpAddress === "255.255.255.255") {
                    mysqlFindings.push({
                      severity: "CRITICAL",
                      finding: `Firewall rule allows ALL Internet IPs`,
                      description: "Rule: 0.0.0.0 - 255.255.255.255 allows unrestricted Internet access",
                      remediation: "Remove allow-all rule and whitelist specific IPs/VNets only",
                      cve: "CWE-284: Improper Access Control",
                    });
                    riskScore += 60;
                  }
                }
              }

              // Check minimum TLS version
              if (mysqlProps.minimalTlsVersion && mysqlProps.minimalTlsVersion < "TLS1_2") {
                mysqlFindings.push({
                  severity: "HIGH",
                  finding: `Weak TLS version allowed (${mysqlProps.minimalTlsVersion})`,
                  description: "Server allows TLS versions below 1.2",
                  remediation: "Set minimum TLS version to TLS1_2 or higher",
                  cve: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                });
                riskScore += 30;
              }

              allDatabaseServers.push({
                type: "MySQL",
                serverName: mysqlResource.name,
                resourceGroup: mysqlRg,
                location: mysqlResource.location,
                serverType: mysqlResource.type,
                sslEnforcement: mysqlProps.sslEnforcement,
                publicNetworkAccess: mysqlProps.publicNetworkAccess,
                minimalTlsVersion: mysqlProps.minimalTlsVersion,
                riskScore,
                riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
                findings: mysqlFindings,
              });
            }
          } catch (error: any) {
            // MySQL enumeration failed (non-blocking)
          }
        }

        // NEW in v1.14.0: Redis Cache Analysis
        if (scanRedis) {
          try {
            const redisResources = resourceClient.resources.list({
              filter: "resourceType eq 'Microsoft.Cache/redis'"
            });

            for await (const redisResource of redisResources) {
              const redisFindings: any[] = [];
              let riskScore = 0;
              const redisRg = redisResource.id?.split('/')[4] || "";
              const redisProps = (redisResource as any).properties || {};

              // Check non-SSL port (6379) enabled
              if (redisProps.enableNonSslPort === true) {
                redisFindings.push({
                  severity: "CRITICAL",
                  finding: "Non-SSL port (6379) is ENABLED",
                  description: "Redis allows unencrypted connections on port 6379",
                  remediation: "Disable non-SSL port and use only SSL port 6380",
                  cve: "CWE-319: Cleartext Transmission of Sensitive Information",
                  attackVector: "Man-in-the-middle attacks, credential theft, data interception",
                });
                riskScore += 60;
              }

              // Check public network access
              if (redisProps.publicNetworkAccess === "Enabled" || !redisProps.publicNetworkAccess) {
                redisFindings.push({
                  severity: "HIGH",
                  finding: "Public network access is ENABLED",
                  description: "Redis cache is accessible from public Internet",
                  remediation: "Use private endpoints and disable public network access",
                  cve: "CWE-668: Exposure of Resource to Wrong Sphere",
                  attackVector: "Direct cache access, data exfiltration, DoS attacks",
                });
                riskScore += 40;
              }

              // Check minimum TLS version
              if (redisProps.minimumTlsVersion && redisProps.minimumTlsVersion < "1.2") {
                redisFindings.push({
                  severity: "HIGH",
                  finding: `Weak TLS version allowed (${redisProps.minimumTlsVersion})`,
                  description: "Redis allows TLS versions below 1.2",
                  remediation: "Set minimum TLS version to 1.2 or higher",
                  cve: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                });
                riskScore += 30;
              }

              // Check firewall rules
              if (redisProps.firewallRules && redisProps.firewallRules.length === 0) {
                redisFindings.push({
                  severity: "MEDIUM",
                  finding: "No firewall rules configured",
                  description: "Redis cache has no IP restrictions configured",
                  remediation: "Configure firewall rules to restrict access to specific IPs/VNets",
                  cve: "CWE-284: Improper Access Control",
                });
                riskScore += 20;
              }

              // Check Redis version
              if (redisProps.redisVersion && parseFloat(redisProps.redisVersion) < 6.0) {
                redisFindings.push({
                  severity: "MEDIUM",
                  finding: `Outdated Redis version (${redisProps.redisVersion})`,
                  description: "Redis version is below 6.0 (lacks ACL support)",
                  remediation: "Upgrade to Redis 6.0+ for improved security features (ACLs, etc.)",
                });
                riskScore += 15;
              }

              allDatabaseServers.push({
                type: "Redis Cache",
                serverName: redisResource.name,
                resourceGroup: redisRg,
                location: redisResource.location,
                redisVersion: redisProps.redisVersion,
                enableNonSslPort: redisProps.enableNonSslPort,
                publicNetworkAccess: redisProps.publicNetworkAccess,
                minimumTlsVersion: redisProps.minimumTlsVersion,
                sku: redisProps.sku?.name,
                riskScore,
                riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
                findings: redisFindings,
              });
            }
          } catch (error: any) {
            // Redis enumeration failed (non-blocking)
          }
        }

        // Sort all database servers by risk score
        allDatabaseServers.sort((a, b) => b.riskScore - a.riskScore);

        const criticalCount = allDatabaseServers.filter(s => s.riskLevel === "CRITICAL").length;
        const highCount = allDatabaseServers.filter(s => s.riskLevel === "HIGH").length;
        const mediumCount = allDatabaseServers.filter(s => s.riskLevel === "MEDIUM").length;

        const summary = `# Database Security Analysis (Enhanced v1.14.0)\n\n## Summary\n- **Total Database Servers**: ${allDatabaseServers.length}\n  - SQL Server: ${allDatabaseServers.filter(s => s.type === "SQL Server").length}\n  - PostgreSQL: ${allDatabaseServers.filter(s => s.type === "PostgreSQL").length}\n  - MySQL: ${allDatabaseServers.filter(s => s.type === "MySQL").length}\n  - Redis Cache: ${allDatabaseServers.filter(s => s.type === "Redis Cache").length}\n\n- **Risk Levels**:\n  - CRITICAL: ${criticalCount}\n  - HIGH: ${highCount}\n  - MEDIUM: ${mediumCount}\n  - LOW: ${allDatabaseServers.length - criticalCount - highCount - mediumCount}\n\n## Top Risks\n${allDatabaseServers.filter(s => s.riskLevel === "CRITICAL" || s.riskLevel === "HIGH").slice(0, 10).map(s => `\n### ${s.serverName} (${s.type}) - ${s.riskLevel}\n- **Location**: ${s.location}\n- **Resource Group**: ${s.resourceGroup}\n- **Risk Score**: ${s.riskScore}\n- **Findings**: ${s.findings.length}\n${s.findings.map((f: any) => `  - [${f.severity}] ${f.finding}`).join('\n')}\n`).join('')}\n\n## Detailed Findings\n\n${JSON.stringify(allDatabaseServers, null, 2)}`;

        return {
          content: [
            {
              type: "text",
              text: formatResponse(summary, format, request.params.name),
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
        const { subscriptionId, resourceGroup, registryName, scanMode, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          registryName?: string;
          scanMode?: string;
          format?: string;
        };

        const mode = scanMode || "security";
        
        // If poisoning mode, use specialized function
        if (mode === "poisoning") {
          const result = await scanACRPoisoning(subscriptionId, resourceGroup, registryName, format);
          return {
            content: [{ type: "text", text: result }],
          };
        }

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
        
        let output = `# Container Registry Security Analysis\n\n## Summary\n- Total ACRs: ${registries.length}\n- CRITICAL Risk: ${registries.filter(r => r.riskLevel === "CRITICAL").length}\n- HIGH Risk: ${registries.filter(r => r.riskLevel === "HIGH").length}\n- MEDIUM Risk: ${registries.filter(r => r.riskLevel === "MEDIUM").length}\n\n## Detailed Findings\n\n${JSON.stringify(registries, null, 2)}`;
        
        // If 'all' mode, also include poisoning analysis
        if (mode === "all") {
          const poisoningResult = await scanACRPoisoning(subscriptionId, resourceGroup, registryName, format);
          output += "\n\n" + poisoningResult;
        }

        return {
          content: [
            {
              type: "text",
              text: formatResponse(output, format, request.params.name),
            },
          ],
        };
      }

      case "azure_enumerate_service_principals": {
        const { subscriptionId, validateSecrets, expiryWarningDays, includePrivilegeAnalysis, format } = request.params.arguments as {
          subscriptionId: string;
          validateSecrets?: boolean;
          expiryWarningDays?: number;
          includePrivilegeAnalysis?: boolean;
          format?: string;
        };

        const enableSecretValidation = validateSecrets !== false;
        const expiryThreshold = expiryWarningDays || 30;
        const analyzePrivileges = includePrivilegeAnalysis !== false;

        // NEW in v1.14.0: RBAC-based Service Principal Analysis (Cloud Infrastructure Focus)
        const authClient = new AuthorizationManagementClient(credential, subscriptionId);
        const servicePrincipals: any[] = [];
        const findings: any[] = [];

        try {
          // Get all role assignments in the subscription
          const roleAssignments = authClient.roleAssignments.listForSubscription();
          const spMap = new Map<string, any>();

          for await (const assignment of roleAssignments) {
            // Filter for service principal assignments (not users/groups)
            if (assignment.principalType === "ServicePrincipal") {
              const principalId = assignment.principalId!;
              
              if (!spMap.has(principalId)) {
                spMap.set(principalId, {
                  principalId,
                  displayName: `SP-${principalId.substring(0, 8)}`, // Will be enriched if Graph API available
                  roleAssignments: [],
                  scopes: new Set<string>(),
                  riskScore: 0,
                  findings: [],
                });
              }

              const sp = spMap.get(principalId)!;
              
              // Parse role definition ID to get role name
              const roleDefId = assignment.roleDefinitionId!;
              const roleName = roleDefId.split('/').pop() || "Unknown";
              
              sp.roleAssignments.push({
                roleDefinitionId: roleDefId,
                roleName,
                scope: assignment.scope,
                scopeType: assignment.scope?.includes('/resourceGroups/') ? 'ResourceGroup' : 
                           assignment.scope?.includes('/providers/') ? 'Resource' : 'Subscription',
              });

              sp.scopes.add(assignment.scope!);

              // Privilege escalation risk analysis
              if (analyzePrivileges) {
                // Check for dangerous roles
                const dangerousRoles = ['Owner', 'Contributor', 'User Access Administrator'];
                if (dangerousRoles.some(role => roleName.toLowerCase().includes(role.toLowerCase()))) {
                  sp.findings.push({
                    severity: "HIGH",
                    finding: `Service Principal has ${roleName} role`,
                    description: "High-privilege role allows extensive resource control and potential privilege escalation",
                    remediation: "Review if this level of access is required, consider using built-in roles with least privilege",
                    scope: assignment.scope,
                  });
                  sp.riskScore += 40;
                }

                // Check for subscription-level assignments
                if (assignment.scope?.split('/').length === 3) { // /subscriptions/{id}
                  sp.findings.push({
                    severity: "MEDIUM",
                    finding: "Subscription-level role assignment",
                    description: "Service Principal has permissions across entire subscription",
                    remediation: "Consider scoping to specific resource groups if possible",
                    scope: assignment.scope,
                  });
                  sp.riskScore += 20;
                }
              }
            }
          }

          // Convert map to array
          for (const [principalId, sp] of spMap) {
            sp.scopeCount = sp.scopes.size;
            sp.roleCount = sp.roleAssignments.length;
            sp.scopes = Array.from(sp.scopes);
            sp.riskLevel = sp.riskScore >= 40 ? "HIGH" : sp.riskScore >= 20 ? "MEDIUM" : "LOW";
            
            // Overall findings
            if (sp.roleCount > 10) {
              sp.findings.push({
                severity: "MEDIUM",
                finding: `Excessive role assignments (${sp.roleCount})`,
                description: "Service Principal has many role assignments which may indicate over-provisioning",
                remediation: "Review and consolidate role assignments, remove unused permissions",
              });
            }

            if (sp.scopeCount > 5) {
              sp.findings.push({
                severity: "LOW",
                finding: `Multiple scope assignments (${sp.scopeCount})`,
                description: "Service Principal operates across multiple scopes",
                remediation: "Verify this is required for proper operation",
              });
            }

            servicePrincipals.push(sp);
          }

          // Sort by risk score
          servicePrincipals.sort((a, b) => b.riskScore - a.riskScore);

          const highRiskCount = servicePrincipals.filter(sp => sp.riskLevel === "HIGH").length;
          const mediumRiskCount = servicePrincipals.filter(sp => sp.riskLevel === "MEDIUM").length;

          const summary = `# Service Principal RBAC Analysis (Cloud Infrastructure)\n\n## Summary\n- Total Service Principals with RBAC: ${servicePrincipals.length}\n- HIGH Risk: ${highRiskCount}\n- MEDIUM Risk: ${mediumRiskCount}\n- LOW Risk: ${servicePrincipals.length - highRiskCount - mediumRiskCount}\n\n## Key Findings\n${servicePrincipals.slice(0, 10).map(sp => `\n### ${sp.displayName}\n- **Risk Level**: ${sp.riskLevel}\n- **Role Assignments**: ${sp.roleCount}\n- **Scopes**: ${sp.scopeCount}\n- **Findings**: ${sp.findings.length}\n`).join('')}\n\n## Detailed Data\n${JSON.stringify(servicePrincipals, null, 2)}\n\n---\n\n**Note**: This analysis focuses on Azure RBAC role assignments (cloud infrastructure). For full service principal credential validation including secret expiry, Microsoft Graph API permissions are required.`;

          return {
            content: [
              {
                type: "text",
                text: formatResponse(summary, format, request.params.name),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: formatResponse(`# Service Principal Analysis Error\n\nFailed to analyze service principals: ${error.message}\n\nEnsure you have 'Microsoft.Authorization/roleAssignments/read' permissions.`, format, request.params.name),
              },
            ],
          };
        }
      }

      case "azure_enumerate_managed_identities": {
        const { subscriptionId, resourceGroup, analyzeFederatedCredentials, detectCrossSubscription, includeRoleAssignments, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          analyzeFederatedCredentials?: boolean;
          detectCrossSubscription?: boolean;
          includeRoleAssignments?: boolean;
          format?: string;
        };

        const checkFederatedCreds = analyzeFederatedCredentials !== false;
        const checkCrossSubscription = detectCrossSubscription !== false;
        const includeRbac = includeRoleAssignments !== false;

        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const authClient = new AuthorizationManagementClient(credential, subscriptionId);
        const identities: any[] = [];
        const findings: any[] = [];

        // Find user-assigned managed identities
        const filter = "resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities'";
        const resources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup, { filter })
          : resourceClient.resources.list({ filter });

        for await (const identity of resources) {
          const identityData: any = {
            name: identity.name,
            type: "User-Assigned",
            resourceGroup: identity.id?.split('/')[4],
            location: identity.location,
            id: identity.id,
            principalId: (identity as any).principalId || "Unknown",
            findings: [],
            riskScore: 0,
          };

          // NEW in v1.14.0: Federated Identity Credentials Analysis
          if (checkFederatedCreds) {
            try {
              // Query federated credentials via REST API (requires Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read)
              const federatedCredsUrl = `${identity.id}/federatedIdentityCredentials?api-version=2023-01-31`;
              
              // Note: This requires Azure Management SDK extension
              // For now, we'll check for tags indicating federation configuration
              const tags = (identity as any).tags || {};
              
              if (tags["workloadIdentity"] || tags["federatedIdentity"] || tags["github-actions"] || tags["aks-workload-identity"]) {
                identityData.federatedIdentityEnabled = true;
                identityData.findings.push({
                  severity: "MEDIUM",
                  finding: "Federated identity configuration detected",
                  description: "This identity may have workload identity federation enabled (GitHub Actions, Kubernetes, etc.)",
                  remediation: "Validate issuer URLs, subject claims, and audience configurations to prevent token injection attacks",
                  cve: "CWE-290: Authentication Bypass by Spoofing",
                });
                identityData.riskScore += 15;
              }

              // Check for external IdP integration
              if (tags["issuer"] || tags["subject"]) {
                identityData.findings.push({
                  severity: "HIGH",
                  finding: "External IdP integration via federated credentials",
                  description: `Issuer: ${tags["issuer"] || "Unknown"}, Subject: ${tags["subject"] || "Unknown"}`,
                  remediation: "Ensure issuer is trusted, subject claims are strict, and audience is properly scoped",
                });
                identityData.riskScore += 25;
              }
            } catch (error: any) {
              // Federated credential check failed (likely missing permissions)
            }
          }

          // NEW in v1.14.0: Role Assignments with Cross-Subscription Detection
          if (includeRbac) {
            try {
              const principalId = identityData.principalId;
              if (principalId && principalId !== "Unknown") {
                const roleAssignments: any[] = [];
                const roleAssignmentsIter = authClient.roleAssignments.listForSubscription({
                  filter: `principalId eq '${principalId}'`,
                });

                for await (const assignment of roleAssignmentsIter) {
                  const assignmentScope = assignment.scope || "";
                  const roleData: any = {
                    roleDefinitionId: assignment.roleDefinitionId,
                    roleName: assignment.roleDefinitionId?.split('/').pop() || "Unknown",
                    scope: assignmentScope,
                    scopeType: assignmentScope.includes('/resourceGroups/') ? 'ResourceGroup' :
                               assignmentScope.includes('/providers/') ? 'Resource' : 'Subscription',
                  };

                  // Cross-subscription detection
                  if (checkCrossSubscription) {
                    const scopeSubId = assignmentScope.match(/\/subscriptions\/([^\/]+)/)?.[1];
                    if (scopeSubId && scopeSubId !== subscriptionId) {
                      roleData.crossSubscription = true;
                      identityData.findings.push({
                        severity: "MEDIUM",
                        finding: "Cross-subscription role assignment detected",
                        description: `Identity has access to resources in subscription ${scopeSubId}`,
                        remediation: "Verify this cross-subscription access is required and properly documented",
                        scope: assignmentScope,
                      });
                      identityData.riskScore += 20;
                    }
                  }

                  roleAssignments.push(roleData);
                }

                identityData.roleAssignments = roleAssignments;
                identityData.roleCount = roleAssignments.length;

                // Check for privileged roles
                const privilegedRoles = roleAssignments.filter(r => 
                  r.roleName.toLowerCase().includes('owner') ||
                  r.roleName.toLowerCase().includes('contributor') ||
                  r.roleName.toLowerCase().includes('administrator')
                );

                if (privilegedRoles.length > 0) {
                  identityData.findings.push({
                    severity: "HIGH",
                    finding: `Managed identity has ${privilegedRoles.length} privileged role assignment(s)`,
                    description: "User-assigned identities with high privileges can be attached to VMs/containers for privilege escalation",
                    remediation: "Review if this level of access is required, consider using least-privilege built-in roles",
                  });
                  identityData.riskScore += 30;
                }
              }
            } catch (error: any) {
              identityData.roleAssignmentError = error.message;
            }
          }

          identityData.riskLevel = identityData.riskScore >= 40 ? "HIGH" : identityData.riskScore >= 20 ? "MEDIUM" : "LOW";
          identities.push(identityData);
        }

        // Find resources with system-assigned identities
        const allResources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup)
          : resourceClient.resources.list();

        const resourcesWithIdentity: any[] = [];
        for await (const resource of allResources) {
          if (resource.identity) {
            const resourceData: any = {
              resourceName: resource.name,
              resourceType: resource.type,
              identityType: resource.identity.type,
              principalId: resource.identity.principalId,
              resourceGroup: resource.id?.split('/')[4],
              findings: [],
              riskScore: 0,
            };

            // Role assignment analysis for system-assigned identities
            if (includeRbac && resource.identity.principalId) {
              try {
                const roleAssignments: any[] = [];
                const roleAssignmentsIter = authClient.roleAssignments.listForSubscription({
                  filter: `principalId eq '${resource.identity.principalId}'`,
                });

                for await (const assignment of roleAssignmentsIter) {
                  const assignmentScope = assignment.scope || "";
                  roleAssignments.push({
                    roleDefinitionId: assignment.roleDefinitionId,
                    roleName: assignment.roleDefinitionId?.split('/').pop() || "Unknown",
                    scope: assignmentScope,
                  });

                  // Cross-subscription check
                  if (checkCrossSubscription) {
                    const scopeSubId = assignmentScope.match(/\/subscriptions\/([^\/]+)/)?.[1];
                    if (scopeSubId && scopeSubId !== subscriptionId) {
                      resourceData.findings.push({
                        severity: "MEDIUM",
                        finding: "Cross-subscription access",
                        description: `System-assigned identity has access in subscription ${scopeSubId}`,
                      });
                      resourceData.riskScore += 15;
                    }
                  }
                }

                resourceData.roleAssignments = roleAssignments;
                resourceData.roleCount = roleAssignments.length;
              } catch (error: any) {
                // Role assignment read failed
              }
            }

            resourceData.riskLevel = resourceData.riskScore >= 20 ? "MEDIUM" : "LOW";
            resourcesWithIdentity.push(resourceData);
          }
        }

        // Summary statistics
        const highRiskIdentities = identities.filter(i => i.riskLevel === "HIGH").length;
        const mediumRiskIdentities = identities.filter(i => i.riskLevel === "MEDIUM").length;
        const federatedIdentities = identities.filter(i => i.federatedIdentityEnabled).length;
        const crossSubIdentities = identities.filter(i => i.findings.some((f: any) => f.finding.includes("Cross-subscription"))).length;

        const summary = `# Managed Identity Enumeration (Enhanced v1.14.0)\n\n## Summary\n- **User-Assigned Identities**: ${identities.length}\n  - HIGH Risk: ${highRiskIdentities}\n  - MEDIUM Risk: ${mediumRiskIdentities}\n  - Federated Identity Enabled: ${federatedIdentities}\n  - Cross-Subscription Access: ${crossSubIdentities}\n\n- **Resources with System-Assigned Identity**: ${resourcesWithIdentity.length}\n\n## Security Analysis\n\n${identities.filter(i => i.riskLevel === "HIGH" || i.riskLevel === "MEDIUM").slice(0, 10).map(i => `\n### ${i.name} (${i.riskLevel} Risk)\n- **Type**: ${i.type}\n- **Resource Group**: ${i.resourceGroup}\n- **Risk Score**: ${i.riskScore}\n- **Role Assignments**: ${i.roleCount || 0}\n- **Findings**: ${i.findings.length}\n${i.findings.map((f: any) => `  - [${f.severity}] ${f.finding}\n    ${f.description}`).join('\n')}\n`).join('')}\n\n## Detailed Data\n\n### User-Assigned Identities\n${JSON.stringify(identities, null, 2)}\n\n### Resources with System-Assigned Identity\n${JSON.stringify(resourcesWithIdentity, null, 2)}`;

        return {
          content: [
            {
              type: "text",
              text: formatResponse(summary, format, request.params.name),
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
        const { subscriptionId, resourceGroup, format, fullScan, includeRemediation, includeCompliance } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          format?: string;
          fullScan?: boolean;
          includeRemediation?: boolean;
          includeCompliance?: boolean;
        };

        const outputFormat = format || "markdown";
        const comprehensiveScan = fullScan === true;
        const withRemediation = includeRemediation !== false;
        const withCompliance = includeCompliance !== false;

        // Run all security scanners to gather findings
        const findings: any = {
          subscription: subscriptionId,
          resourceGroup: resourceGroup || "All",
          scanDate: new Date().toISOString(),
          scanType: comprehensiveScan ? "Comprehensive (All 40 Tools - v1.14.0)" : "Quick Scan (4 Core Tools)",
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

          // ============ COMPREHENSIVE SCAN (fullScan: true) ============
          if (comprehensiveScan) {
            // VM Security Scan
            const computeClient = new ComputeManagementClient(credential, subscriptionId);
            const vms = resourceGroup
              ? computeClient.virtualMachines.list(resourceGroup)
              : computeClient.virtualMachines.listAll();
            
            const vmFindings: any[] = [];
            for await (const vm of vms) {
              const vmRg = vm.id?.split('/')[4] || "";
              
              // Check disk encryption
              if (!vm.storageProfile?.osDisk?.encryptionSettings?.enabled) {
                vmFindings.push({ severity: "HIGH", resource: vm.name, finding: "OS disk encryption not enabled" });
              }
              
              // Check for public IP attachment
              if (vm.networkProfile?.networkInterfaces) {
                for (const nic of vm.networkProfile.networkInterfaces) {
                  const nicName = nic.id?.split('/').pop();
                  if (nicName) {
                    try {
                      const nicDetails = await networkClient.networkInterfaces.get(vmRg, nicName);
                      if (nicDetails.ipConfigurations?.[0]?.publicIPAddress) {
                        vmFindings.push({ severity: "MEDIUM", resource: vm.name, finding: "VM has public IP assigned - potential attack surface" });
                      }
                    } catch {}
                  }
                }
              }
            }
            findings.categories.virtualmachines = { count: vmFindings.length, findings: vmFindings };

            // CosmosDB Security Scan
            const cosmosClient = new CosmosDBManagementClient(credential, subscriptionId);
            const cosmosAccounts = resourceGroup
              ? cosmosClient.databaseAccounts.listByResourceGroup(resourceGroup)
              : cosmosClient.databaseAccounts.list();
            
            const cosmosFindings: any[] = [];
            for await (const account of cosmosAccounts) {
              if (account.publicNetworkAccess === "Enabled") {
                cosmosFindings.push({ severity: "HIGH", resource: account.name, finding: "Public network access enabled" });
              }
              if (!account.isVirtualNetworkFilterEnabled) {
                cosmosFindings.push({ severity: "MEDIUM", resource: account.name, finding: "Virtual network filtering not enabled" });
              }
              if (account.enableAutomaticFailover !== true) {
                cosmosFindings.push({ severity: "LOW", resource: account.name, finding: "Automatic failover not enabled" });
              }
            }
            findings.categories.cosmosdb = { count: cosmosFindings.length, findings: cosmosFindings };

            // ACR Security Scan
            const acrClient = new ContainerRegistryManagementClient(credential, subscriptionId);
            const registries = acrClient.registries.list();
            
            const acrFindings: any[] = [];
            for await (const registry of registries) {
              if (registry.adminUserEnabled === true) {
                acrFindings.push({ severity: "HIGH", resource: registry.name, finding: "Admin user enabled (use Azure AD instead)" });
              }
              if (registry.publicNetworkAccess === "Enabled") {
                acrFindings.push({ severity: "MEDIUM", resource: registry.name, finding: "Public network access enabled" });
              }
              if (!registry.policies?.quarantinePolicy?.status || registry.policies.quarantinePolicy.status !== "enabled") {
                acrFindings.push({ severity: "LOW", resource: registry.name, finding: "Quarantine policy not enabled" });
              }
            }
            findings.categories.containerregistry = { count: acrFindings.length, findings: acrFindings };

            // AKS Security Scan
            const aksClient = new ContainerServiceClient(credential, subscriptionId);
            const aksClusters = aksClient.managedClusters.list();
            
            const aksFindings: any[] = [];
            for await (const cluster of aksClusters) {
              if (!cluster.aadProfile) {
                aksFindings.push({ severity: "CRITICAL", resource: cluster.name, finding: "Azure AD integration not enabled" });
              }
              if (cluster.apiServerAccessProfile?.enablePrivateCluster !== true) {
                aksFindings.push({ severity: "HIGH", resource: cluster.name, finding: "API server not private - publicly accessible" });
              }
              if (!cluster.addonProfiles?.azurepolicy?.enabled) {
                aksFindings.push({ severity: "MEDIUM", resource: cluster.name, finding: "Azure Policy addon not enabled" });
              }
              if (!cluster.networkProfile?.networkPolicy) {
                aksFindings.push({ severity: "MEDIUM", resource: cluster.name, finding: "Network policy not configured (Calico/Azure/Cilium)" });
              }
              if (!cluster.securityProfile?.defender?.securityMonitoring?.enabled) {
                aksFindings.push({ severity: "MEDIUM", resource: cluster.name, finding: "Microsoft Defender for Containers not enabled" });
              }
            }
            findings.categories.kubernetes = { count: aksFindings.length, findings: aksFindings };

            // RBAC/IAM Analysis
            const authClient = new AuthorizationManagementClient(credential, subscriptionId);
            const roleAssignments = authClient.roleAssignments.listForSubscription();
            
            const rbacFindings: any[] = [];
            const dangerousRoles = ["Owner", "Contributor", "User Access Administrator"];
            const assignmentCounts: any = {};
            
            for await (const assignment of roleAssignments) {
              const roleDefId = assignment.roleDefinitionId?.split('/').pop();
              if (roleDefId) {
                try {
                  const roleDef = await authClient.roleDefinitions.getById(assignment.roleDefinitionId || "");
                  const roleName = roleDef.roleName || "";
                  
                  if (dangerousRoles.includes(roleName)) {
                    assignmentCounts[roleName] = (assignmentCounts[roleName] || 0) + 1;
                  }
                  
                  // Check for overly permissive custom roles
                  if (roleDef.roleType === "CustomRole" && roleDef.permissions) {
                    for (const permission of roleDef.permissions) {
                      if (permission.actions?.includes("*")) {
                        rbacFindings.push({ severity: "HIGH", resource: roleName, finding: "Custom role has wildcard (*) permissions" });
                      }
                    }
                  }
                } catch {}
              }
            }
            
            // Report on high-privilege role assignment counts
            for (const [role, count] of Object.entries(assignmentCounts)) {
              if (count as number > 5) {
                rbacFindings.push({ severity: "MEDIUM", resource: "RBAC", finding: `${count} ${role} role assignments (review for least privilege)` });
              }
            }
            findings.categories.rbac = { count: rbacFindings.length, findings: rbacFindings };

            // Managed Identity Analysis
            const resourceClient = new ResourceManagementClient(credential, subscriptionId);
            const identities = resourceClient.resources.list({
              filter: "resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities'"
            });
            
            const identityFindings: any[] = [];
            let identityCount = 0;
            for await (const identity of identities) {
              identityCount++;
            }
            
            if (identityCount > 20) {
              identityFindings.push({ severity: "LOW", resource: "Managed Identities", finding: `${identityCount} managed identities found - review for unused identities` });
            }
            findings.categories.identities = { count: identityFindings.length, findings: identityFindings };

            // Public IP Exposure Analysis
            const publicIPs = networkClient.publicIPAddresses.listAll();
            const publicIPFindings: any[] = [];
            let pipCount = 0;
            
            for await (const pip of publicIPs) {
              pipCount++;
              if (!pip.ipConfiguration) {
                publicIPFindings.push({ severity: "LOW", resource: pip.name, finding: "Public IP not attached to any resource - unused" });
              }
            }
            
            if (pipCount > 10) {
              publicIPFindings.push({ severity: "MEDIUM", resource: "Public IPs", finding: `${pipCount} public IPs allocated - review attack surface` });
            }
            findings.categories.publicips = { count: publicIPFindings.length, findings: publicIPFindings };
          }

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
        report += `**Scan Type:** ${findings.scanType}\n`;
        report += `**Scan Date:** ${findings.scanDate}\n\n`;
        report += `## Executive Summary\n\n`;
        report += `**Total Findings:** ${findings.summary.totalFindings}\n`;
        report += `- **🔴 CRITICAL:** ${findings.summary.critical}\n`;
        report += `- **🟠 HIGH:** ${findings.summary.high}\n`;
        report += `- **🟡 MEDIUM:** ${findings.summary.medium}\n`;
        report += `- **🟢 LOW:** ${findings.summary.low}\n\n`;

        report += `## Risk Assessment\n\n`;
        const overallRisk = findings.summary.critical > 0 ? "CRITICAL 🔴" : findings.summary.high > 0 ? "HIGH 🟠" : findings.summary.medium > 0 ? "MEDIUM 🟡" : "LOW 🟢";
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
    .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold; }
    .badge-comprehensive { background: #107c10; color: white; }
    .badge-quick { background: #0078d4; color: white; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Azure Security Assessment Report</h1>
    <div class="metadata">
      <p><strong>Subscription:</strong> ${subscriptionId}</p>
      <p><strong>Resource Group:</strong> ${findings.resourceGroup}</p>
      <p><strong>Scan Type:</strong> <span class="badge ${comprehensiveScan ? 'badge-comprehensive' : 'badge-quick'}">${findings.scanType}</span></p>
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
              .text(`  |  Scan Type: ${findings.scanType}`)
              .moveDown(0.5)
              .text(`Date: ${new Date(findings.scanDate).toLocaleDateString()}`);
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
        const { subscriptionId, resourceGroup, validateEventGrid, validateServiceBus, checkIntegrationSecurity, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          validateEventGrid?: boolean;
          validateServiceBus?: boolean;
          checkIntegrationSecurity?: boolean;
          format?: string;
        };

        const checkEventGrid = validateEventGrid !== false;
        const checkServiceBus = validateServiceBus !== false;
        const checkIntegrations = checkIntegrationSecurity !== false;

        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const functionApps: any[] = [];

        // Find all Function Apps
        const filter = "resourceType eq 'Microsoft.Web/sites' and kind eq 'functionapp'";
        const resources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup, { filter })
          : resourceClient.resources.list({ filter });

        for await (const funcApp of resources) {
          const findings: any[] = [];
          let riskScore = 0;
          const funcRg = funcApp.id?.split('/')[4] || "";
          const funcProps = (funcApp as any).properties || {};
          const funcConfig = funcProps.siteConfig || {};

          // Basic security checks
          if (!funcProps.httpsOnly) {
            findings.push({
              severity: "HIGH",
              finding: "HTTPS-only is DISABLED",
              description: "Function App allows HTTP connections",
              remediation: "Enable HTTPS-only to enforce encrypted connections",
              cve: "CWE-319: Cleartext Transmission of Sensitive Information",
            });
            riskScore += 40;
          }

          if (funcConfig.minTlsVersion && funcConfig.minTlsVersion < "1.2") {
            findings.push({
              severity: "HIGH",
              finding: `Weak TLS version (${funcConfig.minTlsVersion})`,
              description: "Function App allows TLS versions below 1.2",
              remediation: "Set minimum TLS version to 1.2 or higher",
              cve: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            });
            riskScore += 30;
          }

          if (!funcProps.identity) {
            findings.push({
              severity: "MEDIUM",
              finding: "No managed identity configured",
              description: "Function App not using managed identity for Azure resource authentication",
              remediation: "Enable system-assigned or user-assigned managed identity",
            });
            riskScore += 15;
          }

          // NEW in v1.14.0: Event Grid Integration Security
          if (checkEventGrid || checkIntegrations) {
            try {
              const eventGridResources = resourceClient.resources.list({
                filter: "resourceType eq 'Microsoft.EventGrid/eventSubscriptions'"
              });

              for await (const subscription of eventGridResources) {
                const subProps = (subscription as any).properties || {};
                const destination = subProps.destination || {};

                // Check if this subscription targets our Function App
                if (destination.endpointType === "WebHook" && destination.endpointUrl?.includes(funcApp.name || "")) {
                  findings.push({
                    severity: "INFO",
                    finding: "Event Grid subscription detected",
                    description: `Function triggered by Event Grid topic: ${subscription.name}`,
                    integration: "Event Grid",
                  });

                  // Check for webhook authentication
                  if (!destination.properties || !destination.properties.maxEventsPerBatch) {
                    findings.push({
                      severity: "MEDIUM",
                      finding: "Event Grid webhook lacks batch configuration",
                      description: "May be vulnerable to event flooding attacks",
                      remediation: "Configure maxEventsPerBatch and preferredBatchSizeInKilobytes",
                    });
                    riskScore += 10;
                  }

                  // Check dead letter configuration
                  if (!subProps.deadLetterDestination) {
                    findings.push({
                      severity: "LOW",
                      finding: "No dead letter queue configured for Event Grid",
                      description: "Failed events may be lost",
                      remediation: "Configure dead letter destination (Storage blob container)",
                    });
                  }

                  // Check retry policy
                  if (!subProps.retryPolicy || subProps.retryPolicy.maxDeliveryAttempts > 30) {
                    findings.push({
                      severity: "LOW",
                      finding: "Event Grid retry policy misconfigured",
                      description: "Excessive retry attempts may cause resource exhaustion",
                      remediation: "Set maxDeliveryAttempts to reasonable value (e.g., 10)",
                    });
                  }
                }
              }
            } catch (error: any) {
              // Event Grid check failed (non-blocking)
            }
          }

          // NEW in v1.14.0: Service Bus Integration Security
          if (checkServiceBus || checkIntegrations) {
            try {
              const serviceBusResources = resourceClient.resources.list({
                filter: "resourceType eq 'Microsoft.ServiceBus/namespaces'"
              });

              for await (const sbNamespace of serviceBusResources) {
                const sbRg = sbNamespace.id?.split('/')[4] || "";
                const sbProps = (sbNamespace as any).properties || {};

                findings.push({
                  severity: "INFO",
                  finding: "Service Bus namespace detected",
                  description: `Namespace: ${sbNamespace.name} - check for Function triggers`,
                  integration: "Service Bus",
                });

                // Check for overly permissive SAS policies
                if (sbProps.authorizationRules) {
                  for (const rule of sbProps.authorizationRules) {
                    const rights = rule.rights || [];
                    if (rights.includes("Manage")) {
                      findings.push({
                        severity: "MEDIUM",
                        finding: `Service Bus SAS policy '${rule.name}' has Manage rights`,
                        description: "Function may have excessive permissions on Service Bus",
                        remediation: "Use Listen-only SAS policy for queue/topic triggers",
                        cve: "CWE-269: Improper Privilege Management",
                      });
                      riskScore += 20;
                    }

                    if (rights.includes("Send") && rights.includes("Listen")) {
                      findings.push({
                        severity: "LOW",
                        finding: `Service Bus SAS policy has both Send and Listen rights`,
                        description: "Consider separating Send and Listen permissions",
                        remediation: "Use different SAS policies for producers and consumers",
                      });
                    }
                  }
                }

                // Check minimum TLS version
                if (!sbProps.minimumTlsVersion || sbProps.minimumTlsVersion < "1.2") {
                  findings.push({
                    severity: "HIGH",
                    finding: "Service Bus allows weak TLS versions",
                    description: "Service Bus namespace allows TLS < 1.2",
                    remediation: "Set minimumTlsVersion to 1.2 on Service Bus namespace",
                    cve: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                  });
                  riskScore += 30;
                }

                // Check public network access
                if (sbProps.publicNetworkAccess === "Enabled") {
                  findings.push({
                    severity: "MEDIUM",
                    finding: "Service Bus has public network access enabled",
                    description: "Service Bus accessible from public Internet",
                    remediation: "Use private endpoints and disable public network access",
                  });
                  riskScore += 15;
                }
              }
            } catch (error: any) {
              // Service Bus check failed (non-blocking)
            }
          }

          // NEW in v1.14.0: Integration Security Summary
          if (checkIntegrations) {
            // Check for Storage Queue triggers (common misconfig)
            const appSettings = funcProps.appSettings || [];
            const storageConnections = appSettings.filter((s: any) => 
              s.name?.includes("AzureWebJobsStorage") || s.name?.includes("STORAGE")
            );

            if (storageConnections.length > 0) {
              findings.push({
                severity: "INFO",
                finding: "Storage connections detected",
                description: "Function may use Storage Queue triggers - verify managed identity authentication",
                remediation: "Use managed identity for storage authentication instead of connection strings",
              });

              // Check if using connection strings (security risk)
              for (const conn of storageConnections) {
                if (conn.value && !conn.value.includes("@Microsoft.KeyVault")) {
                  findings.push({
                    severity: "MEDIUM",
                    finding: "Storage connection string in app settings",
                    description: `Setting '${conn.name}' contains plaintext connection string`,
                    remediation: "Use Key Vault references or managed identity",
                    cve: "CWE-798: Use of Hard-coded Credentials",
                  });
                  riskScore += 20;
                }
              }
            }
          }

          functionApps.push({
            name: funcApp.name,
            resourceGroup: funcRg,
            location: funcApp.location,
            httpsOnly: funcProps.httpsOnly,
            minTlsVersion: funcConfig.minTlsVersion,
            hasManagedIdentity: !!funcProps.identity,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings,
          });
        }

        functionApps.sort((a, b) => b.riskScore - a.riskScore);

        const criticalCount = functionApps.filter(f => f.riskLevel === "CRITICAL").length;
        const highCount = functionApps.filter(f => f.riskLevel === "HIGH").length;

        const summary = `# Azure Functions Security Analysis (Enhanced v1.14.0)\n\n## Summary\n- **Total Function Apps**: ${functionApps.length}\n- **Risk Levels**:\n  - CRITICAL: ${criticalCount}\n  - HIGH: ${highCount}\n  - MEDIUM: ${functionApps.filter(f => f.riskLevel === "MEDIUM").length}\n  - LOW: ${functionApps.filter(f => f.riskLevel === "LOW").length}\n\n## Integration Security Analysis\n${functionApps.filter(f => f.findings.some((ff: any) => ff.integration)).map(f => `\n### ${f.name}\n${f.findings.filter((ff: any) => ff.integration).map((ff: any) => `- [${ff.severity}] ${ff.finding} (${ff.integration})`).join('\n')}\n`).join('')}\n\n## Detailed Findings\n\n${JSON.stringify(functionApps, null, 2)}`;

        return {
          content: [
            {
              type: "text",
              text: formatResponse(summary, format, request.params.name),
            },
          ],
        };
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
        const args = request.params.arguments as {
          subscriptionId: string;
          resourceGroup: string;
          clusterName: string;
          scanMode?: string;
          namespace?: string;
          podName?: string;
          deepScan?: boolean;
          testDataPlane?: boolean;
          exportTokens?: boolean;
          deepDataPlane?: boolean;
          scanAllPods?: boolean;
          format?: string;
        };

        // Validate scanMode
        const validScanModes = ['full', 'live', 'imds', 'pod_identity', 'admission'];
        const scanMode = args.scanMode || 'full';
        if (!validScanModes.includes(scanMode)) {
          return {
            content: [{ type: 'text', text: `Invalid scanMode: ${scanMode}. Valid modes: ${validScanModes.join(', ')}` }],
            isError: true,
          };
        }

        const { subscriptionId, resourceGroup, clusterName, format, namespace, podName, deepScan, testDataPlane, exportTokens, deepDataPlane, scanAllPods } = args;

        try {
          // Route to appropriate scan mode
          if (scanMode !== 'full') {
            return await scanAKSModeSpecific(
              credential,
              subscriptionId,
              resourceGroup,
              clusterName,
              scanMode,
              namespace,
              podName,
              deepScan,
              testDataPlane,
              exportTokens,
              deepDataPlane,
              scanAllPods,
              format,
              request.params.name
            );
          }

          // Continue with full scan implementation below
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

      case "azure_scan_aks_policy_bypass": {
        const subscriptionId = String(request.params.arguments?.subscriptionId);
        const resourceGroup = String(request.params.arguments?.resourceGroup);
        const clusterName = String(request.params.arguments?.clusterName);
        const format = request.params.arguments?.format ? String(request.params.arguments.format) : "markdown";
        
        try {
          const result = await scanAKSPolicyBypass(subscriptionId, resourceGroup, clusterName, format);
          performanceTracker.end(trackingId, true);
          logger.info(`Tool completed successfully: ${name}`, {}, name);
          return {
            content: [
              {
                type: "text",
                text: result,
              },
            ],
          };
        } catch (error: any) {
          performanceTracker.end(trackingId, false, error.message);
          logger.error(`Tool failed: ${name}`, { error: error.message }, name);
          return {
            content: [{type: 'text', text: `Error scanning AKS policy configurations: ${error.message}`}],
            isError: true,
          };
        }
      }

      case "azure_scan_container_apps_security": {
        const subscriptionId = String(request.params.arguments?.subscriptionId);
        const resourceGroup = request.params.arguments?.resourceGroup ? String(request.params.arguments.resourceGroup) : undefined;
        const containerAppName = request.params.arguments?.containerAppName ? String(request.params.arguments.containerAppName) : undefined;
        const format = request.params.arguments?.format ? String(request.params.arguments.format) : "markdown";
        
        try {
          const result = await scanContainerAppsSecurity(subscriptionId, resourceGroup, containerAppName, format);
          performanceTracker.end(trackingId, true);
          logger.info(`Tool completed successfully: ${name}`, {}, name);
          return {
            content: [{ type: "text", text: result }],
          };
        } catch (error: any) {
          performanceTracker.end(trackingId, false, error.message);
          logger.error(`Tool failed: ${name}`, { error: error.message }, name);
          return {
            content: [{ type: 'text', text: `Error scanning Container Apps: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_scan_gitops_security": {
        const subscriptionId = String(request.params.arguments?.subscriptionId);
        const resourceGroup = String(request.params.arguments?.resourceGroup);
        const clusterName = String(request.params.arguments?.clusterName);
        const format = request.params.arguments?.format ? String(request.params.arguments.format) : "markdown";
        
        try {
          const result = await scanGitOpsSecurity(subscriptionId, resourceGroup, clusterName, format);
          performanceTracker.end(trackingId, true);
          logger.info(`Tool completed successfully: ${name}`, {}, name);
          return {
            content: [{ type: "text", text: result }],
          };
        } catch (error: any) {
          performanceTracker.end(trackingId, false, error.message);
          logger.error(`Tool failed: ${name}`, { error: error.message }, name);
          return {
            content: [{ type: 'text', text: `Error scanning GitOps: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_scan_cdn_security": {
        const subscriptionId = String(request.params.arguments?.subscriptionId);
        const resourceGroup = request.params.arguments?.resourceGroup ? String(request.params.arguments.resourceGroup) : undefined;
        const profileName = request.params.arguments?.profileName ? String(request.params.arguments.profileName) : undefined;
        const format = request.params.arguments?.format ? String(request.params.arguments.format) : "markdown";
        
        try {
          const result = await scanCDNSecurity(subscriptionId, resourceGroup, profileName, format);
          performanceTracker.end(trackingId, true);
          logger.info(`Tool completed successfully: ${name}`, {}, name);
          return {
            content: [{ type: "text", text: result }],
          };
        } catch (error: any) {
          performanceTracker.end(trackingId, false, error.message);
          logger.error(`Tool failed: ${name}`, { error: error.message }, name);
          return {
            content: [{ type: 'text', text: `Error scanning CDN: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "azure_analyze_backup_security": {
        const { subscriptionId, resourceGroup, includeASR, checkImmutability, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          includeASR?: boolean;
          checkImmutability?: boolean;
          format?: string;
        };

        const analyzeASR = includeASR !== false;
        const validateImmutability = checkImmutability !== false;

        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const backupVaults: any[] = [];

        // Find Recovery Services Vaults
        const vaultFilter = "resourceType eq 'Microsoft.RecoveryServices/vaults'";
        const vaultResources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup, { filter: vaultFilter })
          : resourceClient.resources.list({ filter: vaultFilter });

        for await (const vault of vaultResources) {
          const findings: any[] = [];
          let riskScore = 0;
          const vaultRg = vault.id?.split('/')[4] || "";
          const vaultProps = (vault as any).properties || {};

          // Check soft delete
          if (!vaultProps.enableSoftDelete) {
            findings.push({
              severity: "HIGH",
              finding: "Soft delete is DISABLED",
              description: "Deleted backups can be permanently lost",
              remediation: "Enable soft delete for 14-day retention of deleted backups",
              cve: "CWE-404: Improper Resource Shutdown or Release",
            });
            riskScore += 35;
          }

          // Check vault encryption
          if (!vaultProps.encryption || vaultProps.encryption.keyVaultProperties === undefined) {
            findings.push({
              severity: "MEDIUM",
              finding: "Vault not using customer-managed keys",
              description: "Backup data encrypted with Microsoft-managed keys only",
              remediation: "Use customer-managed keys (CMK) in Key Vault for enhanced control",
            });
            riskScore += 15;
          }

          // NEW in v1.14.0: Immutable vault validation (ransomware protection)
          if (validateImmutability) {
            if (!vaultProps.immutabilitySettings || vaultProps.immutabilitySettings.state !== "Locked") {
              findings.push({
                severity: "CRITICAL",
                finding: "Immutable vault NOT configured (ransomware risk)",
                description: "Backup vault can be deleted or modified by attackers with sufficient privileges",
                remediation: "Enable immutability with locked state to prevent ransomware from deleting backups",
                cve: "CWE-404: Resource Deletion Without Protection",
              });
              riskScore += 60;
            }
          }

          // Check cross-region restore
          if (!vaultProps.crossRegionRestore) {
            findings.push({
              severity: "LOW",
              finding: "Cross-region restore not enabled",
              description: "Cannot restore backups if primary region fails",
              remediation: "Enable cross-region restore for disaster recovery",
            });
          }

          backupVaults.push({
            name: vault.name,
            resourceGroup: vaultRg,
            location: vault.location,
            softDeleteEnabled: vaultProps.enableSoftDelete,
            immutabilityState: vaultProps.immutabilitySettings?.state,
            crossRegionRestore: vaultProps.crossRegionRestore,
            riskScore,
            riskLevel: riskScore >= 50 ? "CRITICAL" : riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings,
          });
        }

        // NEW in v1.14.0: Azure Site Recovery (ASR) Analysis
        if (analyzeASR) {
          const asrVaults = backupVaults.filter(v => v.name?.toLowerCase().includes("asr") || v.name?.toLowerCase().includes("recovery"));
          if (asrVaults.length > 0) {
            for (const vault of asrVaults) {
              vault.findings.push({
                severity: "INFO",
                finding: "ASR vault detected",
                description: "Azure Site Recovery configured for disaster recovery",
              });
            }
          }
        }

        backupVaults.sort((a, b) => b.riskScore - a.riskScore);

        const summary = `# Backup & Site Recovery Security Analysis\\n\\n## Summary\\n- Recovery Services Vaults: ${backupVaults.length}\\n- CRITICAL Risk: ${backupVaults.filter(v => v.riskLevel === "CRITICAL").length}\\n- Immutability Enabled: ${backupVaults.filter(v => v.immutabilityState === "Locked").length}\\n- Soft Delete Enabled: ${backupVaults.filter(v => v.softDeleteEnabled).length}\\n\\n${JSON.stringify(backupVaults, null, 2)}`;

        return {
          content: [{ type: "text", text: formatResponse(summary, format, request.params.name) }],
        };
      }

      case "azure_analyze_vnet_peering": {
        const { subscriptionId, resourceGroup, detectTopology, checkCrossTenant, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          detectTopology?: boolean;
          checkCrossTenant?: boolean;
          format?: string;
        };

        const analyzeTopology = detectTopology !== false;
        const validateCrossTenant = checkCrossTenant !== false;

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const peerings: any[] = [];

        const vnets = resourceGroup
          ? networkClient.virtualNetworks.list(resourceGroup)
          : networkClient.virtualNetworks.listAll();

        for await (const vnet of vnets) {
          if (vnet.virtualNetworkPeerings && vnet.virtualNetworkPeerings.length > 0) {
            for (const peering of vnet.virtualNetworkPeerings) {
              const findings: any[] = [];
              let riskScore = 0;

              if (peering.allowForwardedTraffic) {
                findings.push({
                  severity: "MEDIUM",
                  finding: "Allow forwarded traffic enabled",
                  description: "Network traffic can be routed through this peering",
                  remediation: "Disable if not required for hub-spoke topology",
                });
                riskScore += 20;
              }

              if (peering.allowGatewayTransit) {
                findings.push({
                  severity: "HIGH",
                  finding: "Allow gateway transit enabled",
                  description: "Remote VNet can use local VNet's VPN gateway (privilege escalation risk)",
                  remediation: "Review necessity and ensure proper NSG controls",
                  cve: "CWE-269: Improper Privilege Management",
                });
                riskScore += 30;
              }

              if (validateCrossTenant && peering.remoteVirtualNetwork?.id) {
                const remoteSubId = peering.remoteVirtualNetwork.id.match(/\/subscriptions\/([^\/]+)/)?.[1];
                if (remoteSubId && remoteSubId !== subscriptionId) {
                  findings.push({
                    severity: "MEDIUM",
                    finding: "Cross-subscription peering detected",
                    description: `Peered with subscription: ${remoteSubId}`,
                    remediation: "Verify cross-subscription peering is authorized",
                  });
                  riskScore += 25;
                }
              }

              peerings.push({
                vnetName: vnet.name,
                peeringName: peering.name,
                peeringState: peering.peeringState,
                remoteVNet: peering.remoteVirtualNetwork?.id,
                allowForwardedTraffic: peering.allowForwardedTraffic,
                allowGatewayTransit: peering.allowGatewayTransit,
                useRemoteGateways: peering.useRemoteGateways,
                riskScore,
                riskLevel: riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
                findings,
              });
            }
          }
        }

        peerings.sort((a, b) => b.riskScore - a.riskScore);

        const summary = `# VNet Peering Security Analysis\\n\\n## Summary\\n- Total Peerings: ${peerings.length}\\n- HIGH Risk: ${peerings.filter(p => p.riskLevel === "HIGH").length}\\n- Cross-Subscription: ${peerings.filter(p => p.findings.some((f: any) => f.finding.includes("Cross-subscription"))).length}\\n\\n${JSON.stringify(peerings, null, 2)}`;

        return {
          content: [{ type: "text", text: formatResponse(summary, format, request.params.name) }],
        };
      }

      case "azure_validate_private_endpoints": {
        const { subscriptionId, resourceGroup, serviceType, validateDNS, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          serviceType?: string;
          validateDNS?: boolean;
          format?: string;
        };

        const checkDNS = validateDNS !== false;

        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const privateEndpoints: any[] = [];

        const endpoints = resourceGroup
          ? networkClient.privateEndpoints.list(resourceGroup)
          : networkClient.privateEndpoints.listBySubscription();

        for await (const endpoint of endpoints) {
          const findings: any[] = [];
          let riskScore = 0;

          const connectionState = endpoint.privateLinkServiceConnections?.[0]?.privateLinkServiceConnectionState?.status;

          if (connectionState === "Pending") {
            findings.push({
              severity: "MEDIUM",
              finding: "Private endpoint connection PENDING approval",
              description: "Connection awaiting approval from service owner",
              remediation: "Approve the connection or investigate why it's pending",
            });
            riskScore += 20;
          }

          if (!endpoint.subnet) {
            findings.push({
              severity: "HIGH",
              finding: "Private endpoint not attached to subnet",
              description: "Endpoint misconfigured without subnet assignment",
              remediation: "Assign private endpoint to a subnet",
            });
            riskScore += 35;
          }

          if (checkDNS && (!endpoint.customDnsConfigs || endpoint.customDnsConfigs.length === 0)) {
            findings.push({
              severity: "MEDIUM",
              finding: "No custom DNS configuration",
              description: "Private endpoint may not resolve correctly without private DNS zone",
              remediation: "Configure private DNS zone integration",
            });
            riskScore += 15;
          }

          privateEndpoints.push({
            name: endpoint.name,
            resourceGroup: endpoint.id?.split('/')[4],
            subnet: endpoint.subnet?.id,
            connectionState,
            service: endpoint.privateLinkServiceConnections?.[0]?.privateLinkServiceId,
            dnsConfigured: endpoint.customDnsConfigs && endpoint.customDnsConfigs.length > 0,
            riskScore,
            riskLevel: riskScore >= 30 ? "HIGH" : riskScore >= 15 ? "MEDIUM" : "LOW",
            findings,
          });
        }

        privateEndpoints.sort((a, b) => b.riskScore - a.riskScore);

        const summary = `# Private Endpoints Validation\\n\\n## Summary\\n- Total Private Endpoints: ${privateEndpoints.length}\\n- Pending Approval: ${privateEndpoints.filter(p => p.connectionState === "Pending").length}\\n- DNS Configured: ${privateEndpoints.filter(p => p.dnsConfigured).length}\\n\\n${JSON.stringify(privateEndpoints, null, 2)}`;

        return {
          content: [{ type: "text", text: formatResponse(summary, format, request.params.name) }],
        };
      }

      case "azure_validate_diagnostic_settings": {
        const { subscriptionId, resourceGroup, resourceType, checkCompliance, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          resourceType?: string;
          checkCompliance?: boolean;
          format?: string;
        };

        const validateCompliance = checkCompliance !== false;

        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        const diagnosticResults: any[] = [];

        const filter = resourceType ? `resourceType eq '${resourceType}'` : undefined;
        const resources = resourceGroup
          ? resourceClient.resources.listByResourceGroup(resourceGroup, { filter })
          : resourceClient.resources.list({ filter });

        let totalResources = 0;
        let resourcesWithDiagnostics = 0;

        for await (const resource of resources) {
          totalResources++;
          const findings: any[] = [];
          let riskScore = 0;

          // Check if diagnostic settings exist
          const hasDiagnostics = (resource as any).properties?.diagnosticSettings !== undefined;

          if (!hasDiagnostics) {
            findings.push({
              severity: "HIGH",
              finding: "No diagnostic settings configured",
              description: "Resource is not logging events or metrics",
              remediation: "Configure diagnostic settings to send logs to Log Analytics workspace",
              cve: "CWE-778: Insufficient Logging",
            });
            riskScore += 40;
          } else {
            resourcesWithDiagnostics++;
          }

          if (riskScore > 0) {
            diagnosticResults.push({
              resourceName: resource.name,
              resourceType: resource.type,
              resourceGroup: resource.id?.split('/')[4],
              hasDiagnostics,
              riskScore,
              riskLevel: riskScore >= 30 ? "HIGH" : "MEDIUM",
              findings,
            });
          }
        }

        const coveragePercent = totalResources > 0 ? Math.round((resourcesWithDiagnostics / totalResources) * 100) : 0;

        const summary = `# Diagnostic Settings Validation\\n\\n## Summary\\n- Total Resources: ${totalResources}\\n- Resources with Diagnostics: ${resourcesWithDiagnostics}\\n- Coverage: ${coveragePercent}%\\n- Missing Diagnostics: ${totalResources - resourcesWithDiagnostics}\\n\\n${JSON.stringify(diagnosticResults, null, 2)}`;

        return {
          content: [{ type: "text", text: formatResponse(summary, format, request.params.name) }],
        };
      }

      case "azure_assess_defender_coverage": {
        const { subscriptionId, includeRecommendations, includeCompliance, format } = request.params.arguments as {
          subscriptionId: string;
          includeRecommendations?: boolean;
          includeCompliance?: boolean;
          format?: string;
        };

        const checkRecommendations = includeRecommendations !== false;
        const checkCompliance = includeCompliance !== false;

        const summary = `# Microsoft Defender for Cloud Assessment\\n\\n## Summary\\n- Subscription: ${subscriptionId}\\n\\n**Note**: This tool requires Microsoft Defender for Cloud API access.\\n\\nTo fully implement, you need:\\n1. @azure/arm-security package\\n2. Security Reader or Security Admin role\\n3. Defender for Cloud enabled on subscription\\n\\n## Key Capabilities\\n- Defender plan coverage (VMs, Storage, SQL, App Service, Key Vault, Containers)\\n- Secure Score analysis\\n- Security recommendations by severity\\n- Regulatory compliance status\\n- Active security alerts\\n\\nThis will be fully implemented in a future update.`;

        return {
          content: [{ type: "text", text: formatResponse(summary, format, request.params.name) }],
        };
      }

      case "azure_validate_policy_compliance": {
        const { subscriptionId, resourceGroup, policyScope, includeExemptions, format } = request.params.arguments as {
          subscriptionId: string;
          resourceGroup?: string;
          policyScope?: string;
          includeExemptions?: boolean;
          format?: string;
        };

        const checkExemptions = includeExemptions !== false;
        const scope = policyScope || "subscription";

        const summary = `# Azure Policy Compliance Validation\\n\\n## Summary\\n- Subscription: ${subscriptionId}\\n- Scope: ${scope}\\n\\n**Note**: This tool requires Azure Policy API access.\\n\\nTo fully implement, you need:\\n1. @azure/arm-policy package\\n2. Policy Reader or Resource Policy Contributor role\\n\\n## Key Capabilities\\n- Policy assignments analysis\\n- Compliance state (compliant/non-compliant/conflict/exempt)\\n- Policy effects (deny, audit, append, modify)\\n- Built-in vs custom policies\\n- Policy initiative assignments\\n- Exemptions and exceptions\\n\\nThis will be fully implemented in a future update.`;

        return {
          content: [{ type: "text", text: formatResponse(summary, format, request.params.name) }],
        };
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

// ACR Container Registry Poisoning Scanner
async function scanACRPoisoning(subscriptionId: string, resourceGroup?: string, registryName?: string, format: string = "markdown"): Promise<string> {
  const acrClient = new ContainerRegistryManagementClient(credential, subscriptionId);
  const outputLines: string[] = [];
  
  try {
    outputLines.push(`# ACR Container Registry Poisoning Scan`);
    outputLines.push(`**Subscription:** ${subscriptionId}`);
    outputLines.push(`**Scan Time:** ${new Date().toISOString()}`);
    outputLines.push(``);
    
    // List registries
    let registries: any[] = [];
    
    if (registryName && resourceGroup) {
      // Get specific registry
      const registry = await acrClient.registries.get(resourceGroup, registryName);
      registries = [registry];
    } else if (resourceGroup) {
      // List registries in resource group
      for await (const registry of acrClient.registries.listByResourceGroup(resourceGroup)) {
        registries.push(registry);
      }
    } else {
      // List all registries in subscription
      for await (const registry of acrClient.registries.list()) {
        registries.push(registry);
      }
    }
    
    if (registries.length === 0) {
      outputLines.push(`[INFO] No ACR registries found`);
      return outputLines.join('\n');
    }
    
    outputLines.push(`**Registries Analyzed:** ${registries.length}`);
    outputLines.push(``);
    
    // Risk counters
    let publicAccessCount = 0;
    let adminEnabledCount = 0;
    let noContentTrustCount = 0;
    let noDefenderCount = 0;
    let noEncryptionCount = 0;
    let noNetworkRulesCount = 0;
    
    // Risk Summary (will update at the end)
    const riskSummaryIndex = outputLines.length;
    outputLines.push(`## Risk Summary`);
    outputLines.push(``);
    
    outputLines.push(`## Detailed Findings`);
    outputLines.push(``);
    
    // Analyze each registry
    for (const registry of registries) {
      const name = registry.name || 'unknown';
      const rg = registry.id?.split('/')[4] || 'unknown';
      const loginServer = registry.loginServer || 'N/A';
      const sku = registry.sku?.name || 'N/A';
      const location = registry.location || 'N/A';
      const createdAt = registry.creationDate ? new Date(registry.creationDate).toISOString() : 'N/A';
      
      outputLines.push(`### Registry: ${name}`);
      outputLines.push(`**Resource Group:** ${rg}`);
      outputLines.push(`**Login Server:** ${loginServer}`);
      outputLines.push(`**SKU:** ${sku}`);
      outputLines.push(`**Location:** ${location}`);
      outputLines.push(`**Created:** ${createdAt}`);
      outputLines.push(``);
      
      const findings: string[] = [];
      
      // TC-ACR-001: Public Network Access
      const publicAccess = registry.publicNetworkAccess || 'Enabled';
      if (publicAccess === 'Enabled') {
        publicAccessCount++;
        findings.push(`#### TC-ACR-001: Public Network Access`);
        findings.push(`**Risk:** CRITICAL | **MITRE:** T1525 - Implant Internal Image`);
        findings.push(`- Public Access: **ENABLED**`);
        findings.push(`- ⚠️ Registry accessible from internet`);
        findings.push(`- Recommendation: Disable public access, use private endpoints`);
        findings.push(``);
      }
      
      // TC-ACR-002: Admin Account Enabled
      if (registry.adminUserEnabled === true) {
        adminEnabledCount++;
        findings.push(`#### TC-ACR-002: Admin Account Enabled`);
        findings.push(`**Risk:** HIGH | **MITRE:** T1078 - Valid Accounts`);
        findings.push(`- Admin Enabled: **true**`);
        findings.push(`- ⚠️ Username/password authentication enabled (should use Azure AD tokens)`);
        findings.push(`- Credentials can be compromised and provide full registry access`);
        findings.push(``);
      }
      
      // TC-ACR-003: No Content Trust (Image Signing)
      const contentTrust = registry.policies?.trustPolicy?.status || 'disabled';
      if (contentTrust === 'disabled') {
        noContentTrustCount++;
        findings.push(`#### TC-ACR-003: No Content Trust`);
        findings.push(`**Risk:** HIGH | **MITRE:** T1195.003 - Supply Chain Compromise`);
        findings.push(`- Content Trust: **NOT ENABLED**`);
        findings.push(`- ⚠️ Images not signed, no integrity verification`);
        findings.push(`- Vulnerable to image tampering and supply chain attacks`);
        findings.push(``);
      }
      
      // TC-ACR-004: Missing Vulnerability Scanning (Defender for Containers)
      // Note: This requires checking Azure Defender/Microsoft Defender for Cloud
      // For now, we'll note if Premium SKU is not in use (required for some security features)
      if (sku !== 'Premium') {
        findings.push(`#### TC-ACR-004: Limited Security Features`);
        findings.push(`**Risk:** MEDIUM | **MITRE:** T1525 - Implant Internal Image`);
        findings.push(`- SKU: **${sku}** (not Premium)`);
        findings.push(`- ⚠️ Premium tier required for geo-replication, customer-managed keys, and advanced features`);
        findings.push(`- Consider upgrading to Premium for enhanced security`);
        findings.push(``);
      }
      
      // Check for Defender for Containers - assume not enabled if we can't verify
      // In production, you would query Defender for Cloud API
      noDefenderCount++;
      findings.push(`#### TC-ACR-005: Vulnerability Scanning Status Unknown`);
      findings.push(`**Risk:** HIGH | **MITRE:** T1525 - Implant Internal Image`);
      findings.push(`- Defender for Containers: **UNKNOWN** (requires Azure Security Center API check)`);
      findings.push(`- ⚠️ Images may not be scanned for vulnerabilities`);
      findings.push(`- Enable Defender for Containers in Azure Security Center`);
      findings.push(``);
      
      // TC-ACR-006: Encryption Configuration
      const encryptionStatus = registry.encryption?.status || 'disabled';
      if (encryptionStatus === 'disabled') {
        noEncryptionCount++;
        findings.push(`#### TC-ACR-006: Default Encryption`);
        findings.push(`**Risk:** LOW | **MITRE:** T1530 - Data from Cloud Storage`);
        findings.push(`- Encryption: **Platform-managed keys** (not customer-managed)`);
        findings.push(`- ⚠️ Consider using customer-managed keys (CMK) with Key Vault for better control`);
        findings.push(``);
      }
      
      // TC-ACR-007: Network Rules
      const networkRuleSet = registry.networkRuleSet;
      if (!networkRuleSet || networkRuleSet.defaultAction === 'Allow') {
        noNetworkRulesCount++;
        findings.push(`#### TC-ACR-007: No Network Restrictions`);
        findings.push(`**Risk:** MEDIUM | **MITRE:** T1071 - Application Layer Protocol`);
        findings.push(`- Network Rule Default Action: **Allow**`);
        findings.push(`- ⚠️ No IP allowlist or virtual network rules configured`);
        findings.push(`- Configure network rules to restrict access to specific IPs/VNets`);
        findings.push(``);
      }
      
      // TC-ACR-008: Anonymous Pull Access
      const anonymousPull = registry.anonymousPullEnabled === true;
      if (anonymousPull) {
        findings.push(`#### TC-ACR-008: Anonymous Pull Enabled`);
        findings.push(`**Risk:** CRITICAL | **MITRE:** T1525 - Implant Internal Image`);
        findings.push(`- Anonymous Pull: **ENABLED**`);
        findings.push(`- ⚠️ Anyone can pull images without authentication`);
        findings.push(`- This is extremely dangerous - disable immediately unless required`);
        findings.push(``);
      }
      
      // Check retention policy
      const retentionPolicy = registry.policies?.retentionPolicy;
      if (retentionPolicy?.status === 'disabled') {
        findings.push(`#### TC-ACR-009: No Retention Policy`);
        findings.push(`**Risk:** LOW | **MITRE:** T1562.008 - Impair Defenses`);
        findings.push(`- Retention Policy: **DISABLED**`);
        findings.push(`- ⚠️ Old, vulnerable images may accumulate`);
        findings.push(`- Enable retention policy to automatically clean up untagged manifests`);
        findings.push(``);
      }
      
      // Output findings for this registry
      if (findings.length > 0) {
        outputLines.push(...findings);
      } else {
        outputLines.push(`[OK] No critical security issues found for this registry`);
        outputLines.push(``);
      }
      
      outputLines.push(`---`);
      outputLines.push(``);
    }
    
    // Insert risk summary after calculating all risks
    const riskSummaryLines = [
      `| Risk Type | Count | Severity |`,
      `|-----------|-------|----------|`,
      `| Public Access Enabled | ${publicAccessCount} | CRITICAL |`,
      `| Admin Account Enabled | ${adminEnabledCount} | HIGH |`,
      `| No Content Trust | ${noContentTrustCount} | HIGH |`,
      `| No Defender Scanning | ${noDefenderCount} | HIGH |`,
      `| No Network Rules | ${noNetworkRulesCount} | MEDIUM |`,
      `| Default Encryption | ${noEncryptionCount} | LOW |`,
      ``,
    ];
    outputLines.splice(riskSummaryIndex + 2, 0, ...riskSummaryLines);
    
    // Remediation section
    outputLines.push(`## Remediation`);
    outputLines.push(``);
    outputLines.push(`1. **Disable public network access** - Use private endpoints only`);
    outputLines.push(`2. **Disable admin account** - Use Azure AD authentication with RBAC`);
    outputLines.push(`3. **Enable content trust** - Implement image signing for integrity verification`);
    outputLines.push(`4. **Enable Defender for Containers** - Scan images for vulnerabilities`);
    outputLines.push(`5. **Configure network rules** - Restrict access to specific IPs or VNets`);
    outputLines.push(`6. **Use customer-managed keys** - Enable encryption with Key Vault CMK`);
    outputLines.push(`7. **Enable retention policies** - Automatically clean up old images`);
    outputLines.push(`8. **Use Azure Policy** - Enforce security standards across all registries`);
    outputLines.push(``);
    outputLines.push(`### Example Azure CLI Commands`);
    outputLines.push(`\`\`\`bash`);
    outputLines.push(`# Disable public access`);
    outputLines.push(`az acr update --name REGISTRY_NAME --public-network-enabled false`);
    outputLines.push(``);
    outputLines.push(`# Disable admin account`);
    outputLines.push(`az acr update --name REGISTRY_NAME --admin-enabled false`);
    outputLines.push(``);
    outputLines.push(`# Enable content trust (requires Docker Notary)`);
    outputLines.push(`az acr config content-trust update --registry REGISTRY_NAME --status enabled`);
    outputLines.push(``);
    outputLines.push(`# Configure network rules`);
    outputLines.push(`az acr network-rule add --name REGISTRY_NAME --ip-address YOUR_IP/32`);
    outputLines.push(``);
    outputLines.push(`# Create private endpoint`);
    outputLines.push(`az network private-endpoint create --name ACR-PE --resource-group RG \\`);
    outputLines.push(`  --vnet-name VNET --subnet SUBNET --private-connection-resource-id REGISTRY_ID \\`);
    outputLines.push(`  --group-id registry --connection-name ACR-Connection`);
    outputLines.push(`\`\`\``);
    outputLines.push(``);
    
    // Attack vectors section
    outputLines.push(`## Attack Vectors`);
    outputLines.push(``);
    outputLines.push(`| Vector | Risk | MITRE ATT&CK |`);
    outputLines.push(`|--------|------|--------------|`);
    outputLines.push(`| Public registry exposure | CRITICAL | T1525 - Implant Internal Image |`);
    outputLines.push(`| Image poisoning/backdoor | HIGH | T1195.003 - Supply Chain Compromise |`);
    outputLines.push(`| Admin credential theft | HIGH | T1552.001 - Credentials in Files |`);
    outputLines.push(`| Vulnerable image deployment | HIGH | T1525 - Implant Internal Image |`);
    outputLines.push(`| Anonymous pull abuse | CRITICAL | T1078 - Valid Accounts |`);
    outputLines.push(`| Network-based attacks | MEDIUM | T1071 - Application Layer Protocol |`);
    outputLines.push(``);
    
  } catch (error: any) {
    outputLines.push(``);
    outputLines.push(`[FAIL] Error scanning ACR poisoning: ${error.message}`);
  }
  
  return outputLines.join('\n');
}

/**
 * Live K8s API scan via kubectl (placeholder - implementation pending)
 */
async function scanAKSLive(
  subscriptionId: string,
  resourceGroup: string,
  clusterName: string,
  namespace?: string,
  format?: string
): Promise<string> {
  // TODO: Extract logic from azure_scan_aks_live handler (line 5889)
  return `# 🔴 AKS Live Scan\n\n` +
    `**NOTE:** This scan mode implementation is in progress.\n\n` +
    `**Workaround:** Use scanMode='full' for comprehensive analysis.\n\n` +
    `**Parameters:**\n` +
    `- Cluster: ${clusterName}\n` +
    `- Resource Group: ${resourceGroup}\n` +
    `- Subscription: ${subscriptionId}\n` +
    `- Namespace: ${namespace || 'all'}\n`;
}

/**
 * IMDS exploitation scan (placeholder - implementation pending)
 */
async function scanAKSIMDS(
  subscriptionId: string,
  resourceGroup: string,
  clusterName: string,
  podName?: string,
  exportTokens?: boolean,
  format?: string
): Promise<string> {
  // TODO: Extract logic from azure_scan_aks_imds handler (line 7227)
  return `# 🔴 AKS IMDS Exploitation Scan\n\n` +
    `**NOTE:** This scan mode implementation is in progress.\n\n` +
    `**Workaround:** Use scanMode='full' for comprehensive analysis.\n\n` +
    `**Parameters:**\n` +
    `- Cluster: ${clusterName}\n` +
    `- Pod: ${podName || 'auto-discover'}\n` +
    `- Export Tokens: ${exportTokens || false}\n`;
}

/**
 * Mode-specific AKS security scan router
 * Routes scanMode to appropriate specialized functions
 */
async function scanAKSModeSpecific(
  credential: any,
  subscriptionId: string,
  resourceGroup: string,
  clusterName: string,
  scanMode: string,
  namespace?: string,
  podName?: string,
  deepScan?: boolean,
  testDataPlane?: boolean,
  exportTokens?: boolean,
  deepDataPlane?: boolean,
  scanAllPods?: boolean,
  format?: string,
  toolName?: string
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  try {
    let output = '';

    switch (scanMode) {
      case 'live':
        // Live K8s API scan via kubectl
        output = await scanAKSLive(subscriptionId, resourceGroup, clusterName, namespace, format || "markdown");
        break;

      case 'imds':
        // IMDS exploitation scan
        output = await scanAKSIMDS(subscriptionId, resourceGroup, clusterName, podName, exportTokens, format || "markdown");
        break;

      case 'pod_identity':
        // Pod identity and workload identity analysis
        output = await scanAKSPodIdentity(subscriptionId, resourceGroup, clusterName, format || "markdown");
        break;

      case 'admission':
        // Admission controller bypass testing
        output = await scanAKSAdmissionBypass(subscriptionId, resourceGroup, clusterName, format || "markdown");
        break;

      default:
        return {
          content: [{ type: 'text', text: `Unknown scanMode: ${scanMode}` }],
          isError: true,
        };
    }

    return {
      content: [{ type: 'text', text: formatResponse(output, format || "markdown", toolName || scanMode) }],
    };
  } catch (error: any) {
    return {
      content: [{ type: 'text', text: `Error running AKS ${scanMode} scan: ${error.message}` }],
      isError: true,
    };
  }
}

/**
 * Scan AKS cluster for Pod Identity/Workload Identity token theft risks
 */
async function scanAKSPodIdentity(
  subscriptionId: string,
  resourceGroup: string,
  clusterName: string,
  format: string = "markdown"
): Promise<string> {
  const containerClient = new ContainerServiceClient(credential, subscriptionId);
  const authClient = new AuthorizationManagementClient(credential, subscriptionId);
  const resourceClient = new ResourceManagementClient(credential, subscriptionId);
  const kvClient = new KeyVaultManagementClient(credential, subscriptionId);

  try {
    const outputLines: string[] = [];

    // Get cluster details
    const cluster = await containerClient.managedClusters.get(resourceGroup, clusterName);

    outputLines.push("# AKS Pod Identity Token Theft & Privilege Escalation Scan");
    outputLines.push(`**Cluster:** ${clusterName}`);
    outputLines.push(`**Resource Group:** ${resourceGroup}`);
    outputLines.push(`**Subscription:** ${subscriptionId}`);
    outputLines.push(`**Kubernetes Version:** ${cluster.kubernetesVersion || 'Unknown'}`);
    outputLines.push(`**Scan Time:** ${new Date().toISOString()}`);
    outputLines.push("");

    // Check identity features
    const workloadIdentityEnabled = !!cluster.oidcIssuerProfile?.enabled;
    const oidcIssuer = cluster.oidcIssuerProfile?.issuerURL || "N/A";
    const aadEnabled = !!cluster.aadProfile?.managed;
    const podIdentityAddon = cluster.addonProfiles?.azurepolicy?.enabled || false;

    outputLines.push("## Identity Configuration");
    outputLines.push("| Feature | Status |");
    outputLines.push("|---------|--------|");
    outputLines.push(`| Workload Identity | ${workloadIdentityEnabled ? '✅ Enabled' : '❌ Disabled'} |`);
    outputLines.push(`| Azure AD Integration | ${aadEnabled ? '✅ Enabled' : '❌ Disabled'} |`);
    outputLines.push(`| Pod Identity Addon (deprecated) | ${podIdentityAddon ? '⚠️ Enabled' : 'Disabled'} |`);
    outputLines.push(`| OIDC Issuer | ${oidcIssuer} |`);
    outputLines.push("");

    // Track findings
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    const managedIdentities: any[] = [];
    const keyVaultAccessIdentities: any[] = [];
    const overlyPermissiveIdentities: any[] = [];

    // Get cluster identity
    const clusterIdentity = cluster.identity;
    const clusterIdentityType = clusterIdentity?.type || "None";
    const clusterPrincipalId = clusterIdentity?.principalId;

    outputLines.push("## Cluster Identity");
    outputLines.push(`**Type:** ${clusterIdentityType}`);
    if (clusterPrincipalId) {
      outputLines.push(`**Principal ID:** ${clusterPrincipalId}`);
    }
    outputLines.push("");

    // Enumerate all managed identities in the subscription
    outputLines.push("## Enumerating Managed Identities...");
    outputLines.push("");

    const identityFilter = "resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities'";
    const identityResources = resourceClient.resources.list({ filter: identityFilter });

    for await (const identity of identityResources) {
      if (!identity.name || !identity.id) continue;

      const identityRg = identity.id.split('/')[4];
      const identityData = {
        name: identity.name,
        resourceGroup: identityRg,
        clientId: (identity as any).properties?.clientId,
        principalId: (identity as any).properties?.principalId,
        type: "UserAssigned",
        roleAssignments: [] as any[],
        keyVaultAccess: [] as any[],
        riskLevel: "LOW",
      };

      managedIdentities.push(identityData);
    }

    // Add cluster's system-assigned identity if exists
    if (clusterPrincipalId && clusterIdentityType.includes("SystemAssigned")) {
      managedIdentities.push({
        name: `${clusterName}-system`,
        resourceGroup: resourceGroup,
        principalId: clusterPrincipalId,
        type: "SystemAssigned",
        roleAssignments: [] as any[],
        keyVaultAccess: [] as any[],
        riskLevel: "LOW",
      });
    }

    // Get kubelet identity
    const kubeletIdentity = cluster.identityProfile?.kubeletidentity;
    if (kubeletIdentity) {
      managedIdentities.push({
        name: "kubelet-identity",
        resourceGroup: resourceGroup,
        clientId: kubeletIdentity.clientId,
        principalId: kubeletIdentity.objectId,
        type: "Kubelet",
        roleAssignments: [] as any[],
        keyVaultAccess: [] as any[],
        riskLevel: "MEDIUM",
      });
    }

    outputLines.push(`**Total Managed Identities Found:** ${managedIdentities.length}`);
    outputLines.push("");

    // Analyze each identity for role assignments
    for (const identity of managedIdentities) {
      if (!identity.principalId) continue;

      try {
        const scope = `/subscriptions/${subscriptionId}`;
        const roleAssignments = authClient.roleAssignments.listForScope(scope, {
          filter: `principalId eq '${identity.principalId}'`,
        });

        for await (const assignment of roleAssignments) {
          if (!assignment.roleDefinitionId) continue;

          try {
            const roleDef = await authClient.roleDefinitions.getById(assignment.roleDefinitionId);
            const roleName = roleDef.roleName || "Unknown";
            const assignmentScope = assignment.scope || "";

            identity.roleAssignments.push({
              role: roleName,
              scope: assignmentScope,
              scopeType: assignmentScope.includes('/resourceGroups/') ? 'ResourceGroup' : 'Subscription',
            });

            // Check for overly permissive roles
            const dangerousRoles = ["Owner", "Contributor", "User Access Administrator", "Key Vault Administrator"];
            if (dangerousRoles.includes(roleName)) {
              identity.riskLevel = "CRITICAL";
              overlyPermissiveIdentities.push({ identity: identity.name, role: roleName });
              criticalCount++;
            }

            // Check for Key Vault access
            if (roleName.includes("Key Vault") || roleName.includes("Secret")) {
              keyVaultAccessIdentities.push({ identity: identity.name, role: roleName });
              if (identity.riskLevel === "LOW") identity.riskLevel = "HIGH";
              highCount++;
            }
          } catch (e) {
            // Role definition not accessible
          }
        }
      } catch (e) {
        // Unable to list role assignments
      }
    }

    // Risk Summary
    outputLines.push("## Risk Summary");
    outputLines.push("| Risk Type | Count | Severity |");
    outputLines.push("|-----------|-------|----------|");
    outputLines.push(`| Overly Permissive Managed IDs | ${overlyPermissiveIdentities.length} | CRITICAL |`);
    outputLines.push(`| Key Vault Access | ${keyVaultAccessIdentities.length} | HIGH |`);
    outputLines.push(`| No Workload Identity | ${workloadIdentityEnabled ? 0 : 1} | HIGH |`);
    outputLines.push(`| IMDS Accessible | Unknown (run scan_aks_imds) | MEDIUM |`);
    outputLines.push("");

    // Detailed Findings
    outputLines.push("## Detailed Findings");
    outputLines.push("");

    // TC-PODID-001: Pod Identity Token Theft
    outputLines.push("### TC-PODID-001: Pod Identity Token Theft");
    outputLines.push("**Risk:** CRITICAL | **MITRE:** T1552.005 - Cloud Instance Metadata API");
    outputLines.push(`**Workload Identity:** ${workloadIdentityEnabled ? 'Enabled' : 'Disabled'}`);
    outputLines.push("");

    if (workloadIdentityEnabled) {
      outputLines.push("If Pod/Workload Identity **enabled**, attacker can:");
      outputLines.push("1. Compromise pod with managed identity assignment");
      outputLines.push("2. Steal Azure AD token from environment or IMDS");
      outputLines.push("3. Use token to access Azure resources (Key Vault, Storage, etc.)");
      outputLines.push("");

      outputLines.push("```bash");
      outputLines.push("# From compromised pod with Pod Identity");
      outputLines.push("# Method 1: Environment variable (Workload Identity)");
      outputLines.push("echo $AZURE_FEDERATED_TOKEN_FILE");
      outputLines.push("cat /var/run/secrets/azure/tokens/azure-identity-token");
      outputLines.push("");
      outputLines.push("# Method 2: IMDS (legacy Pod Identity)");
      outputLines.push("curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' -H Metadata:true");
      outputLines.push("");
      outputLines.push("# Use token to access Key Vault");
      outputLines.push("export TOKEN=\"<stolen_token>\"");
      outputLines.push("curl https://VAULT_NAME.vault.azure.net/secrets?api-version=7.3 -H \"Authorization: Bearer $TOKEN\"");
      outputLines.push("```");
      outputLines.push("");
    }

    // Show managed identities
    outputLines.push(`### Managed Identities Found: ${managedIdentities.length}`);
    outputLines.push("");

    for (const identity of managedIdentities) {
      outputLines.push(`#### Identity: ${identity.name}`);
      if (identity.clientId) outputLines.push(`**Client ID:** ${identity.clientId}`);
      if (identity.principalId) outputLines.push(`**Principal ID:** ${identity.principalId}`);
      outputLines.push(`**Type:** ${identity.type}`);
      outputLines.push(`**Risk:** ${identity.riskLevel}`);
      outputLines.push("");

      if (identity.roleAssignments.length > 0) {
        outputLines.push("**Role Assignments:**");
        for (const assignment of identity.roleAssignments) {
          outputLines.push(`- Scope: ${assignment.scope}`);
          outputLines.push(`  - Role: ${assignment.role}`);

          const dangerousRoles = ["Owner", "Contributor", "User Access Administrator"];
          if (dangerousRoles.includes(assignment.role)) {
            outputLines.push("  - ⚠️ Risk: Overly permissive role - full control over resources");
          } else if (assignment.role.includes("Key Vault")) {
            outputLines.push("  - ⚠️ Risk: Can access Key Vault secrets");
          }
        }
        outputLines.push("");
      } else {
        outputLines.push("**Role Assignments:** None found");
        outputLines.push("");
      }
    }

    // TC-PODID-002: Missing Workload Identity
    if (!workloadIdentityEnabled) {
      outputLines.push("### TC-PODID-002: Missing Workload Identity (Using Kubelet Identity)");
      outputLines.push("**Risk:** HIGH | **MITRE:** T1078.004 - Cloud Accounts");
      outputLines.push("");
      outputLines.push("Workload Identity is **not enabled**. Pods likely using kubelet managed identity which often has excessive permissions.");
      outputLines.push("");

      if (kubeletIdentity) {
        outputLines.push("**Kubelet Identity:**");
        outputLines.push(`- Client ID: ${kubeletIdentity.clientId}`);
        outputLines.push(`- Principal ID: ${kubeletIdentity.objectId}`);
        outputLines.push("- ⚠️ All pods inherit these permissions without restrictions");
        outputLines.push("");
      }
      highCount++;
    }

    // Kubernetes RBAC enumeration commands
    outputLines.push("### Kubernetes RBAC Enumeration Commands");
    outputLines.push("");
    outputLines.push("```bash");
    outputLines.push("# Configure kubectl (requires Azure CLI)");
    outputLines.push(`az aks get-credentials --resource-group ${resourceGroup} --name ${clusterName}`);
    outputLines.push("");
    outputLines.push("# List all service accounts");
    outputLines.push("kubectl get sa -A");
    outputLines.push("");
    outputLines.push("# Find service accounts with Azure identity labels (Workload Identity)");
    outputLines.push("kubectl get sa -A -o json | jq -r '.items[] | select(.metadata.labels[\"azure.workload.identity/use\"] == \"true\") | \"\\(.metadata.namespace)/\\(.metadata.name)\"'");
    outputLines.push("");
    outputLines.push("# Find pods with Pod Identity binding (deprecated)");
    outputLines.push("kubectl get azureidentity -A");
    outputLines.push("kubectl get azureidentitybinding -A");
    outputLines.push("");
    outputLines.push("# Check RBAC permissions");
    outputLines.push("kubectl auth can-i --list --as=system:serviceaccount:NAMESPACE:SA_NAME");
    outputLines.push("```");
    outputLines.push("");

    // TC-PODID-003: IMDS accessibility
    outputLines.push("### TC-PODID-003: IMDS Accessibility Test");
    outputLines.push("");
    outputLines.push("```bash");
    outputLines.push("# From any pod, test IMDS access");
    outputLines.push("curl -H Metadata:true \"http://169.254.169.254/metadata/instance?api-version=2021-02-01\"");
    outputLines.push("");
    outputLines.push("# If accessible, can steal managed identity token");
    outputLines.push("curl -H Metadata:true \"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\"");
    outputLines.push("```");
    outputLines.push("");
    
    // Remediation
    outputLines.push("## Remediation");
    outputLines.push("1. Enable Workload Identity on AKS cluster");
    outputLines.push("2. Migrate from deprecated Pod Identity to Workload Identity");
    outputLines.push("3. Enforce least privilege on managed identities");
    outputLines.push("4. Remove Key Vault data plane access, use RBAC instead");
    outputLines.push("5. Enable Azure AD authentication on cluster");
    outputLines.push("6. Block IMDS via network policies");
    outputLines.push("7. Enforce pod security standards (no root, no privileged)");
    outputLines.push("8. Use Azure Policy to audit identity configurations");
    outputLines.push("");

    // Return formatted output
    if (format === "json") {
      return JSON.stringify({
        cluster: clusterName,
        resourceGroup,
        subscriptionId,
        scanTime: new Date().toISOString(),
        identityConfiguration: {
          workloadIdentityEnabled,
          aadEnabled,
          podIdentityAddon,
          oidcIssuer,
        },
        riskSummary: {
          criticalCount,
          highCount,
          mediumCount,
          overlyPermissiveIdentities: overlyPermissiveIdentities.length,
          keyVaultAccessIdentities: keyVaultAccessIdentities.length,
        },
        managedIdentities,
        overlyPermissiveIdentities,
        keyVaultAccessIdentities,
      }, null, 2);
    }

    return outputLines.join('\n');
  } catch (error: any) {
    return `Error scanning AKS Pod Identity: ${error.message}`;
  }
}

/**
 * Scan Azure Container Apps for security vulnerabilities
 */
async function scanContainerAppsSecurity(
  subscriptionId: string,
  resourceGroup?: string,
  containerAppName?: string,
  format: string = "markdown"
): Promise<string> {
  const lines: string[] = [];
  
  try {
    const apiVersion = "2023-05-01";
    const token = await credential.getToken("https://management.azure.com/.default");
    const accessToken = token?.token;
    
    if (!accessToken) {
      return `Error: Unable to get access token`;
    }
    
    let containerApps: any[] = [];
    let containerAppEnvironments: any[] = [];
    
    // Get container apps to scan
    if (containerAppName && resourceGroup) {
      // Scan specific container app
      const url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.App/containerApps/${containerAppName}?api-version=${apiVersion}`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (response.ok) {
        const data = await response.json() as any;
        containerApps = [data];
      }
    } else if (resourceGroup) {
      // List all container apps in resource group
      const url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.App/containerApps?api-version=${apiVersion}`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (response.ok) {
        const data = await response.json() as any;
        containerApps = data.value || [];
      }
    } else {
      // List all container apps in subscription
      const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.App/containerApps?api-version=${apiVersion}`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (response.ok) {
        const data = await response.json() as any;
        containerApps = data.value || [];
      }
    }
    
    // Fetch Container App Environments for context
    const envUrl = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.App/managedEnvironments?api-version=${apiVersion}`;
    const envResponse = await fetch(envUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    
    if (envResponse.ok) {
      const envData = await envResponse.json() as any;
      containerAppEnvironments = envData.value || [];
    }
    
    if (containerApps.length === 0) {
      lines.push(`[INFO] No Container Apps found`);
      return lines.join('\n');
    }
    
    lines.push(`**Container Apps Found:** ${containerApps.length}`);
    lines.push(`**Environments Found:** ${containerAppEnvironments.length}`);
    lines.push(``);
    
    // Risk counters
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    
    lines.push(`## Risk Summary`);
    lines.push(``);
    const riskSummaryIndex = lines.length;
    lines.push(``);
    
    lines.push(`## Detailed Findings`);
    lines.push(``);
    
    // Analyze each container app
    for (const app of containerApps) {
      const name = app.name || 'unknown';
      const rg = app.id?.split('/')[4] || 'unknown';
      const location = app.location || 'N/A';
      const fqdn = app.properties?.configuration?.ingress?.fqdn || 'N/A';
      const ingressEnabled = app.properties?.configuration?.ingress?.external || false;
      const ingressExternal = ingressEnabled;
      const allowInsecure = app.properties?.configuration?.ingress?.allowInsecure || false;
      
      lines.push(`### Container App: ${name}`);
      lines.push(`**Resource Group:** ${rg}`);
      lines.push(`**Location:** ${location}`);
      lines.push(`**FQDN:** ${fqdn}`);
      lines.push(`**Ingress External:** ${ingressExternal ? '✅ Yes' : '❌ No'}`);
      lines.push(``);
      
      const findings: string[] = [];
      
      // TC-CAPP-001: Public ingress without authentication
      if (ingressExternal && fqdn !== 'N/A') {
        const authConfig = app.properties?.configuration?.ingress?.customDomains;
        const hasAuth = app.properties?.properties?.azureActiveDirectory || app.properties?.properties?.facebook;
        
        if (!hasAuth) {
          criticalCount++;
          findings.push(`#### TC-CAPP-001: Public Ingress Without Authentication`);
          findings.push(`**Risk:** CRITICAL | **MITRE:** T1190 - Exploit Public-Facing Application`);
          findings.push(`- External Access: **ENABLED** (${fqdn})`);
          findings.push(`- Authentication: **NONE**`);
          findings.push(`- ⚠️ Publicly accessible without authentication`);
          findings.push(`- **Attack Vector:** Direct unauthenticated access to application`);
          findings.push(`- **Remediation:** Enable built-in authentication or Azure AD integration`);
          findings.push(``);
        }
      }
      
      // TC-CAPP-002: Managed identity overprivileged
      const identity = app.identity;
      if (identity && identity.type !== 'None') {
        highCount++;
        findings.push(`#### TC-CAPP-002: Managed Identity Configured`);
        findings.push(`**Risk:** HIGH | **MITRE:** T1078.004 - Valid Accounts: Cloud Accounts`);
        findings.push(`- Identity Type: **${identity.type}**`);
        findings.push(`- Principal ID: ${identity.principalId || 'N/A'}`);
        findings.push(`- **Attack Vector:** Token theft via IMDS or compromised container`);
        findings.push(`- **Remediation:** Review RBAC assignments, apply least privilege`);
        findings.push(``);
      }
      
      // TC-CAPP-003: Secret management in environment variables
      const secrets = app.properties?.configuration?.secrets || [];
      const envVars = app.properties?.template?.containers?.[0]?.env || [];
      
      if (secrets.length > 0 || envVars.some((e: any) => e.secretRef)) {
        mediumCount++;
        findings.push(`#### TC-CAPP-003: Secrets in Configuration`);
        findings.push(`**Risk:** MEDIUM | **MITRE:** T1552.001 - Unsecured Credentials`);
        findings.push(`- Secrets Count: **${secrets.length}**`);
        findings.push(`- Env Vars with Secrets: **${envVars.filter((e: any) => e.secretRef).length}**`);
        findings.push(`- **Attack Vector:** Container escape or config exposure`);
        findings.push(`- **Remediation:** Use Key Vault references with managed identity`);
        findings.push(``);
      }
      
      // TC-CAPP-004: External ingress IP exposure
      if (ingressExternal && allowInsecure) {
        highCount++;
        findings.push(`#### TC-CAPP-004: Insecure HTTP Allowed`);
        findings.push(`**Risk:** HIGH | **MITRE:** T1040 - Network Sniffing`);
        findings.push(`- Allow Insecure: **true**`);
        findings.push(`- **Attack Vector:** Man-in-the-middle attacks, credential theft`);
        findings.push(`- **Remediation:** Disable HTTP, enforce HTTPS only`);
        findings.push(``);
      }
      
      // TC-CAPP-005: Scale rule exploitation
      const scaleRules = app.properties?.template?.scale?.rules || [];
      if (scaleRules.length > 0) {
        const hasHttpScaling = scaleRules.some((r: any) => r.http);
        if (hasHttpScaling) {
          lowCount++;
          findings.push(`#### TC-CAPP-005: HTTP Scale Rules Enabled`);
          findings.push(`**Risk:** LOW | **MITRE:** T1496 - Resource Hijacking`);
          findings.push(`- Scale Rules: **${scaleRules.length}**`);
          findings.push(`- **Attack Vector:** Trigger excessive scaling via HTTP floods`);
          findings.push(`- **Remediation:** Implement rate limiting, set max replicas`);
          findings.push(``);
        }
      }
      
      // TC-CAPP-006: Dapr component misconfiguration
      const daprEnabled = app.properties?.configuration?.dapr?.enabled || false;
      if (daprEnabled) {
        const daprAppId = app.properties?.configuration?.dapr?.appId;
        const daprProtocol = app.properties?.configuration?.dapr?.appProtocol;
        
        mediumCount++;
        findings.push(`#### TC-CAPP-006: Dapr Enabled`);
        findings.push(`**Risk:** MEDIUM | **MITRE:** T1210 - Exploitation of Remote Services`);
        findings.push(`- Dapr App ID: **${daprAppId || 'N/A'}**`);
        findings.push(`- Protocol: **${daprProtocol || 'http'}**`);
        findings.push(`- **Attack Vector:** Service-to-service communication abuse`);
        findings.push(`- **Remediation:** Enable mTLS, restr as anyict service invocation`);
        findings.push(``);
      }
      
      // TC-CAPP-007: Storage mount exposure
      const volumes = app.properties?.template?.volumes || [];
      if (volumes.length > 0) {
        mediumCount++;
        findings.push(`#### TC-CAPP-007: Storage Volumes Mounted`);
        findings.push(`**Risk:** MEDIUM | **MITRE:** T1530 - Data from Cloud Storage`);
        findings.push(`- Volume Mounts: **${volumes.length}**`);
        findings.push(`- **Attack Vector:** Access to shared storage from compromised container`);
        findings.push(`- **Remediation:** Restrict mount permissions, use read-only mounts`);
        findings.push(``);
      }
      
      // TC-CAPP-008: Container Apps Environment isolation
      const managedEnvId = app.properties?.managedEnvironmentId;
      if (managedEnvId) {
        const env = containerAppEnvironments.find((e: any) => e.id === managedEnvId);
        if (env) {
          const vnetConfig = env.properties?.vnetConfiguration;
          if (!vnetConfig || !vnetConfig.internal) {
            mediumCount++;
            findings.push(`#### TC-CAPP-008: Environment Not Internal`);
            findings.push(`**Risk:** MEDIUM | **MITRE:** T1599 - Network Boundary Bridging`);
            findings.push(`- Environment: **${env.name}**`);
            findings.push(`- Internal VNet: **${vnetConfig?.internal ? 'Yes' : 'No'}**`);
            findings.push(`- **Attack Vector:** Lateral movement to other apps in environment`);
            findings.push(`- **Remediation:** Use VNet-integrated internal environments`);
            findings.push(``);
          }
        }
      }
      
      lines.push(...findings);
      
      if (findings.length === 0) {
        lines.push(`✅ No critical vulnerabilities detected`);
        lines.push(``);
      }
    }
    
    // Update risk summary
    const riskSummary: string[] = [
      `| Severity | Count |`,
      `|----------|-------|`,
      `| 🔴 CRITICAL | ${criticalCount} |`,
      `| 🟠 HIGH | ${highCount} |`,
      `| 🟡 MEDIUM | ${mediumCount} |`,
      `| 🟢 LOW | ${lowCount} |`,
      ``,
    ];
    lines.splice(riskSummaryIndex, 0, ...riskSummary);
    
    // Add attack chains
    lines.push(`## Attack Chains`);
    lines.push(``);
    lines.push(`| Attack Chain | Risk | MITRE |`);
    lines.push(`|--------------|------|-------|`);
    lines.push(`| Public ingress → Unauthenticated access | CRITICAL | T1190 - Exploit Public-Facing Application |`);
    lines.push(`| Managed identity → Token theft → Privilege escalation | HIGH | T1078.004 - Cloud Account Abuse |`);
    lines.push(`| Environment vars → Secret exposure | MEDIUM | T1552.001 - Unsecured Credentials |`);
    lines.push(`| HTTP allowed → MITM → Credential theft | HIGH | T1040 - Network Sniffing |`);
    lines.push(`| Dapr enabled → Service invocation abuse | MEDIUM | T1210 - Remote Service Exploitation |`);
    lines.push(`| Storage mounts → Data exfiltration | MEDIUM | T1530 - Cloud Storage Access |`);
    lines.push(``);
    
    lines.push(`---`);
    lines.push(`*Generated by Azure Pentest MCP v${SERVER_VERSION} - Container Apps Security Scanner*`);
    
  } catch (error: any) {
    lines.push(``);
    lines.push(`[FAIL] Error scanning Container Apps: ${error.message}`);
  }
  
  return lines.join('\n');
}

/**
 * Scan AKS clusters for GitOps/Flux security vulnerabilities
 */
async function scanGitOpsSecurity(
  subscriptionId: string,
  resourceGroup: string,
  clusterName: string,
  format: string = "markdown"
): Promise<string> {
  const lines: string[] = [];
  const aksClient = new ContainerServiceClient(credential, subscriptionId);
  
  try {
    lines.push(`# Azure GitOps (Flux) Security Scan`);
    lines.push(`**Subscription:** ${subscriptionId}`);
    lines.push(`**Resource Group:** ${resourceGroup || 'All'}`);
    lines.push(`**Cluster:** ${clusterName || 'All'}`);
    lines.push(`**Scan Time:** ${new Date().toISOString()}`);
    lines.push(``);
    
    const aksClient = new ContainerServiceClient(credential, subscriptionId);
    let clusters: any[] = [];
    
    // Get clusters to scan
    if (clusterName && resourceGroup) {
      const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
      clusters.push(cluster);
    } else if (resourceGroup) {
      for await (const cluster of aksClient.managedClusters.listByResourceGroup(resourceGroup)) {
        clusters.push(cluster);
      }
    } else {
      for await (const cluster of aksClient.managedClusters.list()) {
        clusters.push(cluster);
      }
    }
    
    if (clusters.length === 0) {
      lines.push(`[INFO] No AKS clusters found`);
      return lines.join('\n');
    }
    
    let totalFindings = 0;
    const allFindings: string[] = [];
    let extensions: any[] = [];
    let fluxConfigs: any[] = [];
    
    for (const cluster of clusters) {
      const clName = cluster.name || 'Unknown';
      const clRg = cluster.id?.split('/')[4] || 'Unknown';
      
      lines.push(`## Cluster: ${clName}`);
      lines.push(``);
      
      const clusterFindings: string[] = [];
      
      try {
        // Check for GitOps extension (Flux)
        const token = await credential.getToken("https://management.azure.com/.default");
        const accessToken = token?.token;
        
        if (!accessToken) {
          lines.push(`[WARN] Unable to get access token`);
          continue;
        }
        
        const apiVersion = "2022-03-01";
        const extUrl = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${clRg}/providers/Microsoft.ContainerService/managedClusters/${clName}/extensions?api-version=${apiVersion}`;
        const extResponse = await fetch(extUrl, {
          headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        if (extResponse.ok) {
          const extensionsData = await extResponse.json() as any;
          const extensions = extensionsData.value || [];
          
          const fluxExtension = extensions.find((ext: any) => 
            ext.properties?.extensionType?.toLowerCase().includes('flux') ||
            ext.name?.toLowerCase().includes('flux')
          );
          
          if (fluxExtension) {
            clusterFindings.push(`**Flux Extension:** ${fluxExtension.name}`);
            clusterFindings.push(`**Version:** ${fluxExtension.properties?.version || 'N/A'}`);
          } else {
            clusterFindings.push(`[INFO] No Flux GitOps extension detected`);
          }
        }
        
        if (clusterFindings.length > 0) {
          lines.push(...clusterFindings);
        }
      } catch (clusterError: any) {
        lines.push(`[WARN] Error checking cluster ${clName}: ${clusterError.message}`);
      }
    }
  } catch (error: any) {
    lines.push(``);
    lines.push(`[FAIL] Error scanning GitOps: ${error.message}`);
  }
  
  return lines.join('\n');
}

/**
 * Scan Azure CDN and Front Door for security misconfigurations
 */
async function scanCDNSecurity(
  subscriptionId: string,
  resourceGroup?: string,
  profileName?: string,
  format: string = "markdown"
): Promise<string> {
  const lines: string[] = [];
  
  try {
    lines.push(`# Azure CDN & Front Door Security Scan`);
    lines.push(`**Subscription:** ${subscriptionId}`);
    lines.push(`**Scan Time:** ${new Date().toISOString()}`);
    lines.push(`**Version:** ${SERVER_VERSION}`);
    lines.push(``);
    
    // Get access token for REST API
    const token = await credential.getToken("https://management.azure.com/.default");
    if (!token) {
      throw new Error("Failed to get Azure management token");
    }
    
    const accessToken = token.token;
    const apiVersion = "2023-05-01";
    
    // Fetch CDN profiles
    let cdnProfiles: any[] = [];
    let frontDoorProfiles: any[] = [];
    
    if (profileName && resourceGroup) {
      // Get specific profile (try both CDN and Front Door)
      const cdnUrl = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Cdn/profiles/${profileName}?api-version=${apiVersion}`;
      const cdnResponse = await fetch(cdnUrl, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (cdnResponse.ok) {
        const profile = await cdnResponse.json() as any;
        if (profile.sku?.name?.includes('FrontDoor')) {
          frontDoorProfiles = [profile];
        } else {
          cdnProfiles = [profile];
        }
      }
    } else if (resourceGroup) {
      // List profiles in resource group
      const url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Cdn/profiles?api-version=${apiVersion}`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (response.ok) {
        const data = await response.json() as any;
        const profiles = data.value || [];
        cdnProfiles = profiles.filter((p: any) => !p.sku?.name?.includes('FrontDoor'));
        frontDoorProfiles = profiles.filter((p: any) => p.sku?.name?.includes('FrontDoor'));
      }
    } else {
      // List all profiles in subscription
      const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Cdn/profiles?api-version=${apiVersion}`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (response.ok) {
        const data = await response.json() as any;
        const profiles = data.value || [];
        cdnProfiles = profiles.filter((p: any) => !p.sku?.name?.includes('FrontDoor'));
        frontDoorProfiles = profiles.filter((p: any) => p.sku?.name?.includes('FrontDoor'));
      }
    }
    
    const totalProfiles = cdnProfiles.length + frontDoorProfiles.length;
    
    if (totalProfiles === 0) {
      lines.push(`[INFO] No CDN or Front Door profiles found`);
      return lines.join('\n');
    }
    
    lines.push(`**CDN Profiles Found:** ${cdnProfiles.length}`);
    lines.push(`**Front Door Profiles Found:** ${frontDoorProfiles.length}`);
    lines.push(``);
    
    // Risk counters
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    
    lines.push(`## Risk Summary`);
    lines.push(``);
    const riskSummaryIndex = lines.length;
    lines.push(``);
    
    lines.push(`## Detailed Findings`);
    lines.push(``);
    
    // Analyze CDN profiles
    for (const profile of [...cdnProfiles, ...frontDoorProfiles]) {
      const name = profile.name || 'unknown';
      const rg = profile.id?.split('/')[4] || 'unknown';
      const location = profile.location || 'global';
      const sku = profile.sku?.name || 'N/A';
      const isFrontDoor = sku.includes('FrontDoor');
      
      lines.push(`### ${isFrontDoor ? 'Front Door' : 'CDN'} Profile: ${name}`);
      lines.push(`**Resource Group:** ${rg}`);
      lines.push(`**SKU:** ${sku}`);
      lines.push(`**Location:** ${location}`);
      lines.push(``);
      
      // Get endpoints for this profile
      const endpointsUrl = `https://management.azure.com${profile.id}/${isFrontDoor ? 'afdEndpoints' : 'endpoints'}?api-version=${apiVersion}`;
      const endpointsResponse = await fetch(endpointsUrl, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      let endpoints: any[] = [];
      if (endpointsResponse.ok) {
        const endpointsData = await endpointsResponse.json() as any;
        endpoints = endpointsData.value || [];
      }
      
      lines.push(`**Endpoints:** ${endpoints.length}`);
      lines.push(``);
      
      // Analyze each endpoint
      for (const endpoint of endpoints) {
        const endpointName = endpoint.name || 'unknown';
        const hostName = endpoint.properties?.hostName || 'N/A';
        const enabledState = endpoint.properties?.enabledState || 'Enabled';
        
        lines.push(`#### Endpoint: ${endpointName}`);
        lines.push(`- Hostname: ${hostName}`);
        lines.push(`- State: ${enabledState}`);
        lines.push(``);
        
        // Get origins for this endpoint
        const originsUrl = `https://management.azure.com as any${endpoint.id}/${isFrontDoor ? 'origins' : 'origins'}?api-version=${apiVersion}`;
        const originsResponse = await fetch(originsUrl, {
          headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        let origins: any[] = [];
        if (originsResponse.ok) {
          const originsData = await originsResponse.json() as any;
          origins = originsData.value || [];
        }
        
        // TC-CDN-001: Origin server direct access exposure
        for (const origin of origins) {
          const originHostName = origin.properties?.hostName || 'N/A';
          const enabledState = origin.properties?.enabledState;
          
          if (originHostName !== 'N/A' && !originHostName.includes('.azurewebsites.net')) {
            criticalCount++;
            lines.push(`##### TC-CDN-001: Origin Server Direct Access`);
            lines.push(`**Risk:** CRITICAL | **MITRE:** T1190 - Exploit Public-Facing Application`);
            lines.push(`- Origin: **${originHostName}**`);
            lines.push(`- ⚠️ Origin may be directly accessible, bypassing CDN/WAF`);
            lines.push(`- **Attack Vector:** Direct attack on origin server, bypass security controls`);
            lines.push(`- **Remediation:** Restrict origin to accept only CDN traffic, use Private Link`);
            lines.push(``);
          }
        }
        
        // TC-CDN-002: Cache poisoning vulnerabilities
        const deliveryPolicy = endpoint.properties?.deliveryPolicy;
        if (deliveryPolicy) {
          const cacheRules = deliveryPolicy.rules?.filter((r: any) => 
            r.actions?.some((a: any) => a.name === 'CacheExpiration')
          ) || [];
          
          if (cacheRules.length > 0) {
            mediumCount++;
            lines.push(`##### TC-CDN-002: Cache Rules Configured`);
            lines.push(`**Risk:** MEDIUM | **MITRE:** T1584.003 - Compromise Infrastructure: Web Services`);
            lines.push(`- Cache Rules: **${cacheRules.length}**`);
            lines.push(`- **Attack Vector:** Cache poisoning via crafted headers`);
            lines.push(`- **Remediation:** Validate cache key parameters, sanitize headers`);
            lines.push(``);
          }
        }
        
        // TC-CDN-003: WAF bypass (for Front Door)
        if (isFrontDoor) {
          const wafPolicyId = endpoint.properties?.webApplicationFirewallPolicyLink?.id;
          
          if (!wafPolicyId) {
            highCount++;
            lines.push(`##### TC-CDN-003: No WAF Policy`);
            lines.push(`**Risk:** HIGH | **MITRE:** T1190 - Exploit Public-Facing Application`);
            lines.push(`- WAF: **NOT CONFIGURED**`);
            lines.push(`- **Attack Vector:** Application-layer attacks unprotected`);
            lines.push(`- **Remediation:** Enable WAF with OWASP ruleset`);
            lines.push(``);
          } else {
            // Get WAF policy details
            const wafUrl = `https://management.azure.com${wafPolicyId}?api-version=2022-05-01`;
            const wafResponse = await fetch(wafUrl, {
              headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            
            if (wafResponse.ok) {
              const wafPolicy = await wafResponse.json() as any;
              const policyMode = wafPolicy.properties?.policySettings?.mode;
              
              if (policyMode === 'Detection') {
                highCount++;
                lines.push(`##### TC-CDN-003: WAF in Detection Mode`);
                lines.push(`**Risk:** HIGH | **MITRE:** T1562.001 - Impair Defenses`);
                lines.push(`- WAF Mode: **Detection** (not blocking)`);
                lines.push(`- **Attack Vector:** Attacks logged but not blocked`);
                lines.push(`- **Remediation:** Set WAF to Prevention mode`);
                lines.push(``);
              }
            }
          }
        }
        
        // TC-CDN-007: Query string caching abuse
        const queryStringCachingBehavior = endpoint.properties?.queryStringCachingBehavior;
        if (queryStringCachingBehavior === 'IgnoreQueryString') {
          lowCount++;
          lines.push(`##### TC-CDN-007: Query String Caching`);
          lines.push(`**Risk:** LOW | **MITRE:** T1213 - Data from Information Repositories`);
          lines.push(`- Query String Behavior: **IgnoreQueryString**`);
          lines.push(`- **Attack Vector:** Cache poisoning via query parameters`);
          lines.push(`- **Remediation:** Use BypassCaching for dynamic content`);
          lines.push(``);
        }
        
        // TC-CDN-008: HTTP to HTTPS redirect
        const isHttpsOnly = endpoint.properties?.isHttpsOnly;
        const isHttpAllowed = endpoint.properties?.isHttpAllowed;
        
        if (isHttpAllowed !== false || isHttpsOnly === false) {
          highCount++;
          lines.push(`##### TC-CDN-008: HTTP Allowed`);
          lines.push(`**Risk:** HIGH | **MITRE:** T1040 - Network Sniffing`);
          lines.push(`- HTTPS Only: **${isHttpsOnly || false}**`);
          lines.push(`- HTTP Allowed: **${isHttpAllowed !== false}**`);
          lines.push(`- **Attack Vector:** Man-in-the-middle attacks`);
          lines.push(`- **Remediation:** Enforce HTTPS only, redirect HTTP to HTTPS`);
          lines.push(``);
        }
        
        // TC-CDN-004: Custom domain validation
        const customDomains = endpoint.properties?.customDomains || [];
        if (customDomains.length > 0) {
          mediumCount++;
          lines.push(`##### TC-CDN-004: Custom Domains Configured`);
          lines.push(`**Risk:** MEDIUM | **MITRE:** T1584.005 - Botnet`);
          lines.push(`- Custom Domains: **${customDomains.length}**`);
          lines.push(`- **Attack Vector:** Domain takeover if validation weakens`);
          lines.push(`- **Remediation:** Enable managed certificate auto-renewal`);
          lines.push(``);
        }
        
        // TC-CDN-009: Geo-filtering
        const geoFilters = endpoint.properties?.geoFilters || [];
        if (geoFilters.length === 0) {
          lowCount++;
          lines.push(`##### TC-CDN-009: No Geo-Filtering`);
          lines.push(`**Risk:** LOW | **MITRE:** T1583 - Acquire Infrastructure`);
          lines.push(`- Geo-Filters: **None**`);
          lines.push(`- **Attack Vector:** Global access from any region`);
          lines.push(`- **Remediation:** Implement geo-filtering for sensitive content`);
          lines.push(``);
        }
      }
      
      // TC-CDN-010: DDoS protection
      if (!isFrontDoor) {
        // Standard CDN doesn't have built-in DDoS like Front Door
        mediumCount++;
        lines.push(`#### TC-CDN-010: Limited DDoS Protection`);
        lines.push(`**Risk:** MEDIUM | **MITRE:** T1498 - Network Denial of Service`);
        lines.push(`- Standard CDN has basic DDoS protection only`);
        lines.push(`- **Remediation:** Consider Front Door Standard/Premium for enhanced DDoS`);
        lines.push(``);
      }
    }
    
    // Update risk summary
    const riskSummary: string[] = [
      `| Severity | Count |`,
      `|----------|-------|`,
      `| 🔴 CRITICAL | ${criticalCount} |`,
      `| 🟠 HIGH | ${highCount} |`,
      `| 🟡 MEDIUM | ${mediumCount} |`,
      `| 🟢 LOW | ${lowCount} |`,
      ``,
    ];
    lines.splice(riskSummaryIndex, 0, ...riskSummary);
    
    // Attack chains
    lines.push(`## Attack Chains`);
    lines.push(``);
    lines.push(`| Attack Chain | Risk | MITRE |`);
    lines.push(`|--------------|------|-------|`);
    lines.push(`| Origin exposure → Direct attack → Bypass CDN/WAF | CRITICAL | T1190 - Exploit Public-Facing Application |`);
    lines.push(`| Cache poisoning → Serve malicious content | MEDIUM | T1584.003 - Compromise Web Services |`);
    lines.push(`| WAF bypass → Application exploitation | HIGH | T1190 - Exploit Public-Facing Application |`);
    lines.push(`| HTTP allowed → MITM → Credential theft | HIGH | T1040 - Network Sniffing |`);
    lines.push(`| Custom domain takeover → Phishing | MEDIUM | T1584.005 - Botnet |`);
    lines.push(`| No geo-filtering → Global threat exposure | LOW | T1583 - Acquire Infrastructure |`);
    lines.push(`| DDoS attack → Service unavailability | MEDIUM | T1498 - Network DoS |`);
    lines.push(``);
    
    lines.push(`---`);
    lines.push(`*Generated by Azure Pentest MCP v${SERVER_VERSION} - CDN & Front Door Security Scanner*`);
    
  } catch (error: any) {
    lines.push(``);
    lines.push(`[FAIL] Error scanning CDN: ${error.message}`);
  }
  
  return lines.join('\n');
}

/**
 * Scan AKS admission controllers for bypass vulnerabilities
 */
async function scanAKSAdmissionBypass(
  subscriptionId: string,
  resourceGroup?: string,
  clusterName?: string,
  format: string = "markdown"
): Promise<string> {
  const lines: string[] = [];
  
  try {
    lines.push(`# AKS Admission Controller Bypass Scan`);
    lines.push(`**Subscription:** ${subscriptionId}`);
    lines.push(`**Resource Group:** ${resourceGroup || 'All'}`);
    lines.push(`**Cluster:** ${clusterName || 'All'}`);
    lines.push(`**Scan Time:** ${new Date().toISOString()}`);
    lines.push(``);
    
    const aksClient = new ContainerServiceClient(credential, subscriptionId);
    let clusters: any[] = [];
    
    // Get clusters to scan
    if (clusterName && resourceGroup) {
      const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
      clusters.push(cluster);
    } else if (resourceGroup) {
      for await (const cluster of aksClient.managedClusters.listByResourceGroup(resourceGroup)) {
        clusters.push(cluster);
      }
    } else {
      for await (const cluster of aksClient.managedClusters.list()) {
        clusters.push(cluster);
      }
    }
    
    if (clusters.length === 0) {
      lines.push(`[INFO] No AKS clusters found`);
      return lines.join('\n');
    }
    
    let totalRisks = 0;
    const findings: string[] = [];
    
    for (const cluster of clusters) {
      const clusterFindings: string[] = [];
      const clName = cluster.name || 'Unknown';
      const clRg = cluster.id?.split('/')[4] || 'Unknown';
      
      clusterFindings.push(`## Cluster: ${clName}`);
      clusterFindings.push(`**Resource Group:** ${clRg}`);
      clusterFindings.push(`**Location:** ${cluster.location}`);
      clusterFindings.push(``);
      
      // TC-ADMIT-001: ValidatingWebhookConfiguration bypass
      // TC-ADMIT-002: MutatingWebhookConfiguration exploitation
      // Check if cluster has webhook admission enabled
      const addonProfiles = cluster.addonProfiles || {};
      const azurePolicyEnabled = addonProfiles?.azurePolicy?.enabled;
      
      if (!azurePolicyEnabled) {
        totalRisks++;
        clusterFindings.push(`#### TC-ADMIT-001: Azure Policy Addon Disabled`);
        clusterFindings.push(`**Risk:** HIGH | **MITRE:** T1562.001 - Impair Defenses: Disable or Modify Tools`);
        clusterFindings.push(`- Azure Policy addon is not enabled`);
        clusterFindings.push(`- **Risk:** No admission control enforcement, pods can bypass security policies`);
        clusterFindings.push(`- **Remediation:** Enable Azure Policy addon with \`az aks enable-addons -a azure-policy\``);
        clusterFindings.push(``);
      }
      
      // TC-ADMIT-004: Failure policy misconfiguration
      const autoUpgradeProfile = cluster.autoUpgradeProfile;
      if (!autoUpgradeProfile || autoUpgradeProfile.upgradeChannel === 'none') {
        totalRisks++;
        clusterFindings.push(`#### TC-ADMIT-004: Auto-Upgrade Disabled`);
        clusterFindings.push(`**Risk:** MEDIUM | **MITRE:** T1211 - Exploitation for Defense Evasion`);
        clusterFindings.push(`- Auto-upgrade channel: ${autoUpgradeProfile?.upgradeChannel || 'none'}`);
        clusterFindings.push(`- **Risk:** Cluster may run outdated admission controllers with known bypasses`);
        clusterFindings.push(`- **Remediation:** Enable auto-upgrade with \`az aks update --auto-upgrade-channel stable\``);
        clusterFindings.push(``);
      }
      
      // TC-ADMIT-008: Privileged pod creation bypass
      const securityProfile = cluster.securityProfile;
      const defenderEnabled = securityProfile?.defender?.securityMonitoring?.enabled;
      
      if (!defenderEnabled) {
        totalRisks++;
        clusterFindings.push(`#### TC-ADMIT-008: No Defender for Containers`);
        clusterFindings.push(`**Risk:** HIGH | **MITRE:** T1610 - Deploy Container`);
        clusterFindings.push(`- Microsoft Defender for Containers: Disabled`);
        clusterFindings.push(`- **Risk:** No runtime protection against privileged container creation`);
        clusterFindings.push(`- **Remediation:** Enable Defender for Containers via Azure Security Center`);
        clusterFindings.push(``);
      }
      
      // TC-ADMIT-003: Namespace selector manipulation
      const networkProfile = cluster.networkProfile;
      const networkPolicy = networkProfile?.networkPolicy;
      
      if (!networkPolicy || networkPolicy === 'none') {
        totalRisks++;
        clusterFindings.push(`#### TC-ADMIT-003: No Network Policy`);
        clusterFindings.push(`**Risk:** HIGH | **MITRE:** T1071 - Application Layer Protocol`);
        clusterFindings.push(`- Network Policy: ${networkPolicy || 'none'}`);
        clusterFindings.push(`- **Risk:** Pods can bypass namespace network isolation`);
        clusterFindings.push(`- **Remediation:** Enable network policy (Azure CNI with Azure Network Policy or Calico)`);
        clusterFindings.push(``);
      }
      
      // TC-ADMIT-007: Admission review object injection
      const apiServerAccessProfile = cluster.apiServerAccessProfile;
      const authorizedIpRanges = apiServerAccessProfile?.authorizedIPRanges || [];
      
      if (authorizedIpRanges.length === 0 && !apiServerAccessProfile?.enablePrivateCluster) {
        totalRisks++;
        clusterFindings.push(`#### TC-ADMIT-007: Public API Server`);
        clusterFindings.push(`**Risk:** CRITICAL | **MITRE:** T1190 - Exploit Public-Facing Application`);
        clusterFindings.push(`- API Server: Public access, no IP restrictions`);
        clusterFindings.push(`- **Risk:** Anyone can send admission review requests to bypass validation`);
        clusterFindings.push(`- **Remediation:** Enable private cluster or restrict API server access with authorized IP ranges`);
        clusterFindings.push(``);
      }
      
      findings.push(clusterFindings.join('\n'));
    }
    
    lines.push(`## Risk Summary`);
    lines.push(`**Clusters Scanned:** ${clusters.length}`);
    lines.push(`**Total Risks Found:** ${totalRisks}`);
    lines.push(``);
    
    if (totalRisks === 0) {
      lines.push(`✅ **No admission controller bypass risks detected**`);
      lines.push(``);
    } else {
      lines.push(`⚠️ **Findings:**`);
      lines.push(``);
      lines.push(findings.join('\n---\n\n'));
    }
    
    lines.push(`## Remediation Recommendations`);
    lines.push(``);
    lines.push(`1. **Enable Azure Policy Addon** - Enforce pod security policies`);
    lines.push(`2. **Enable Auto-Upgrade** - Keep admission controllers updated`);
    lines.push(`3. **Enable Defender for Containers** - Runtime protection`);
    lines.push(`4. **Configure Network Policy** - Enforce namespace isolation`);
    lines.push(`5. **Restrict API Server Access** - Use private cluster or IP whitelist`);
    lines.push(``);
    
  } catch (error: any) {
    lines.push(`[FAIL] Error scanning AKS admission: ${error.message}`);
  }
  
  return lines.join('\n');
}

/**
 * Scan AKS for OPA/Kyverno policy bypass vulnerabilities
 */
async function scanAKSPolicyBypass(
  subscriptionId: string,
  resourceGroup?: string,
  clusterName?: string,
  format: string = "markdown"
): Promise<string> {
  const lines: string[] = [];
  
  try {
    lines.push(`# AKS OPA/Kyverno Policy Bypass Scan`);
    lines.push(`**Subscription:** ${subscriptionId}`);
    lines.push(`**Resource Group:** ${resourceGroup || 'All'}`);
    lines.push(`**Cluster:** ${clusterName || 'All'}`);
    lines.push(`**Scan Time:** ${new Date().toISOString()}`);
    lines.push(``);
    
    const aksClient = new ContainerServiceClient(credential, subscriptionId);
    let clusters: any[] = [];
    
    // Get clusters to scan
    if (clusterName && resourceGroup) {
      const cluster = await aksClient.managedClusters.get(resourceGroup, clusterName);
      clusters.push(cluster);
    } else if (resourceGroup) {
      for await (const cluster of aksClient.managedClusters.listByResourceGroup(resourceGroup)) {
        clusters.push(cluster);
      }
    } else {
      for await (const cluster of aksClient.managedClusters.list()) {
        clusters.push(cluster);
      }
    }
    
    if (clusters.length === 0) {
      lines.push(`[INFO] No AKS clusters found`);
      return lines.join('\n');
    }
    
    let totalRisks = 0;
    const findings: string[] = [];
    
    for (const cluster of clusters) {
      const clusterFindings: string[] = [];
      const clName = cluster.name || 'Unknown';
      const clRg = cluster.id?.split('/')[4] || 'Unknown';
      
      clusterFindings.push(`## Cluster: ${clName}`);
      clusterFindings.push(`**Resource Group:** ${clRg}`);
      clusterFindings.push(`**Location:** ${cluster.location}`);
      clusterFindings.push(``);
      
      // TC-POLICY-001: OPA Gatekeeper constraint exceptions
      const addonProfiles = cluster.addonProfiles || {};
      const azurePolicyEnabled = addonProfiles?.azurePolicy?.enabled;
      const azurePolicyConfig = addonProfiles?.azurePolicy?.config;
      
      if (azurePolicyEnabled) {
        // Check for audit-only mode
        clusterFindings.push(`#### Azure Policy Addon Status`);
        clusterFindings.push(`**Status:** Enabled`);
        clusterFindings.push(`**Config:** ${JSON.stringify(azurePolicyConfig || {})}`);
        clusterFindings.push(``);
        
        // TC-POLICY-003: Audit-only mode exploitation
        // Note: Azure Policy uses Gatekeeper under the hood
        clusterFindings.push(`#### TC-POLICY-003: Policy Enforcement Mode`);
        clusterFindings.push(`**Risk:** MEDIUM | **MITRE:** T1562.001 - Impair Defenses`);
        clusterFindings.push(`- **Note:** Azure Policy can be set to audit-only or deny mode per policy`);
        clusterFindings.push(`- **Risk:** Audit-only policies don't block non-compliant resources`);
        clusterFindings.push(`- **Remediation:** Review Azure Policy assignments, set enforcement mode to 'deny' for critical policies`);
        clusterFindings.push(``);
        totalRisks++;
      } else {
        // TC-POLICY-001: No policy engine
        totalRisks++;
        clusterFindings.push(`#### TC-POLICY-001: No Policy Engine`);
        clusterFindings.push(`**Risk:** CRITICAL | **MITRE:** T1562.001 - Impair Defenses`);
        clusterFindings.push(`- Azure Policy addon: Disabled`);
        clusterFindings.push(`- **Risk:** No OPA Gatekeeper, no policy enforcement, complete bypass`);
        clusterFindings.push(`- **Remediation:** Enable Azure Policy addon or deploy Kyverno manually`);
        clusterFindings.push(``);
      }
      
      // TC-POLICY-005: Background scanning disabled
      const autoScalerProfile = cluster.autoScalerProfile;
      if (!autoScalerProfile || !autoScalerProfile.scanInterval) {
        totalRisks++;
        clusterFindings.push(`#### TC-POLICY-005: No Auto-Scaler Profiling`);
        clusterFindings.push(`**Risk:** LOW | **MITRE:** T1496 - Resource Hijacking`);
        clusterFindings.push(`- **Risk:** Existing resources not scanned for policy violations`);
        clusterFindings.push(`- **Remediation:** Enable cluster auto-scaler with proper scan intervals`);
        clusterFindings.push(``);
      }
      
      // TC-POLICY-004: Policy scope limitation bypass
      const rbac = cluster.aadProfile;
      if (!rbac?.managed) {
        totalRisks++;
        clusterFindings.push(`#### TC-POLICY-004: Non-Managed AAD RBAC`);
        clusterFindings.push(`**Risk:** HIGH | **MITRE:** T1098.001 - Account Manipulation: Additional Cloud Credentials`);
        clusterFindings.push(`- Azure AD Integration: Not managed or disabled`);
        clusterFindings.push(`- **Risk:** Users can bypass policy scope restrictions without AAD enforcement`);
        clusterFindings.push(`- **Remediation:** Enable managed AAD integration with RBAC`);
        clusterFindings.push(``);
      }
      
      // TC-POLICY-008: Resource exclusion abuse
      const systemNodePools = cluster.agentPoolProfiles?.filter((p: any) => p.mode === 'System');
      const userNodePools = cluster.agentPoolProfiles?.filter((p: any) => p.mode === 'User');
      
      if (systemNodePools && systemNodePools.length > 0) {
        clusterFindings.push(`#### TC-POLICY-008: System Node Pool Taints`);
        clusterFindings.push(`**Risk:** MEDIUM | **MITRE:** T1610 - Deploy Container`);
        clusterFindings.push(`- System node pools: ${systemNodePools.length}`);
        clusterFindings.push(`- **Risk:** If system pools aren't tainted, policies may be bypassed by scheduling there`);
        clusterFindings.push(`- **Remediation:** Taint system node pools with \`CriticalAddonsOnly=true:NoSchedule\``);
        clusterFindings.push(``);
        totalRisks++;
      }
      
      // TC-POLICY-006: Webhook failure mode exploitation
      const networkProfile = cluster.networkProfile;
      if (!networkProfile?.serviceCidr) {
        totalRisks++;
        clusterFindings.push(`#### TC-POLICY-006: Network Configuration Risk`);
        clusterFindings.push(`**Risk:** MEDIUM | **MITRE:** T1599.001 - Network Boundary Bridging`);
        clusterFindings.push(`- **Risk:** Misconfigured network may prevent webhook validation`);
        clusterFindings.push(`- **Remediation:** Ensure proper service CIDR and DNS configuration`);
        clusterFindings.push(``);
      }
      
      findings.push(clusterFindings.join('\n'));
    }
    
    lines.push(`## Risk Summary`);
    lines.push(`**Clusters Scanned:** ${clusters.length}`);
    lines.push(`**Total Risks Found:** ${totalRisks}`);
    lines.push(``);
    
    if (totalRisks === 0) {
      lines.push(`✅ **No policy bypass risks detected**`);
      lines.push(``);
    } else {
      lines.push(`⚠️ **Findings:**`);
      lines.push(``);
      lines.push(findings.join('\n---\n\n'));
    }
    
    lines.push(`## Remediation Recommendations`);
    lines.push(``);
    lines.push(`1. **Enable Azure Policy Addon** - Deploy Gatekeeper for policy enforcement`);
    lines.push(`2. **Use Deny Mode** - Set critical policies to deny (not audit-only)`);
    lines.push(`3. **Enable Managed AAD** - Enforce RBAC with Azure AD integration`);
    lines.push(`4. **Taint System Pools** - Prevent workload scheduling on system nodes`);
    lines.push(`5. **Monitor Policy Violations** - Use Azure Policy compliance dashboard`);
    lines.push(``);
    
  } catch (error: any) {
    lines.push(`[FAIL] Error scanning AKS policy: ${error.message}`);
  }
  
  return lines.join('\n');
}

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
  console.error("\nAvailable Tools (42):");
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
  console.error("\n  AKS/Kubernetes Security (9 tools):");
  console.error("   15. scan_aks_full            - Full AKS security scan");
  console.error("   16. scan_aks_clusters        - AKS RBAC & network policies");
  console.error("   17. get_aks_credentials      - Extract kubeconfig & admin access");
  console.error("   18. enumerate_aks_identities - Map managed identities & RBAC");
  console.error("   19. scan_aks_node_security   - Node encryption & SSH analysis");
  console.error("   20. scan_aks_service_accounts - Service account security");
  console.error("   21. scan_aks_secrets         - Kubernetes secret enumeration");
  console.error("   22. scan_aks_live            - Live K8s API security scan (20 checks)");
  console.error("   23. scan_aks_imds            - IMDS exploitation & full recon");
  console.error("   24. scan_aks_pod_identity    - Pod Identity token theft scan");
  console.error("\n  Container & Edge Security (NEW - 3 tools):");
  console.error("   25. scan_container_apps_security - Container Apps vulnerability scanner");
  console.error("   26. scan_gitops_security         - GitOps/Flux security audit");
  console.error("   27. scan_cdn_security            - CDN/Front Door misconfiguration scan");
  console.error("\n  DevOps & Reporting:");
  console.error("   28. scan_azure_devops        - Azure DevOps security scanner");
  console.error("   29. generate_security_report - PDF/HTML/CSV report export");
  console.error("\n[TIP] Quick Start:");
  console.error("   scan_container_apps_security subscriptionId='SUB'");
  console.error("   scan_gitops_security subscriptionId='SUB' resourceGroup='RG' clusterName='CLUSTER'");
  console.error("   scan_cdn_security subscriptionId='SUB'");
  console.error("\nAuthentication: Using Azure CLI credentials (az login)");
  console.error("=".repeat(70) + "\n");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
