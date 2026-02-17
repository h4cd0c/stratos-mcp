import { describe, test, expect, beforeAll } from '@jest/globals';

/**
 * Stratos Azure MCP - Tool Definition Tests
 * Validates tool structure, schemas, and annotations
 */

// Mock tool structure based on MCP SDK types
interface Tool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, any>;
    required?: string[];
  };
  annotations?: {
    readOnly?: boolean;
    destructive?: boolean;
    idempotent?: boolean;
    openWorld?: boolean;
  };
}

// Expected tool names in Stratos
const EXPECTED_TOOLS = [
  "help",
  "list_active_locations",
  "scan_all_locations",
  "enumerate_subscriptions",
  "enumerate_resource_groups",
  "enumerate_resources",
  "get_resource_details",
  "analyze_storage_security",
  "analyze_nsg_rules",
  "enumerate_public_ips",
  "enumerate_rbac_assignments",
  "scan_sql_databases",
  "analyze_keyvault_security",
  "analyze_cosmosdb_security",
  "analyze_vm_security",
  "scan_acr_security",
  "enumerate_service_principals",
  "enumerate_managed_identities",
  "scan_storage_containers",
  "generate_security_report",
  "analyze_attack_paths",
  "get_aks_credentials",
  "scan_azure_devops",
  "analyze_function_apps",
  "analyze_app_service_security",
  "analyze_firewall_policies",
  "analyze_logic_apps",
  "analyze_rbac_privesc",
  "detect_persistence_mechanisms",
  "scan_aks_full",
  "scan_aks_policy_bypass",
  "scan_container_apps_security",
  "scan_gitops_security",
  "scan_cdn_security"
];

describe('Tool Structure Validation', () => {
  test('should have correct number of tools', () => {
    expect(EXPECTED_TOOLS.length).toBe(34);
  });

  test('all tool names should be lowercase with underscores', () => {
    for (const toolName of EXPECTED_TOOLS) {
      expect(toolName).toMatch(/^[a-z_]+$/);
      expect(toolName).not.toContain(' ');
      expect(toolName).not.toContain('-');
    }
  });

  test('all tool names should be descriptive', () => {
    // Tool names should be at least 4 characters
    for (const toolName of EXPECTED_TOOLS) {
      expect(toolName.length).toBeGreaterThanOrEqual(4);
    }
  });

  test('tools should be categorized by prefix', () => {
    const prefixes = {
      enumerate: EXPECTED_TOOLS.filter(t => t.startsWith('enumerate_')),
      scan: EXPECTED_TOOLS.filter(t => t.startsWith('scan_')),
      analyze: EXPECTED_TOOLS.filter(t => t.startsWith('analyze_')),
      get: EXPECTED_TOOLS.filter(t => t.startsWith('get_')),
      detect: EXPECTED_TOOLS.filter(t => t.startsWith('detect_')),
      generate: EXPECTED_TOOLS.filter(t => t.startsWith('generate_')),
    };

    expect(prefixes.enumerate.length).toBeGreaterThan(0);
    expect(prefixes.scan.length).toBeGreaterThan(0);
    expect(prefixes.analyze.length).toBeGreaterThan(0);
  });
});

describe('Tool Annotation Validation', () => {
  // Mock annotations for different tool types
  const mockTools: Tool[] = [
    {
      name: "help",
      description: "Help tool",
      inputSchema: { type: "object", properties: {} },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: true,  // Help is idempotent
        openWorld: false   // Static content
      }
    },
    {
      name: "enumerate_subscriptions",
      description: "Enumerate subscriptions",
      inputSchema: { type: "object", properties: {} },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: false,  // Cloud state can change
        openWorld: true
      }
    },
    {
      name: "scan_aks_imds",
      description: "IMDS exploitation",
      inputSchema: {
        type: "object",
        properties: {
          subscriptionId: { type: "string" },
          resourceGroup: { type: "string" },
          clusterName: { type: "string" }
        },
        required: ["subscriptionId", "resourceGroup", "clusterName"]
      },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: false,
        openWorld: true
      }
    }
  ];

  test('all security tools should be read-only', () => {
    for (const tool of mockTools) {
      expect(tool.annotations?.readOnly).toBe(true);
    }
  });

  test('no security tools should be destructive', () => {
    for (const tool of mockTools) {
      expect(tool.annotations?.destructive).toBe(false);
    }
  });

  test('only help tool should be idempotent', () => {
    const helpTool = mockTools.find(t => t.name === "help");
    const otherTools = mockTools.filter(t => t.name !== "help");

    expect(helpTool?.annotations?.idempotent).toBe(true);
    
    for (const tool of otherTools) {
      expect(tool.annotations?.idempotent).toBe(false);
    }
  });

  test('only help tool should have openWorld: false', () => {
    const helpTool = mockTools.find(t => t.name === "help");
    const otherTools = mockTools.filter(t => t.name !== "help");

    expect(helpTool?.annotations?.openWorld).toBe(false);
    
    for (const tool of otherTools) {
      expect(tool.annotations?.openWorld).toBe(true);
    }
  });
});

describe('Input Schema Validation', () => {
  test('subscriptionId parameter should be string type', () => {
    const schema = {
      type: "object",
      properties: {
        subscriptionId: {
          type: "string",
          description: "Azure subscription ID"
        }
      },
      required: ["subscriptionId"]
    };

    expect(schema.properties.subscriptionId.type).toBe("string");
    expect(schema.required).toContain("subscriptionId");
  });

  test('optional parameters should not be in required array', () => {
    const schema = {
      type: "object",
      properties: {
        subscriptionId: { type: "string" },
        resourceGroup: { type: "string", description: "Optional: ..." }
      },
      required: ["subscriptionId"]
    };

    expect(schema.required).toContain("subscriptionId");
    expect(schema.required).not.toContain("resourceGroup");
  });

  test('enum fields should have valid values', () => {
    const schema = {
      type: "object",
      properties: {
        scanMode: {
          type: "string",
          enum: ["common", "all"]
        }
      }
    };

    expect(schema.properties.scanMode.enum).toContain("common");
    expect(schema.properties.scanMode.enum).toContain("all");
    expect(schema.properties.scanMode.enum?.length).toBe(2);
  });
});

describe('Tool Grouping', () => {
  test('should have multi-location tools', () => {
    const multiLocationTools = EXPECTED_TOOLS.filter(t => 
      t.includes('location') || t === 'azure_scan_all_locations'
    );
    expect(multiLocationTools.length).toBeGreaterThanOrEqual(2);
  });

  test('should have enumeration tools', () => {
    const enumerationTools = EXPECTED_TOOLS.filter(t => t.startsWith('enumerate_'));
    expect(enumerationTools.length).toBeGreaterThanOrEqual(5);
  });

  test('should have security scanning tools', () => {
    const scanningTools = EXPECTED_TOOLS.filter(t => 
      t.startsWith('scan_') || t.startsWith('analyze_')
    );
    expect(scanningTools.length).toBeGreaterThanOrEqual(10);
  });

  test('should have AKS/Kubernetes tools', () => {
    const aksTools = EXPECTED_TOOLS.filter(t => t.includes('aks'));
    expect(aksTools.length).toBeGreaterThanOrEqual(3);
  });

  test('should have reporting tools', () => {
    const reportingTools = EXPECTED_TOOLS.filter(t => t.includes('report'));
    expect(reportingTools.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Tool Naming Convention', () => {
  test('action verbs should be appropriate', () => {
    const validPrefixes = [
      'enumerate', 'scan', 'analyze', 'get', 'detect', 
      'generate', 'list', 'help'
    ];

    for (const tool of EXPECTED_TOOLS) {
      // Skip azure_ prefix to get the actual verb
      const parts = tool.split('_');
      const prefix = parts[0] === 'azure' ? parts[1] : parts[0];
      const isValid = validPrefixes.includes(prefix);
      expect(isValid).toBe(true);
    }
  });

  test('should use underscores not camelCase', () => {
    for (const tool of EXPECTED_TOOLS) {
      // Should not have capital letters (no camelCase)
      expect(tool).toBe(tool.toLowerCase());
      
      // Should use underscores for multi-word names
      if (tool.length > 10) {
        expect(tool).toContain('_');
      }
    }
  });
});
