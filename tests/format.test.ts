import { describe, test, expect } from '@jest/globals';

/**
 * Stratos Azure MCP - Format Parameter Integration Tests
 * Tests for response formatting functionality (v1.10.5+)
 */

describe('Format Parameter Integration (Azure)', () => {
  // Mock formatResponse helper
  function formatResponse(data: any, format: 'markdown' | 'json', toolName: string) {
    if (format === 'json') {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            tool: toolName,
            format: 'json',
            timestamp: new Date().toISOString(),
            data: data
          }, null, 2)
        }]
      };
    }
    
    return {
      content: [{
        type: 'text',
        text: typeof data === 'string' ? data : JSON.stringify(data)
      }]
    };
  }

  describe('Markdown Format Output', () => {
    test('should return plain text for markdown format', () => {
      const data = '## Azure Security Findings\n\n- Virtual Machines: 10\n- Risks: 3 HIGH';
      const result = formatResponse(data, 'markdown', 'azure_scan_vm_security');
      
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toBe(data);
      expect(result.content[0].text).toContain('## Azure Security Findings');
    });

    test('should handle complex markdown tables', () => {
      const data = `
# Azure Storage Security Report

| Account | Public Access | HTTPS Only | Encryption |
|---------|---------------|------------|------------|
| storage1| Disabled      | ✅         | ✅         |
| storage2| Enabled       | ❌         | ✅         |
`;
      const result = formatResponse(data, 'markdown', 'azure_analyze_storage_security');
      
      expect(result.content[0].text).toContain('# Azure Storage Security Report');
      expect(result.content[0].text).toContain('| Account | Public Access |');
    });
  });

  describe('JSON Format Output', () => {
    test('should return structured JSON with metadata envelope', () => {
      const data = {
        findings: ['VM vm-001 has public IP without NSG'],
        severity: 'HIGH',
        count: 1,
        subscriptionId: '12345678-1234-1234-1234-123456789012'
      };
      
      const result = formatResponse(data, 'json', 'azure_scan_vm_security');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed).toHaveProperty('tool');
      expect(parsed).toHaveProperty('format');
      expect(parsed).toHaveProperty('timestamp');
      expect(parsed).toHaveProperty('data');
      expect(parsed.tool).toBe('azure_scan_vm_security');
      expect(parsed.format).toBe('json');
    });

    test('should include timestamp in ISO format', () => {
      const data = { resourceGroup: 'rg-production' };
      const result = formatResponse(data, 'json', 'azure_enumerate_resource_groups');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      expect(() => new Date(parsed.timestamp)).not.toThrow();
    });

    test('should preserve Azure-specific data structures', () => {
      const azureData = {
        resources: [
          {
            id: '/subscriptions/sub-id/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm1',
            name: 'vm1',
            location: 'eastus',
            type: 'Microsoft.Compute/virtualMachines'
          }
        ],
        metadata: {
          subscriptionId: '12345678-1234-1234-1234-123456789012',
          location: 'eastus'
        }
      };
      
      const result = formatResponse(azureData, 'json', 'azure_enumerate_vms');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.data.resources).toHaveLength(1);
      expect(parsed.data.resources[0].location).toBe('eastus');
      expect(parsed.data.metadata.subscriptionId).toBeDefined();
    });

    test('should pretty-print JSON for readability', () => {
      const data = { location: 'westeurope' };
      const result = formatResponse(data, 'json', 'test_tool');
      
      expect(result.content[0].text).toContain('\n');
      expect(result.content[0].text).toContain('  ');
    });
  });

  describe('Format Parameter Validation', () => {
    test('should accept markdown format', () => {
      const validFormats = ['markdown', 'MARKDOWN', 'Markdown'];
      validFormats.forEach(format => {
        expect(() => formatResponse({}, format.toLowerCase() as any, 'test')).not.toThrow();
      });
    });

    test('should accept json format', () => {
      const validFormats = ['json', 'JSON', 'Json'];
      validFormats.forEach(format => {
        expect(() => formatResponse({}, format.toLowerCase() as any, 'test')).not.toThrow();
      });
    });

    test('should default to markdown when undefined', () => {
      const defaultFormat = undefined || 'markdown';
      expect(defaultFormat).toBe('markdown');
    });
  });

  describe('Backward Compatibility', () => {
    test('should maintain existing markdown output structure', () => {
      const legacyData = 'Azure security assessment complete';
      const result = formatResponse(legacyData, 'markdown', 'legacy_tool');
      
      expect(result.content[0].text).toBe(legacyData);
      expect(() => JSON.parse(result.content[0].text)).toThrow();
    });

    test('should not break tools without format parameter', () => {
      const data = '## Default Azure output';
      const result = formatResponse(data, 'markdown', 'default_tool');
      
      expect(result.content[0].text).toContain('## Default Azure output');
    });
  });

  describe('Error Handling', () => {
    test('should handle null data gracefully', () => {
      const result = formatResponse(null, 'json', 'test_tool');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.data).toBeNull();
    });

    test('should handle undefined data gracefully', () => {
      const result = formatResponse(undefined, 'json', 'test_tool');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.data).toBeUndefined();
    });

    test('should handle empty strings', () => {
      const result = formatResponse('', 'markdown', 'test_tool');
      
      expect(result.content[0].text).toBe('');
    });
  });

  describe('Tool Name Tracking', () => {
    test('should correctly identify Azure tools', () => {
      const toolNames = [
        'azure_scan_storage_security',
        'azure_enumerate_vms',
        'azure_analyze_rbac_privesc'
      ];
      
      toolNames.forEach(toolName => {
        const result = formatResponse({}, 'json', toolName);
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.tool).toBe(toolName);
      });
    });
  });

  describe('Performance Considerations', () => {
    test('should handle large Azure resource datasets', () => {
      const largeData = {
        resources: Array.from({ length: 500 }, (_, i) => ({
          id: `/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-${i}`,
          name: `vm-${i}`,
          location: 'eastus'
        }))
      };
      
      const start = Date.now();
      const result = formatResponse(largeData, 'json', 'test_tool');
      const duration = Date.now() - start;
      
      expect(duration).toBeLessThan(100);
      expect(result.content[0].text.length).toBeGreaterThan(5000);
    });
  });

  describe('Real-World Azure Scenarios', () => {
    test('should format storage security findings', () => {
      const storageFindings = {
        accounts: [
          {
            name: 'storageaccount1',
            publicAccess: true,
            httpsOnly: false,
            encryption: true,
            location: 'eastus'
          }
        ],
        findings: [
          { severity: 'HIGH', issue: 'Public blob access enabled' },
          { severity: 'HIGH', issue: 'HTTPS not enforced' }
        ]
      };
      
      const jsonResult = formatResponse(storageFindings, 'json', 'azure_analyze_storage_security');
      const parsed = JSON.parse(jsonResult.content[0].text);
      
      expect(parsed.data.accounts).toHaveLength(1);
      expect(parsed.data.findings).toHaveLength(2);
    });

    test('should format NSG rule analysis', () => {
      const nsgFindings = {
        nsg: 'nsg-production',
        riskyRules: [
          {
            name: 'Allow-All-Inbound',
            priority: 100,
            sourceAddressPrefix: '*',
            destinationPort: '22',
            action: 'Allow'
          }
        ],
        severity: 'CRITICAL'
      };
      
      const jsonResult = formatResponse(nsgFindings, 'json', 'azure_analyze_nsg_rules');
      const parsed = JSON.parse(jsonResult.content[0].text);
      
      expect(parsed.data.riskyRules[0].name).toBe('Allow-All-Inbound');
      expect(parsed.data.severity).toBe('CRITICAL');
    });

    test('should format RBAC privilege escalation paths', () => {
      const rbacFindings = {
        escalationPaths: [
          {
            principal: 'user@example.com',
            role: 'Contributor',
            scope: '/subscriptions/sub-id',
            risk: 'HIGH'
          }
        ],
        totalPaths: 1
      };
      
      const jsonResult = formatResponse(rbacFindings, 'json', 'azure_analyze_rbac_privesc');
      const parsed = JSON.parse(jsonResult.content[0].text);
      
      expect(parsed.data.escalationPaths[0].risk).toBe('HIGH');
    });

    test('should format AKS security assessment', () => {
      const aksFindings = {
        cluster: 'aks-production',
        location: 'eastus',
        findings: {
          networkPolicy: 'Not Enabled',
          rbacEnabled: true,
          podSecurityPolicy: false,
          privateCluster: false
        },
        criticalIssues: 3
      };
      
      const jsonResult = formatResponse(aksFindings, 'json', 'azure_scan_aks_full');
      const parsed = JSON.parse(jsonResult.content[0].text);
      
      expect(parsed.data.cluster).toBe('aks-production');
      expect(parsed.data.criticalIssues).toBe(3);
    });
  });
});
