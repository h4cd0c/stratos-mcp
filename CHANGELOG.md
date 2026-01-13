# Changelog

All notable changes to Stratos (Azure Security Assessment MCP Server) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-01-09

### Added

#### New Automated MCP Tools (2 new)
- **scan_aks_service_accounts** - Automated AKS service account security analysis
  - Checks Workload Identity configuration
  - Validates Azure AD integration
  - Analyzes RBAC and network policies
  - Verifies Defender for Containers status
  - Provides kubectl commands for deeper SA analysis
  - Risk scoring and MITRE ATT&CK mappings

- **hunt_aks_secrets** - Comprehensive AKS secret hunting guide
  - K8s secrets enumeration commands
  - Azure Key Vault hunting techniques
  - IMDS/managed identity credential theft
  - Storage account credential extraction
  - ConfigMap secret discovery
  - Service principal credential hunting
  - ACR pull secret extraction

### Changed
- Total tools: **33** (up from 31)
- All Kubernetes security tools now automated via MCP
- Added Azure-specific exploitation payloads

---

## [1.7.0] - 2026-01-08

### Added

#### New Security Tools (6 tools)
- **`analyze_function_apps`** - Azure Functions security analysis: authentication settings, managed identity, VNet integration, CORS configuration, application settings for secrets, runtime version vulnerabilities
- **`analyze_app_service_security`** - App Service security analysis: HTTPS-only, minimum TLS version, authentication, managed identity, VNet integration, IP restrictions, remote debugging status
- **`analyze_firewall_policies`** - Azure Firewall and NSG rule analysis: overly permissive rules, any-to-any rules, management port exposure, threat intelligence integration
- **`analyze_logic_apps`** - Logic Apps security analysis: authentication, access control, managed identity usage, exposed endpoints, workflow triggers security
- **`analyze_rbac_privilege_escalation`** - Deep RBAC analysis for privilege escalation paths: role assignment permissions, custom role vulnerabilities, subscription-level access, management group permissions
- **`detect_persistence_mechanisms`** - Identify Azure persistence mechanisms: automation accounts, runbooks, Logic Apps triggers, scheduled tasks, webhook endpoints, custom script extensions

#### Infrastructure Improvements
- **Caching System** - Added TTL-based caching for repeated API calls to improve performance
- **Rate Limiting** - Per-service rate limiters (Compute, Storage, Network, Identity, KeyVault) to prevent API throttling
- **Retry Logic** - Exponential backoff with configurable retries for transient failures
- **Error Handling** - Improved error handling with `safeApiCall` and `safeExecute` wrappers
- **Batch Processing** - `batchProcess` utility for processing large datasets efficiently
- **Azure Utilities** - `parseResourceId` and `buildResourceId` helpers for resource ID manipulation

#### Testing
- **Unit Tests** - Added Jest unit tests for utility functions (Cache, RateLimiter, withRetry, parseResourceId, etc.)
- **Test Scripts** - Added `npm test`, `npm test:watch`, and `npm test:coverage` commands

### Changed
- Updated `package.json` with Jest configuration and test scripts
- Tool count increased from 25 to 31

### Technical Details
- New file: `src/utils.ts` - Shared utility functions with Azure-specific helpers
- New file: `tests/utils.test.ts` - Jest unit tests
- Jest configured for ES modules with `ts-jest`

---

## [1.6.0] - 2025-12-20

### Added

#### Azure DevOps Security (Phase 5)
- **`scan_azure_devops`** - Azure DevOps security scanner
  - Enumerate organizations, projects, repositories, pipelines
  - Detect hardcoded secrets in repositories
  - Scan pipelines for exposed credentials
  - Check service connections for insecure authentication
  - Variable group security analysis

#### Report Export Formats
- **PDF Export** - Professional PDF reports with charts and formatting
- **HTML Export** - Interactive HTML reports with sortable tables
- **CSV Export** - Structured data export for analysis

### Changed
- Updated help documentation with Phase 5 features
- Improved error handling for DevOps API calls

---

## [1.5.0] - 2025-12-10

### Added

#### AKS Offensive Security (Phase 4)
- **`get_aks_credentials`** - Extract kubeconfig and admin access credentials
- **`enumerate_aks_identities`** - Map managed identities and RBAC in AKS clusters
- **`scan_aks_node_security`** - Node disk encryption, SSH access, public IP analysis
- **`test_aks_imds_access`** - IMDS exploitation testing for pod escape attacks

### Changed
- Enhanced cluster security scanning
- Improved identity enumeration accuracy

---

## [1.4.0] - 2025-11-25

### Added

#### Advanced Analysis (Phase 3)
- **`generate_security_report`** - Comprehensive security report with multiple export formats
- **`analyze_attack_paths`** - Privilege escalation chain mapping and lateral movement analysis

### Features
- Risk scoring with severity levels
- CIS and NIST compliance mapping
- Remediation guidance for findings

---

## [1.3.0] - 2025-11-10

### Added

#### Database & Secrets Security (Phase 2)
- **`scan_sql_databases`** - SQL Server security analysis (TDE, firewall, auth)
- **`analyze_key_vault_security`** - Key Vault configuration audit
- **`analyze_cosmos_db_security`** - Cosmos DB exposure analysis
- **`analyze_vm_security`** - VM disk encryption and security agents
- **`scan_aks_clusters`** - AKS RBAC and network policies
- **`scan_container_registries`** - ACR admin user and vulnerability scanning
- **`enumerate_service_principals`** - Service principal audit
- **`enumerate_managed_identities`** - Managed identity mapping
- **`scan_storage_containers`** - Deep blob/container scanner

---

## [1.2.0] - 2025-10-25

### Added

#### Network & Storage Security (Phase 1 Extended)
- **`analyze_storage_security`** - Storage account misconfiguration scanner
- **`analyze_nsg_rules`** - Network Security Group exposure analyzer
- **`enumerate_public_ips`** - Internet attack surface mapping
- **`enumerate_rbac_assignments`** - Access control auditing

---

## [1.1.0] - 2025-10-10

### Added

#### Core Enumeration (Phase 1)
- **`help`** - Comprehensive usage guide
- **`enumerate_subscriptions`** - List Azure subscriptions
- **`enumerate_resource_groups`** - List resource groups
- **`enumerate_resources`** - List resources with type filtering
- **`get_resource_details`** - Detailed resource configuration

---

## [1.0.0] - 2025-09-15

### Added
- Initial release
- Model Context Protocol (MCP) integration
- Azure SDK v4 support
- TypeScript implementation
- Read-only security assessment capabilities
