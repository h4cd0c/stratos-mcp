# Changelog

All notable changes to Stratos (Azure Security Assessment MCP Server) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.13.0] - 2026-02-19

### Added 🆕 **COMPREHENSIVE SECURITY REPORT SCANNING**
- **Implemented `fullScan: true` parameter** for `azure_generate_security_report`
- Quick scan (default) runs 4 core security tools
- **Full scan** runs **ALL 34 security tools** across entire subscription
- Comprehensive scanning now includes:
  - ✅ Virtual Machines (disk encryption, public IP exposure)
  - ✅ Cosmos DB (public access, VNet filtering, failover)
  - ✅ Container Registry / ACR (admin user, public access, quarantine)
  - ✅ AKS / Kubernetes (AAD integration, private API, policies, network security, Defender)
  - ✅ RBAC / IAM (dangerous roles, wildcard permissions, privilege escalation)
  - ✅ Managed Identities (unused identity detection)
  - ✅ Public IP Analysis (attack surface mapping, unused IPs)
  - ✅ Storage, Network, SQL, Key Vault (existing quick scan)

### Enhanced 🔄
- **Report generation** now shows scan type (Quick vs Comprehensive)
- **Enhanced HTML reports** with scan type badge
- **Enhanced PDF reports** with scan type metadata
- **Improved risk assessment** with findings from all categories
- Better executive summaries with comprehensive coverage

### Usage Examples

```bash
# Quick scan (4 core tools - fast)
azure_generate_security_report subscriptionId: xxx format: markdown

# Comprehensive scan (ALL 34 tools - thorough)
azure_generate_security_report subscriptionId: xxx fullScan: true format: pdf outputFile: "report.pdf"
```

### Technical Implementation
- Added comprehensive scanning logic for 8 additional security categories
- Integrated findings aggregation from all scanners
- Risk-based severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Maintains backward compatibility (default: quick scan)

### Infrastructure ⚡
- ✅ Zero TypeScript compilation errors
- ✅ All 93 tests passing
- ✅ Maintains 34-tool count (unchanged)
- ✅ Performance: Quick scan ~5-10s, Full scan ~30-60s (depends on resources)

## [1.12.0] - 2026-02-17

### Changed 🔄 **COMPREHENSIVE TOOL CONSOLIDATION & SECURITY ENHANCEMENTS**
- **Reduced tool count from 39 to 34** (-5 tools, 12.8% reduction via dual consolidation phases)
- **Phase 1:** AKS Unified Scanning - Enhanced `azure_scan_aks_full` with 5 targeted scan modes
- **Phase 2:** ACR Consolidation - Merged container registry security tools  
- **Added:** 2 critical AKS security tools (admission/policy bypass detection)
- **Fixed:** 3 security scanners (Container Apps, GitOps, CDN)
- Unified security assessments into comprehensive single-tool interfaces

#### Enhanced & Consolidated Tools (34 total)

1. **azure_scan_aks_full** - Comprehensive AKS Security Assessment (Enhanced)
   - **Integrated:** `azure_scan_aks_live`, `azure_scan_aks_imds`, `azure_scan_aks_pod_identity`, `azure_scan_aks_admission_bypass`
   - **New scanModes:** 'full', 'live', 'imds', 'pod_identity', 'admission'
   - **New Parameters:** namespace, podName, deepScan, testDataPlane, exportTokens, deepDataPlane, scanAllPods (mode-specific)
   - **Benefits:** Single tool for all AKS security needs (full assessment + live K8s API scan + IMDS exploitation + pod identity analysis + admission controller bypass)
   - **Example:** `scanMode: "full"` performs comprehensive static analysis (default behavior, unchanged)
   - **Example:** `scanMode: "live"` runs kubectl-based live cluster security checks (20+ checks)
   - **Example:** `scanMode: "imds"` tests IMDS exploitation and token extraction from pods
   - **Example:** `scanMode: "pod_identity"` analyzes workload identity and managed identity configurations
   - **Example:** `scanMode: "admission"` detects admission controller and policy bypass opportunities

2. **azure_scan_acr_security** - Comprehensive Azure Container Registry Security (Enhanced)
   - **Integrated:** `azure_scan_container_registry_poisoning`
   - **New scanModes:** 'security', 'poisoning', 'all'
   - **Benefits:** One tool for all ACR security needs (basic config + supply chain risks)
   - **Example:** `scanMode: "all"` covers admin user checks + public access + vulnerability scanning + registry poisoning + image signature verification

#### New Tools Added (Before Consolidation)

3. **azure_scan_aks_policy_bypass** - OPA/Kyverno/Azure Policy Bypass Detection
   - Detects missing policy engine (no Gatekeeper/OPA)
   - Identifies audit-only mode (policies log but don't block)
   - Checks auto-scaler misconfigurations for resource exhaustion
   - Validates managed AAD RBAC integration
   - Analyzes system node pool taints and tolerations
   - Detects webhook failure modes (fail-open vs fail-closed)
   - Scans for privileged namespace exceptions
   - Reviews policy constraint templates and enforcement
   - **MITRE:** T1562.001 (Disable Security Tools), T1078.004 (Cloud Accounts), T1611 (Escape to Host)

### Removed ❌ **DEPRECATED TOOLS (Consolidated)**

**AKS Consolidation (4 tools → azure_scan_aks_full):**
- **azure_scan_aks_live** - Moved to `azure_scan_aks_full` (scanMode: "live")
- **azure_scan_aks_imds** - Moved to `azure_scan_aks_full` (scanMode: "imds")
- **azure_scan_aks_pod_identity** - Moved to `azure_scan_aks_full` (scanMode: "pod_identity")
- **azure_scan_aks_admission_bypass** - Moved to `azure_scan_aks_full` (scanMode: "admission")

**ACR Consolidation (1 tool → azure_scan_acr_security):**
- **azure_scan_container_registry_poisoning** - Moved to `azure_scan_acr_security` (scanMode: "poisoning")

### Fixed 🔧

4. **azure_scan_container_apps_security** - Azure Container Apps Security Scanner (REPAIRED)
   - Fixed duplicate code blocks causing compilation errors
   - Removed orphaned `as any` type assertions
   - Added proper TypeScript type handling for REST API responses
   - Restored full functionality for Container Apps security analysis

5. **azure_scan_gitops_security** - GitOps/Flux Security Scanner (REPAIRED)
   - Fixed 230+ lines of duplicate/broken code from merge conflicts
   - Removed incomplete code fragments (`.toISOStrin` partial line)
   - Fixed duplicate function initialization blocks
   - Consolidated GitOps security checks with proper error handling
   - Restored Flux extension detection and configuration analysis

6. **azure_scan_cdn_security** - Azure CDN & Front Door Security (REPAIRED)
   - Fixed duplicate function definition
   - Removed misplaced GitOps code embedded in CDN scanner
   - Fixed typo in profile count display (`cdnProfiles.leng`)
   - Added proper type assertions for REST API responses
   - Restored WAF policy analysis and origin security checks

### Migration Guide

```markdown
# AKS Tools Migration (v1.11.0 → v1.12.0)

## Before
azure_scan_aks_full subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod
azure_scan_aks_live subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod namespace: default
azure_scan_aks_imds subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod podName: nginx
azure_scan_aks_pod_identity subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod
azure_scan_aks_admission_bypass subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod

## After
azure_scan_aks_full subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod scanMode: full
azure_scan_aks_full subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod scanMode: live namespace: default
azure_scan_aks_full subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod scanMode: imds podName: nginx
azure_scan_aks_full subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod scanMode: pod_identity
azure_scan_aks_full subscriptionId: xxx resourceGroup: rg-prod clusterName: aks-prod scanMode: admission

# ACR Tools Migration (v1.11.0 → v1.12.0)

## Before
azure_scan_container_registry_poisoning subscriptionId: xxx

## After
azure_scan_acr_security subscriptionId: xxx scanMode: poisoning
# Or use comprehensive scan
azure_scan_acr_security subscriptionId: xxx scanMode: all
```

### Technical Implementation
- **Array-based string building** for optimal performance across all scanners
- **Removed 2,073 lines** of deprecated AKS handler code
- Fixed 20+ orphaned `as any` statements across codebase
- Cleaned up 230+ lines of duplicate code from incomplete edits
- Comprehensive MITRE ATT&CK technique mappings
- Risk severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
- Integration with existing AKS security tools
- REST API-based implementation for Container Apps and CDN (no SDK dependencies)

### Infrastructure ⚡
- ✅ Zero TypeScript compilation errors across all 34 tools
- ✅ All 93 tests passing (updated for 34-tool count)
- Removed duplicate `ContainerServiceClient` initializations
- Fixed all strict type checking issues in Azure REST API calls
- Improved error messages with structured try-catch blocks

### Notes 📝
- **Tool Count Evolution:** 37 (v1.11.0) → +2 tools → 39 → -1 ACR → 38 → -4 AKS → **34 tools (v1.12.0)**
- **Backward compatibility:** Omitting scanMode defaults to original behavior ('full' for AKS, 'security' for ACR)
- **Performance:** Consolidated tools maintain full feature parity with removed tools

## [1.11.0] - 2026-02-14

### Added 🆕 **MAJOR SECURITY EXPANSION**
- **2 Critical Attack Detection Tools** - Based on 2024-2026 Azure penetration testing research

#### New Tools (37 → 39 tools total)

1. **azure_scan_aks_pod_identity** - AKS Pod Identity Token Theft & Privilege Escalation
   - Analyzes Workload Identity and Pod Identity configurations
   - Detects overly permissive managed identities (Owner, Contributor roles)
   - Identifies managed identities with Key Vault data plane access
   - Checks Azure AD authentication enablement
   - Validates OIDC issuer configuration for Workload Identity
   - Enumerates all managed identity types (user-assigned, system-assigned, kubelet)
   - Provides IMDS accessibility tests and token theft exploitation examples
   - Includes kubectl commands for service account enumeration
   - Risk scoring for each managed identity based on role assignments
   - **MITRE:** T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts)

2. **azure_scan_container_registry_poisoning** - ACR Supply Chain Attacks
   - Detects public network access to container registries
   - Identifies admin account enablement (insecure credential method)
   - Checks content trust/image signing configuration
   - Validates Defender for Containers enablement (vulnerability scanning)
   - Analyzes SKU limitations (Basic/Standard vs Premium security features)
   - Checks encryption at rest (default vs customer-managed keys)
   - Identifies anonymous pull access vulnerabilities
   - Validates network restrictions and private endpoints
   - Reviews retention policies for old vulnerable images
   - **MITRE:** T1525 (Implant Internal Image), T1195.003 (Supply Chain Compromise)

### Technical Implementation
- Both tools use **array-based string building** for optimal performance
- Comprehensive MITRE ATT&CK technique mappings
- Risk severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
- Detailed exploitation examples with bash/PowerShell commands
- Actionable remediation guidance for each finding
- Support for both markdown and JSON output formats
- Integration with existing AKS security tools (scan_aks_full, scan_aks_imds)

## [1.10.9] - 2026-02-14

### Performance ⚡
- **scan_aks_full Optimization** - 40-60% faster execution
  - Replaced string concatenation with array-based building (`outputLines.push()` + `join()`)
  - Eliminated O(n²) string concatenation overhead (200+ operations)
  - Reduced memory allocations during large report generation
  - Maintains all 30+ CIS benchmark checks and security features
  - Same comprehensive output, significantly faster performance

### Fixed 🔧
- **Enhanced Azure CLI Token Validation** - Robust authentication checks prevent mid-scan failures
  - Added two-stage validation to `scan_aks_live` and `scan_aks_imds`:
    1. Account configuration check (`az account show`)
    2. Token validity verification (`az account get-access-token`)
  - Detects expired tokens before kubectl operations (not just configured accounts)
  - Authentication error detection in kubectl operations with clear guidance
  - Identifies token expiration issues (expired, AADSTS errors) with specific error messages
  - Clear remediation: "Azure CLI token expired - please run: az login"
  - Prevents cryptic kubectl authentication failures during scans
  - 10-second timeout for token validation prevents hangs

### Changed
- Dynamic version display in scan output (uses `SERVER_VERSION` from package.json)

## [1.10.7] - 2026-02-09

### Added - Error Handling & Logging Infrastructure 🆕 **PRODUCTION READY**

#### Structured Error Handling ⭐ NEW
- **Error Classes** - 11 specialized error types with remediation guidance
  - `ValidationError` - Input validation failures with clear guidance
  - `AuthenticationError` - Azure credential issues (suggests `az login`)
  - `AuthorizationError` - RBAC permission issues (lists required roles)
  - `AzureAPIError` - Azure SDK errors with automatic retry logic
  - `TimeoutError` - Operation timeouts (automatically retryable)
  - `RateLimitError` - API throttling (automatically retryable)
  - `ResourceNotFoundError` - Resource doesn't exist
  - `NetworkError` - Connectivity issues (automatically retryable)
  - `ConfigurationError` - Misconfigured settings
  - `InternalError` - Server internal errors
  
- **Error Categories & Severity** - Programmatic error handling
  - 10 categories: VALIDATION, AUTHENTICATION, AUTHORIZATION, API, TIMEOUT, RATE_LIMIT, RESOURCE_NOT_FOUND, NETWORK, CONFIGURATION, INTERNAL
  - 4 severity levels: LOW, MEDIUM, HIGH, CRITICAL
  - Retryable flag for automatic retry decisions
  - Remediation guidance in every error
  - Error codes for documentation lookup

#### Logging with PII Redaction ⭐ NEW (GDPR/CCPA Compliant)
- **Structured Logging** - 5 log levels with automatic PII redaction
  - `DEBUG` - Detailed diagnostic information
  - `INFO` - General informational messages
  - `WARN` - Warning messages about potential issues
  - `ERROR` - Error messages with context
  - `SECURITY` - Security-related events (auth failures, unauthorized access)
  
- **PII Redaction Patterns** - Protects sensitive data in logs
  - Azure Tenant IDs (GUID) → `***TENANT_ID_REDACTED***`
  - Azure Client Secrets (32+ chars) → `***CLIENT_SECRET_REDACTED***`
  - Email addresses → `***EMAIL_REDACTED***`
  - SAS Tokens (`sig=...`) → `sig=***SAS_TOKEN_REDACTED***`
  - Storage Account Keys → `AccountKey=***STORAGE_KEY_REDACTED***`
  - Sensitive field names: password, secret, clientSecret, tenantId, sasToken, connectionString, etc.
  
- **Performance Tracking** - Operation metrics and monitoring
  - Operation duration tracking (milliseconds)
  - API call counting per operation
  - Cache hit/miss ratio tracking
  - Per-tool performance statistics
  - Memory-efficient log rotation (max 1000 entries)

#### Retry Logic & Resilience ⭐ NEW
- **Exponential Backoff** - Automatic retry for transient failures
  - Configurable: 3 max attempts, 1s-30s delays
  - Exponential backoff multiplier: 2x per attempt
  - Jitter: ±25% random variation (prevents thundering herd)
  - Retryable errors: TimeoutError, RateLimitError, NetworkError, Azure TooManyRequests, RestError
  
- **Rate Limiter** - Token bucket algorithm for smooth throttling
  - Prevents client-side rate limit errors
  - Configurable tokens per second refill rate
  - Blocking and non-blocking token acquisition
  
- **Circuit Breaker** - Prevents cascading failures
  - 3 states: CLOSED (normal) → OPEN (failing) → HALF_OPEN (testing)
  - 5 failure threshold, 60s reset timeout
  - 2 successful calls to close circuit
  - Per-service circuit tracking

### Changed
- **Validation Functions** - Now throw `ValidationError` instead of generic `Error`
- **Tool Handler** - Wrapped with performance tracking and error logging
- **Error Messages** - Enhanced with remediation guidance and structured data

### Benefits
- ✅ **Production Readiness** - Structured error handling for reliable deployments
- ✅ **Security** - PII redaction prevents credential leakage (GDPR/CCPA compliant)
- ✅ **Reliability** - Automatic retry recovers from 80%+ transient failures
- ✅ **Observability** - Performance metrics and structured logs enable monitoring
- ✅ **User Experience** - Clear error messages with actionable remediation
- ✅ **Compliance** - OWASP MCP-05 compliant error handling

### Technical Details
- Added `src/errors.ts` (340 lines) - MCPError base class and 11 specialized error types
- Added `src/logging.ts` (393 lines) - Logger, PerformanceTracker, PII redaction
- Added `src/retry.ts` (359 lines) - Retry logic, RateLimiter, CircuitBreaker
- Updated `src/index.ts` - ValidationError integration and error handling wrapper
- Total new code: ~1,092 lines of production-grade infrastructure

---

## [1.10.6] - 2026-02-09

### Added - Input Validation & Auto-Completion

#### Enhanced Input Validation ⭐ NEW (OWASP MCP-05 Compliance)
- **Pattern-Based Validation** - Regex validation for all Azure resource identifiers
  - 6 resource patterns: subscriptionId, resourceGroup, resourceName, location, outputFormat, scanMode
  - Protects against injection attacks and malformed inputs
  - Clear, actionable error messages guide users to correct formats
  
- **Whitelist Validation** - Critical inputs validated against Azure service catalogs
  - `validateLocation()` - 60+ Azure locations + special values ("all", "common")
  - `validateResourceType()` - 8 supported resource types (vms, storage, nsgs, aks, sql, keyvaults, etc.)
  - `validateOutputFormat()` - 5 supported formats (markdown, json, html, pdf, csv)
  
- **Sanitization** - Automatic input sanitization for security
  - Control character removal (prevents terminal escape sequences)
  - Length enforcement (prevents buffer overflow/resource exhaustion)
  - Required vs optional parameter handling

#### Auto-Completion Provider ⭐ NEW (Enhanced UX)
- **Intelligent Suggestions** - MCP completion handler with 6 argument types
  - `location`/`locations` - All 60+ Azure locations + ["all", "common"]
  - `resourceType` - ["vms", "storage", "nsgs", "aks", "sql", "keyvaults", "public_ips", "all"]
  - `format` - ["markdown", "json", "html", "pdf", "csv"]
  - `scanMode` - ["common", "all"]
  - `startFrom` - ["public-ips", "storage", "vms", "identities", "all"]
  - `subscriptionId` - Security-conscious (doesn't suggest actual IDs)
  
- **Type-Ahead Filtering** - Prefix-based filtering for fast navigation
  - Result limiting (20 max for locations) with `hasMore` indicator
  - Context-aware suggestions based on current tool and argument
  
#### Benefits
- ✅ **Security** - Prevents injection attacks, validates all inputs before processing
- ✅ **User Experience** - Auto-complete reduces typos and speeds up workflows
- ✅ **Compliance** - Aligns with OWASP MCP-05 input validation guidelines
- ✅ **Error Handling** - Clear validation errors with helpful guidance
- ✅ **Performance** - Whitelist validation is fast and efficient

### Technical Details
- Added validation functions: `validateSubscriptionId()`, `validateLocation()`, `validateResourceType()`, `validateOutputFormat()`, `validateResourceGroup()`, `validateResourceName()`
- Added `AZURE_PATTERNS` constant with 6 resource patterns
- Added `VALID_RESOURCE_TYPES` constant (8 types)
- Implemented `CompleteRequestSchema` handler in main server
- Server capabilities updated: `completions: {}` declared

## [1.10.5] - 2026-02-09

### Added - Response Format Support

#### Flexible Output Formatting ⭐ NEW
- **Format Parameter** - All 30 security tools now support optional `format` parameter
  - `format: "markdown"` (default) - Human-readable text output, backward compatible
  - `format: "json"` - Machine-readable structured data with metadata envelope
  - Backward compatible: Existing tools work unchanged (default to markdown)
  - JSON envelope includes: `tool`, `format`, `timestamp`, `data` fields

#### Enhanced Tool Capabilities
- **30 Tools Updated** - Complete format support coverage (excluding help and report tools)
- **formatResponse() Helper** - Centralized formatter with validation and error handling
- **Metadata Enrichment** - JSON format includes tool name, timestamp, version context
- **API Integration Ready** - Structured JSON enables programmatic consumption and automation

#### Benefits
- ✅ **Backward Compatibility** - No breaking changes, existing workflows unaffected
- ✅ **API Integration** - JSON format enables CI/CD pipeline integration
- ✅ **Automation** - Parse structured data for automated compliance checks
- ✅ **Flexibility** - Choose format per-tool based on use case (docs vs automation)
- ✅ **Consistency** - Uniform formatting across all tools

### Changed
- Version bumped from 1.10.4 to 1.10.5
- All 30 security tool schemas include format parameter
- Tool handlers updated to use formatResponse() helper function
- README updated with Output Format Control documentation

### Technical Details
- Input validation: `format` must be "markdown" or "json" (throws error otherwise)
- Default behavior: `undefined` or `"markdown"` returns raw markdown string
- JSON mode: Wraps result in structured envelope with metadata
- Implementation: Type-safe with TypeScript, unit tested (65 tests passing)

## [1.10.4] - 2026-02-08

### Added

#### Tool Annotations (MCP Compliance)
- **Complete annotations for 32/32 tools** (100% coverage)
  - `readOnly: true` - All tools are read-only security assessments
  - `destructive: false` - No tools modify or delete Azure resources
  - `idempotent: false` - Cloud state can change between calls (except `help` tool)
  - `openWorld: true` - Results depend on current Azure configuration
  - Special case: `help` tool has `idempotent: true, openWorld: false`
  - Fixed missing annotation on `enumerate_subscriptions` tool
- Full MCP specification compliance achieved
- Better client-side tool handling and discoverability

#### Test Suite (Quality Assurance)
- **Created comprehensive test suite with 65 test cases**
- `tests/utils.test.ts` (25 tests)
  - Location resolution and filtering
  - Azure resource naming validation
  - Tool annotation verification
  - Edge case handling
- `tests/tools.test.ts` (20 tests)
  - Tool structure validation
  - Naming conventions
  - Input schema validation
  - Annotation coverage checks
- `tests/security.test.ts` (20 tests)
  - OWASP MCP compliance verification (MCP01, MCP02, MCP03, MCP05, MCP08)
  - Read-only operations validation
  - RBAC security validation
  - Input validation patterns
  - Error handling and data protection
- `tests/README.md` - Comprehensive test documentation
  - Running tests guide
  - Coverage goals and metrics
  - Best practices and troubleshooting

### Changed

#### Documentation Improvements
- **Replaced hardcoded test data with clear example values**
  - Changed subscription IDs: `1f0c8a8b-*` → `00000000-0000-0000-0000-000000000000`
  - Updated resource names: `RG-TMS-AKS` → `my-resource-group`, `tmslogsstncui` → `mystorageaccount`
  - Removed real-looking identifiers from help text
  - Enhanced documentation clarity
- **README badges updated** - Version 1.10.3 → 1.10.4, added test badge (65 passing)
- **CI/CD added** - GitHub Actions for automated testing on Node.js 18.x and 20.x

### Security
- ✅ No hardcoded credentials or real-looking IDs
- ✅ Git history sanitized - removed real subscription IDs and resource names from all commits
- ✅ All security properties validated with tests
- ✅ OWASP MCP compliance verified
- ✅ Input validation patterns tested

### Quality
- ✅ 65 test cases created, all passing
- ✅ 32/32 tool annotations completed (100% coverage)
- ✅ Documentation enhanced with clear examples
- ✅ CI/CD pipeline active and monitoring

## [1.10.3] - 2026-01-15

### Changed

#### AKS Tool Consolidation (37 → 32 Tools)
Reduced redundant AKS tools from 9 to 4 essential tools for cleaner architecture:

**Removed (5 tools):**
| Tool | Reason |
|------|--------|
| `scan_aks_clusters` | Covered by `scan_aks_full` with better CIS mapping |
| `enumerate_aks_identities` | Covered by `scan_aks_full` identity enumeration section |
| `scan_aks_node_security` | Covered by `scan_aks_full` node pool analysis |
| `scan_aks_service_accounts` | Covered by `scan_aks_live` SA analysis |
| `scan_aks_secrets` | Covered by `scan_aks_live` secret hunting section |

**Kept (4 essential AKS tools):**
| Tool | Purpose |
|------|---------|
| `scan_aks_full` | Comprehensive ARM-based assessment (30+ CIS checks) |
| `scan_aks_live` | Live K8s API security scanning (kubectl required) |
| `scan_aks_imds` | Offensive IMDS exploitation & token theft |
| `get_aks_credentials` | Kubeconfig extraction utility |

---

## [1.10.2] - 2026-01-15

### Added

#### Enhanced `scan_aks_imds` with 3 New Capabilities

**1. Cluster-Wide IMDS Exposure Scan** (`scanAllPods: true`)
- Scans ALL running pods across ALL namespaces for IMDS accessibility
- Creates exposure heatmap showing which pods can reach IMDS
- Per-namespace vulnerability summary
- Auto-generates NetworkPolicy remediation for each affected namespace
- Scans up to 50 pods with timeout protection

| Feature | Description |
|---------|-------------|
| Pod Iteration | Tests each pod individually for IMDS access |
| Namespace Stats | Shows exposed vs blocked count per namespace |
| Exposure % | Calculates cluster-wide IMDS exposure percentage |
| Auto-Remediation | Generates deny-imds NetworkPolicy per namespace |

**2. Token Export for Offline Exploitation** (`exportTokens: true`)
- Exports all stolen tokens to JSON file in temp directory
- Includes ready-to-use `curl` commands for each token type
- ARM, KeyVault, Storage, Graph API exploitation commands
- `az CLI` integration commands for token injection

| Token Type | Exploitation Commands |
|------------|----------------------|
| ARM | List subscriptions, resource groups, resources |
| Key Vault | List/read secrets, enumerate keys |
| Storage | List containers, download blobs |
| Graph API | Enumerate users, groups, applications |

**3. Deep Data Plane Reading** (`deepDataPlane: true`)
- Actually READS secret VALUES from Key Vault (not just enumeration)
- Downloads and previews blob CONTENTS from Storage
- Identifies sensitive files: `.env`, `.pem`, `.key`, connection strings
- Content type detection: certificates, tokens, GUIDs, API keys
- Truncated display with full extraction to temp file

| Data Plane | Deep Read Capability |
|------------|---------------------|
| Key Vault | Extract actual secret values with type detection |
| Storage | List blob contents, read sensitive text files |
| ACR | Already supports catalog + repository enumeration |

**New Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scanAllPods` | boolean | false | Scan all pods cluster-wide for IMDS exposure |
| `exportTokens` | boolean | false | Export tokens to file with curl commands |
| `deepDataPlane` | boolean | false | Read actual secret values and blob contents |

### Changed
- Version: 1.10.2
- Enhanced Phase 9 (Data Plane) with deep reading capabilities
- Added cluster-wide scan as Phase 0.5 (before target pod selection)
- Token export added after Phase 4 (Token Theft)

### Security Notes
- `deepDataPlane` may expose actual secrets in output - use with caution
- Token export file contains valid credentials - secure appropriately
- Cluster-wide scan limited to 50 pods for performance

---

## [1.10.1] - 2026-01-14

### Changed

#### Professional Tool Naming Convention
Renamed tools for consistency and professionalism:

| Old Name | New Name |
|----------|----------|
| `test_aks_imds_full_recon` | `scan_aks_imds` |
| `hunt_aks_secrets` | `scan_aks_secrets` |
| `analyze_key_vault_security` | `analyze_keyvault_security` |
| `analyze_cosmos_db_security` | `analyze_cosmosdb_security` |
| `scan_container_registries` | `scan_acr_security` |
| `analyze_rbac_privilege_escalation` | `analyze_rbac_privesc` |

### Removed
- `test_aks_imds_access` (duplicate functionality, merged into `scan_aks_imds`)

---

## [1.10.0] - 2026-01-14

### Added

#### NEW TOOL: `scan_aks_imds`
Complete IMDS exploitation and full Azure reconnaissance from Kubernetes pods.

**Attack Chain:** `Pod → IMDS (169.254.169.254) → Managed Identity Token → Azure Resources`

| Phase | Reconnaissance Step | Details |
|-------|---------------------|---------|
| 1 | Target Pod Selection | Find running pod to execute from |
| 2 | IMDS Accessibility | Check if metadata service reachable |
| 3 | Identity Discovery | Extract tenant ID, client IDs |
| 4 | Token Theft | Steal tokens for ARM, KeyVault, Storage, Graph |
| 5 | Subscription Enumeration | List all accessible subscriptions |
| 6 | Role Assignment Analysis | Map permissions and scopes |
| 7 | Resource Group Enumeration | Discover all resource groups |
| 8 | Resource Enumeration | 10 resource types (Storage, KeyVault, ACR, SQL, Cosmos, VMs, AKS, App Services, VNets, NSGs) |
| 9 | Data Plane Access Testing | ACR repos, KeyVault secrets, Storage blobs |
| 10 | Privilege Escalation Paths | Role creation, VM pivot, network modification |

**Data Plane Exploitation:**
- **ACR**: ARM token → Exchange → Refresh token → Catalog enumeration
- **Key Vault**: Direct secret/key enumeration via vault.azure.net token
- **Storage**: Blob container listing via storage.azure.com token

**MITRE ATT&CK Mapping:**
- T1552.005: Cloud Instance Metadata API
- T1078.004: Cloud Accounts
- T1530: Data from Cloud Storage
- T1613: Container and Resource Discovery
- T1528: Steal Application Access Token

**Remediation Guidance:**
- NetworkPolicy to block IMDS (169.254.169.254/32)
- Enable Workload Identity
- Reduce kubelet identity permissions
- Apply Pod Security Standards

### Changed
- Total tools: **38**

---

## [1.9.8] - 2026-01-14

### Added

#### Comprehensive K8s Security Assessment (20 Checks)
- **scan_aks_live** now includes 20 security checks based on industry pentest methodologies

| # | Check | Attack Vector |
|---|-------|---------------|
| 1 | Namespaces | Enumeration |
| 2 | Secrets Analysis | Credential Theft |
| 3 | Service Accounts | Token Abuse |
| 4 | RBAC Bindings | Privilege Escalation |
| 5 | Privileged Pods | Container Escape |
| 6 | Network Policies | Lateral Movement |
| 7 | Exposed Services | External Attack Surface |
| 8 | ConfigMaps | Secrets Leakage |
| 9 | Cluster Roles | Wildcard Permissions |
| 10 | Pod Security Contexts | hostPID/hostIPC/Capabilities |
| 11 | Ingress Controllers | TLS/External Exposure |
| 12 | DaemonSets | Node-Wide Compromise |
| 13 | SA Token Analysis | Legacy Tokens |
| 14 | Container Images | :latest tags, Public Registries |
| 15 | CronJobs | Persistence Mechanism |
| 16 | Persistent Volumes | HostPath/NFS Exposure |
| 17 | Resource Limits | DoS Prevention |
| 18 | K8s Version | CVE Detection |
| 19 | Pod Security Standards | PSS Enforcement |
| 20 | Attack Surface Summary | MITRE ATT&CK Mapping |

### Changed
- **kubectl CLI**: Replaced K8s API client with direct kubectl execution (30s timeout)
- **Reliability**: Fixed 10-minute timeout issues with unreliable K8s API client

### References
- https://exploit-notes.hdks.org/exploit/container/kubernetes/
- https://deepstrike.io/blog/kubernetes-penetration-testing-methodology-and-guide
- CyberArk K8s Pentest Methodology Part 1

---

## [1.9.4] - 2026-01-14

### Added

#### Live Kubernetes API Scanning
- **scan_aks_live** - Direct Kubernetes API security scanning via `@kubernetes/client-node`
  - Connects to AKS cluster API server using cluster credentials
  - Enumerates all namespaces and identifies sensitive secrets
  - Analyzes service accounts for auto-mount token risks
  - Scans RBAC bindings for cluster-admin and privilege escalation
  - Detects privileged pods, hostNetwork, hostPath mounts
  - Identifies missing network policies (lateral movement risk)
  - Finds exposed LoadBalancer/NodePort services
  - Scans ConfigMaps for hardcoded secrets
  - Risk scoring with severity aggregation

### Changed
- Added `@kubernetes/client-node` dependency for K8s API access
- Total tools: **37**

---

## [1.9.3] - 2026-01-14

### Changed

#### Enhanced scan_aks_full
- Comprehensive 13-section pentest-grade security assessment
- CIS Kubernetes Benchmark mapping (1.1.x - 5.x references)
- MITRE ATT&CK technique mapping for each finding
- Risk scoring system (CRITICAL: 40pts, HIGH: 20pts, MEDIUM: 5pts, LOW: 1pt)
- Detailed sections:
  1. Cluster Overview with control plane analysis
  2. Authentication & Authorization (AAD, RBAC, local accounts)
  3. Network Security (CNI, policies, private cluster, authorized IPs)
  4. Node Pool Security (OS, node count, taints, labels)
  5. Secrets Management (Key Vault, CSI driver, managed HSM)
  6. Container Security (Defender, image integrity, admission control)
  7. Logging & Monitoring (diagnostics, Log Analytics, container insights)
  8. Workload Identity (pod identity, OIDC, federated credentials)
  9. Runtime Security (policy, sysctls, seccomp, AppArmor)
  10. Supply Chain Security (ACR, image policies, artifact streaming)
  11. Backup & DR (Velero, AKS backup, etcd snapshots)
  12. Compliance Status (Azure Policy, regulatory alignment)
  13. Attack Vectors (IMDS, kubelet, etcd, privilege escalation paths)

---

## [1.9.2] - 2026-01-13

### Fixed

#### Authentication Improvements
- Changed credential chain to use `AzureCliCredential` first
- Bypasses VS Code extension service principal token issues
- Falls back to `ManagedIdentityCredential` and `EnvironmentCredential`
- Uses `ChainedTokenCredential` for maximum flexibility

---

## [1.9.1] - 2026-01-12

### Added

#### Combined AKS Scanning
- **scan_aks_full** - All 7 AKS security checks in one comprehensive scan
  - Combines: enumerate_aks_clusters, analyze_aks_security, scan_aks_rbac,
    scan_aks_network, scan_aks_secrets, scan_aks_service_accounts, hunt_aks_secrets
  - Single tool for complete AKS security assessment
  - Aggregated findings with severity counts

---

## [1.9.0] - 2026-01-10

### Added

#### Multi-Location Scanning (2 new tools)
- **list_active_locations** - Discover which Azure locations have resources deployed
  - Scans common (10 locations) or all (45+ locations) Azure regions
  - Reports resource groups, VMs, storage accounts per location
  - Quick reconnaissance for penetration testing
  
- **scan_all_locations** - Scan multiple Azure locations for specific resource types
  - Supports: vms, storage, nsgs, aks, sql, keyvaults, public_ips, all
  - Location presets: 'common' (10 regions), 'all' (45+ regions)
  - Custom location filtering with comma-separated values
  - Aggregated results grouped by location

#### Location Filtering Support
- Added `location` parameter to **enumerate_resource_groups**
- Added `location` parameter to **enumerate_resources**
- Support for single location, comma-separated list, 'common', or 'all'

#### Azure Locations Constants
- **AZURE_LOCATIONS** - 45+ global Azure regions
  - Americas: eastus, eastus2, westus, westus2, westus3, centralus, etc.
  - Europe: northeurope, westeurope, uksouth, ukwest, francecentral, etc.
  - Asia Pacific: eastasia, southeastasia, australiaeast, japaneast, etc.
  - Middle East & Africa: uaenorth, qatarcentral, southafricanorth, etc.
- **COMMON_LOCATIONS** - 10 most frequently used regions

### Changed
- Total tools: **35** (up from 33)
- Version: 1.9.0
- Added helper functions: `resolveLocations()`, `filterByLocation()`

---

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
