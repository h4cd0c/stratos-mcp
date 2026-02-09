/**
 * Stratos Azure MCP - Structured Error Handling
 * See package.json for version
 * 
 * Provides comprehensive error handling with:
 * - Error categorization
 * - Severity levels
 * - Remediation guidance
 * - Error codes for programmatic handling
 */

export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  API = 'API',
  TIMEOUT = 'TIMEOUT',
  RATE_LIMIT = 'RATE_LIMIT',
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
  NETWORK = 'NETWORK',
  CONFIGURATION = 'CONFIGURATION',
  INTERNAL = 'INTERNAL',
}

export enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface StructuredError {
  code: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  message: string;
  details?: Record<string, any>;
  remediation?: string;
  timestamp: string;
  retryable: boolean;
}

/**
 * Base class for all MCP server errors
 */
export class MCPError extends Error {
  public readonly code: string;
  public readonly category: ErrorCategory;
  public readonly severity: ErrorSeverity;
  public readonly details?: Record<string, any>;
  public readonly remediation?: string;
  public readonly timestamp: string;
  public readonly retryable: boolean;

  constructor(
    message: string,
    code: string,
    category: ErrorCategory,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    retryable: boolean = false,
    details?: Record<string, any>,
    remediation?: string
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.category = category;
    this.severity = severity;
    this.details = details;
    this.remediation = remediation;
    this.timestamp = new Date().toISOString();
    this.retryable = retryable;

    Error.captureStackTrace(this, this.constructor);
  }

  toJSON(): StructuredError {
    return {
      code: this.code,
      category: this.category,
      severity: this.severity,
      message: this.message,
      details: this.details,
      remediation: this.remediation,
      timestamp: this.timestamp,
      retryable: this.retryable,
    };
  }

  toString(): string {
    return `[${this.severity}] ${this.category}/${this.code}: ${this.message}${this.remediation ? `\nRemediation: ${this.remediation}` : ''}`;
  }
}

/**
 * Validation errors (invalid inputs)
 */
export class ValidationError extends MCPError {
  constructor(
    message: string,
    details?: Record<string, any>,
    remediation?: string
  ) {
    super(
      message,
      'VALIDATION_ERROR',
      ErrorCategory.VALIDATION,
      ErrorSeverity.MEDIUM,
      false,
      details,
      remediation || 'Check input parameters and format. Refer to tool documentation.'
    );
  }
}

/**
 * Authentication errors (Azure credentials invalid/missing)
 */
export class AuthenticationError extends MCPError {
  constructor(
    message: string,
    details?: Record<string, any>
  ) {
    super(
      message,
      'AUTH_ERROR',
      ErrorCategory.AUTHENTICATION,
      ErrorSeverity.HIGH,
      false,
      details,
      'Verify Azure credentials: az login or set Azure environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET).'
    );
  }
}

/**
 * Authorization errors (insufficient RBAC permissions)
 */
export class AuthorizationError extends MCPError {
  constructor(
    message: string,
    requiredRoles?: string[],
    details?: Record<string, any>
  ) {
    super(
      message,
      'AUTHZ_ERROR',
      ErrorCategory.AUTHORIZATION,
      ErrorSeverity.HIGH,
      false,
      { ...details, requiredRoles },
      requiredRoles 
        ? `Grant RBAC roles: ${requiredRoles.join(', ')}` 
        : 'Verify user/service principal has required RBAC permissions for this operation.'
    );
  }
}

/**
 * Azure API errors
 */
export class AzureAPIError extends MCPError {
  constructor(
    message: string,
    azureErrorCode?: string,
    statusCode?: number,
    retryable: boolean = false,
    details?: Record<string, any>
  ) {
    super(
      message,
      azureErrorCode || 'AZURE_API_ERROR',
      ErrorCategory.API,
      statusCode && statusCode >= 500 ? ErrorSeverity.HIGH : ErrorSeverity.MEDIUM,
      retryable,
      { ...details, statusCode, azureErrorCode },
      retryable 
        ? 'Retry the operation. If error persists, check Azure service health status.' 
        : 'Check Azure API documentation for this error code. Verify resource exists and parameters are correct.'
    );
  }
}

/**
 * Timeout errors
 */
export class TimeoutError extends MCPError {
  constructor(
    operation: string,
    timeoutMs: number,
    details?: Record<string, any>
  ) {
    super(
      `Operation '${operation}' timed out after ${timeoutMs}ms`,
      'TIMEOUT_ERROR',
      ErrorCategory.TIMEOUT,
      ErrorSeverity.MEDIUM,
      true,
      { ...details, operation, timeoutMs },
      'Increase timeout value or check network connectivity. Operation can be retried.'
    );
  }
}

/**
 * Rate limit errors
 */
export class RateLimitError extends MCPError {
  constructor(
    message: string,
    retryAfterMs?: number,
    details?: Record<string, any>
  ) {
    super(
      message,
      'RATE_LIMIT_ERROR',
      ErrorCategory.RATE_LIMIT,
      ErrorSeverity.MEDIUM,
      true,
      { ...details, retryAfterMs },
      retryAfterMs 
        ? `Wait ${retryAfterMs}ms before retrying.` 
        : 'Reduce request rate or implement exponential backoff.'
    );
  }
}

/**
 * Resource not found errors
 */
export class ResourceNotFoundError extends MCPError {
  constructor(
    resourceType: string,
    resourceId: string,
    subscriptionId?: string,
    details?: Record<string, any>
  ) {
    super(
      `${resourceType} '${resourceId}' not found${subscriptionId ? ` in subscription ${subscriptionId}` : ''}`,
      'RESOURCE_NOT_FOUND',
      ErrorCategory.RESOURCE_NOT_FOUND,
      ErrorSeverity.LOW,
      false,
      { ...details, resourceType, resourceId, subscriptionId },
      'Verify resource ID and subscription are correct. Resource may have been deleted.'
    );
  }
}

/**
 * Network errors
 */
export class NetworkError extends MCPError {
  constructor(
    message: string,
    details?: Record<string, any>
  ) {
    super(
      message,
      'NETWORK_ERROR',
      ErrorCategory.NETWORK,
      ErrorSeverity.HIGH,
      true,
      details,
      'Check network connectivity and firewall rules. Verify Azure endpoints are accessible.'
    );
  }
}

/**
 * Configuration errors
 */
export class ConfigurationError extends MCPError {
  constructor(
    message: string,
    configKey?: string,
    details?: Record<string, any>
  ) {
    super(
      message,
      'CONFIG_ERROR',
      ErrorCategory.CONFIGURATION,
      ErrorSeverity.HIGH,
      false,
      { ...details, configKey },
      configKey 
        ? `Set configuration: ${configKey}` 
        : 'Review server configuration and environment variables.'
    );
  }
}

/**
 * Internal server errors
 */
export class InternalError extends MCPError {
  constructor(
    message: string,
    originalError?: Error,
    details?: Record<string, any>
  ) {
    super(
      message,
      'INTERNAL_ERROR',
      ErrorCategory.INTERNAL,
      ErrorSeverity.CRITICAL,
      false,
      { ...details, originalError: originalError?.message, stack: originalError?.stack },
      'This is an internal server error. Please report to maintainers with error details.'
    );
  }
}

/**
 * Convert unknown errors to structured errors
 */
export function normalizeError(error: unknown): MCPError {
  if (error instanceof MCPError) {
    return error;
  }

  if (error instanceof Error) {
    if ('statusCode' in error || 'code' in error) {
      const azureError = error as any;
      return new AzureAPIError(
        error.message,
        azureError.code || azureError.name,
        azureError.statusCode,
        azureError.statusCode >= 500 || azureError.code === 'ETIMEDOUT',
        {
          requestId: azureError.request?.requestId,
        }
      );
    }

    if (error.message.includes('timeout') || error.message.includes('ETIMEDOUT')) {
      return new TimeoutError('Operation', 30000, { originalMessage: error.message });
    }

    if (
      error.message.includes('ECONNREFUSED') ||
      error.message.includes('ENOTFOUND') ||
      error.message.includes('ENETUNREACH')
    ) {
      return new NetworkError(error.message);
    }

    // Default to internal error
    return new InternalError(error.message, error);
  }

  // Unknown error type
  return new InternalError(
    'An unknown error occurred',
    undefined,
    { originalError: String(error) }
  );
}

/**
 * Format error for user display (markdown)
 */
export function formatErrorMarkdown(error: MCPError): string {
  return `
## ❌ Error: ${error.category}

**Severity:** ${error.severity}  
**Code:** \`${error.code}\`  
**Message:** ${error.message}

${error.details ? `**Details:**\n\`\`\`json\n${JSON.stringify(error.details, null, 2)}\n\`\`\`\n` : ''}
${error.remediation ? `### 💡 Remediation\n${error.remediation}\n` : ''}
${error.retryable ? '**Note:** This operation can be retried automatically.\n' : ''}

*Timestamp: ${error.timestamp}*
`.trim();
}

/**
 * Format error for JSON response
 */
export function formatErrorJSON(error: MCPError): string {
  return JSON.stringify(
    {
      error: error.toJSON(),
    },
    null,
    2
  );
}
