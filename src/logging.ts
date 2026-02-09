/**
 * Nimbus Azure MCP - Logging and Performance Tracking
 * See package.json for version
 * 
 * Provides:
 * - Structured logging with levels
 * - PII redaction
 * - Performance metrics
 * - Request/response logging
 */

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  SECURITY = 'SECURITY',
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: Record<string, any>;
  tool?: string;
  duration?: number;
  requestId?: string;
}

interface PerformanceMetrics {
  toolName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  success: boolean;
  errorCode?: string;
  apiCalls?: number;
  cacheHits?: number;
  cacheMisses?: number;
}

/**
 * PII patterns to redact from logs
 */
const PII_PATTERNS = [
  // Azure Tenant IDs (GUID format)
  { pattern: /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, replacement: '***TENANT_ID_REDACTED***' },
  // Azure Client Secrets (base64-like strings)
  { pattern: /([A-Za-z0-9~._-]{32,})/g, replacement: '***CLIENT_SECRET_REDACTED***' },
  // Email addresses
  { pattern: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, replacement: '***EMAIL_REDACTED***' },
  // Azure Subscription IDs (GUID format - already covered by first pattern but keeping for clarity)
  // IP addresses (be conservative, some IPs are not PII)
  // { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '***IP_REDACTED***' },
  // SAS tokens
  { pattern: /(sig=[A-Za-z0-9%+/=]+)/gi, replacement: 'sig=***SAS_TOKEN_REDACTED***' },
  // Storage account keys
  { pattern: /(AccountKey=[A-Za-z0-9+/=]{88})/g, replacement: 'AccountKey=***STORAGE_KEY_REDACTED***' },
];

/**
 * Sensitive field names to redact
 */
const SENSITIVE_FIELDS = new Set([
  'password',
  'secret',
  'token',
  'clientSecret',
  'clientId',
  'tenantId',
  'subscriptionId',
  'authToken',
  'apiKey',
  'privateKey',
  'credential',
  'accountKey',
  'sasToken',
  'connectionString',
]);

class Logger {
  private minLevel: LogLevel;
  private logs: LogEntry[] = [];
  private maxLogs: number = 1000;
  private enableConsole: boolean;

  constructor(minLevel: LogLevel = LogLevel.INFO, enableConsole: boolean = true) {
    this.minLevel = minLevel;
    this.enableConsole = enableConsole;
  }

  /**
   * Redact PII from log data
   */
  private redactPII(data: any): any {
    if (typeof data === 'string') {
      let redacted = data;
      for (const { pattern, replacement } of PII_PATTERNS) {
        redacted = redacted.replace(pattern, replacement);
      }
      return redacted;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.redactPII(item));
    }

    if (data && typeof data === 'object') {
      const redacted: Record<string, any> = {};
      for (const [key, value] of Object.entries(data)) {
        // Redact sensitive fields completely
        if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
          redacted[key] = '***REDACTED***';
        } else {
          redacted[key] = this.redactPII(value);
        }
      }
      return redacted;
    }

    return data;
  }

  /**
   * Check if log level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR, LogLevel.SECURITY];
    const minIndex = levels.indexOf(this.minLevel);
    const currentIndex = levels.indexOf(level);
    return currentIndex >= minIndex;
  }

  /**
   * Log a message
   */
  private log(
    level: LogLevel,
    message: string,
    data?: Record<string, any>,
    tool?: string,
    duration?: number,
    requestId?: string
  ): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message: this.redactPII(message),
      data: data ? this.redactPII(data) : undefined,
      tool,
      duration,
      requestId,
    };

    // Store in memory
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift(); // Remove oldest
    }

    // Output to console (stderr to not interfere with MCP protocol)
    if (this.enableConsole) {
      const prefix = `[${entry.timestamp}] [${level}]${tool ? ` [${tool}]` : ''}`;
      const logMessage = `${prefix} ${message}`;
      
      if (process.env.NODE_ENV !== 'production') {
        console.error(logMessage);
        if (data) {
          console.error(JSON.stringify(entry.data, null, 2));
        }
      }
    }
  }

  debug(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.DEBUG, message, data, tool);
  }

  info(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.INFO, message, data, tool);
  }

  warn(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.WARN, message, data, tool);
  }

  error(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.ERROR, message, data, tool);
  }

  security(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.SECURITY, message, data, tool);
  }

  /**
   * Get recent logs
   */
  getLogs(level?: LogLevel, limit?: number): LogEntry[] {
    let filtered = level 
      ? this.logs.filter(log => log.level === level)
      : this.logs;

    if (limit) {
      filtered = filtered.slice(-limit);
    }

    return filtered;
  }

  /**
   * Clear logs
   */
  clearLogs(): void {
    this.logs = [];
  }

  /**
   * Set minimum log level
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }
}

/**
 * Performance tracker for operations
 */
class PerformanceTracker {
  private metrics: Map<string, PerformanceMetrics> = new Map();
  private maxMetrics: number = 500;

  /**
   * Start tracking an operation
   */
  start(toolName: string, requestId?: string): string {
    const id = requestId || `${toolName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    this.metrics.set(id, {
      toolName,
      startTime: Date.now(),
      success: false,
      apiCalls: 0,
      cacheHits: 0,
      cacheMisses: 0,
    });

    // Cleanup old metrics
    if (this.metrics.size > this.maxMetrics) {
      const oldestKey = this.metrics.keys().next().value;
      if (oldestKey) {
        this.metrics.delete(oldestKey);
      }
    }

    return id;
  }

  /**
   * End tracking an operation
   */
  end(
    id: string,
    success: boolean = true,
    errorCode?: string
  ): PerformanceMetrics | null {
    const metric = this.metrics.get(id);
    if (!metric) return null;

    metric.endTime = Date.now();
    metric.duration = metric.endTime - metric.startTime;
    metric.success = success;
    metric.errorCode = errorCode;

    logger.info(
      `Performance: ${metric.toolName} completed in ${metric.duration}ms`,
      {
        duration: metric.duration,
        success,
        apiCalls: metric.apiCalls,
        cacheHits: metric.cacheHits,
        cacheMisses: metric.cacheMisses,
      },
      metric.toolName
    );

    return metric;
  }

  /**
   * Record API call
   */
  recordAPICall(id: string): void {
    const metric = this.metrics.get(id);
    if (metric) {
      metric.apiCalls = (metric.apiCalls || 0) + 1;
    }
  }

  /**
   * Record cache hit
   */
  recordCacheHit(id: string): void {
    const metric = this.metrics.get(id);
    if (metric) {
      metric.cacheHits = (metric.cacheHits || 0) + 1;
    }
  }

  /**
   * Record cache miss
   */
  recordCacheMiss(id: string): void {
    const metric = this.metrics.get(id);
    if (metric) {
      metric.cacheMisses = (metric.cacheMisses || 0) + 1;
    }
  }

  /**
   * Get performance summary
   */
  getSummary(): {
    totalOperations: number;
    successRate: number;
    averageDuration: number;
    totalAPIcalls: number;
    cacheHitRate: number;
  } {
    const allMetrics = Array.from(this.metrics.values()).filter(m => m.duration !== undefined);

    if (allMetrics.length === 0) {
      return {
        totalOperations: 0,
        successRate: 0,
        averageDuration: 0,
        totalAPIcalls: 0,
        cacheHitRate: 0,
      };
    }

    const successful = allMetrics.filter(m => m.success).length;
    const totalDuration = allMetrics.reduce((sum, m) => sum + (m.duration || 0), 0);
    const totalAPIcalls = allMetrics.reduce((sum, m) => sum + (m.apiCalls || 0), 0);
    const totalCacheHits = allMetrics.reduce((sum, m) => sum + (m.cacheHits || 0), 0);
    const totalCacheMisses = allMetrics.reduce((sum, m) => sum + (m.cacheMisses || 0), 0);
    const totalCacheAccess = totalCacheHits + totalCacheMisses;

    return {
      totalOperations: allMetrics.length,
      successRate: (successful / allMetrics.length) * 100,
      averageDuration: totalDuration / allMetrics.length,
      totalAPIcalls,
      cacheHitRate: totalCacheAccess > 0 ? (totalCacheHits / totalCacheAccess) * 100 : 0,
    };
  }

  /**
   * Get metrics for specific tool
   */
  getToolMetrics(toolName: string): PerformanceMetrics[] {
    return Array.from(this.metrics.values())
      .filter(m => m.toolName === toolName && m.duration !== undefined);
  }

  /**
   * Clear old metrics
   */
  clearMetrics(): void {
    this.metrics.clear();
  }
}

// Singleton instances
export const logger = new Logger(
  process.env.LOG_LEVEL ? (process.env.LOG_LEVEL as LogLevel) : LogLevel.INFO,
  process.env.ENABLE_CONSOLE_LOGGING !== 'false'
);

export const performanceTracker = new PerformanceTracker();

/**
 * Decorator for automatic performance tracking
 */
export function trackPerformance(toolName?: string) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    const name = toolName || propertyKey;

    descriptor.value = async function (...args: any[]) {
      const trackingId = performanceTracker.start(name);
      try {
        const result = await originalMethod.apply(this, args);
        performanceTracker.end(trackingId, true);
        return result;
      } catch (error) {
        performanceTracker.end(trackingId, false, error instanceof Error ? error.name : 'UnknownError');
        throw error;
      }
    };

    return descriptor;
  };
}
