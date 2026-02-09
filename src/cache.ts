/**
 * MCP Server Cache Infrastructure
 * Provides smart caching with TTL, LRU eviction, and request deduplication
 */

export interface CacheEntry<T> {
  value: T;
  timestamp: number;
  expiresAt: number;
  hits: number;
  size: number; // Approximate size in bytes
}

export interface CacheConfig {
  defaultTTL: number; // milliseconds
  maxEntries: number;
  maxMemoryMB: number;
  enableStats: boolean;
}

export interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  totalEntries: number;
  memoryUsageMB: number;
  hitRate: number;
}

/**
 * LRU Cache with TTL support
 * Auto-evicts least recently used entries when limits are reached
 */
export class LRUCache<T = any> {
  private cache = new Map<string, CacheEntry<T>>();
  private accessOrder = new Map<string, number>(); // key -> last access time
  private config: CacheConfig;
  private stats = {
    hits: 0,
    misses: 0,
    evictions: 0,
  };

  // In-flight request deduplication
  private pendingRequests = new Map<string, Promise<T>>();

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = {
      defaultTTL: config.defaultTTL ?? 5 * 60 * 1000, // 5 minutes
      maxEntries: config.maxEntries ?? 1000,
      maxMemoryMB: config.maxMemoryMB ?? 100,
      enableStats: config.enableStats ?? true,
    };
  }

  /**
   * Get value from cache, returns undefined if expired or missing
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);
    
    if (!entry) {
      if (this.config.enableStats) this.stats.misses++;
      return undefined;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.accessOrder.delete(key);
      if (this.config.enableStats) this.stats.misses++;
      return undefined;
    }

    // Update access order and hit count
    this.accessOrder.set(key, Date.now());
    entry.hits++;
    if (this.config.enableStats) this.stats.hits++;

    return entry.value;
  }

  /**
   * Set value in cache with optional TTL override
   */
  set(key: string, value: T, ttl?: number): void {
    const finalTTL = ttl ?? this.config.defaultTTL;
    const now = Date.now();
    
    // Estimate size (rough approximation)
    const size = this.estimateSize(value);

    const entry: CacheEntry<T> = {
      value,
      timestamp: now,
      expiresAt: now + finalTTL,
      hits: 0,
      size,
    };

    // Check if we need to evict before adding
    this.evictIfNeeded(size);

    this.cache.set(key, entry);
    this.accessOrder.set(key, now);
  }

  /**
   * Delete specific key
   */
  delete(key: string): boolean {
    this.accessOrder.delete(key);
    return this.cache.delete(key);
  }

  /**
   * Clear entire cache
   */
  clear(): void {
    this.cache.clear();
    this.accessOrder.clear();
    this.pendingRequests.clear();
  }

  /**
   * Clear expired entries
   */
  clearExpired(): number {
    const now = Date.now();
    let cleared = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        this.accessOrder.delete(key);
        cleared++;
      }
    }

    return cleared;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const totalRequests = this.stats.hits + this.stats.misses;
    const hitRate = totalRequests > 0 ? this.stats.hits / totalRequests : 0;

    let totalMemory = 0;
    for (const entry of this.cache.values()) {
      totalMemory += entry.size;
    }

    return {
      hits: this.stats.hits,
      misses: this.stats.misses,
      evictions: this.stats.evictions,
      totalEntries: this.cache.size,
      memoryUsageMB: totalMemory / (1024 * 1024),
      hitRate: parseFloat((hitRate * 100).toFixed(2)),
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
    };
  }

  /**
   * Get or fetch value with deduplication
   * If same key is being fetched, returns the same promise
   */
  async getOrFetch(
    key: string,
    fetchFn: () => Promise<T>,
    ttl?: number
  ): Promise<T> {
    // Check cache first
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached;
    }

    // Check if request is already in flight
    const pending = this.pendingRequests.get(key);
    if (pending) {
      return pending;
    }

    // Start new request
    const promise = fetchFn()
      .then((value) => {
        this.set(key, value, ttl);
        this.pendingRequests.delete(key);
        return value;
      })
      .catch((error) => {
        this.pendingRequests.delete(key);
        throw error;
      });

    this.pendingRequests.set(key, promise);
    return promise;
  }

  /**
   * Evict entries if memory or count limits exceeded
   */
  private evictIfNeeded(newEntrySize: number): void {
    // Check entry count limit
    while (this.cache.size >= this.config.maxEntries) {
      this.evictLRU();
    }

    // Check memory limit
    const currentMemory = this.calculateTotalMemory();
    const maxMemoryBytes = this.config.maxMemoryMB * 1024 * 1024;

    while (currentMemory + newEntrySize > maxMemoryBytes && this.cache.size > 0) {
      this.evictLRU();
    }
  }

  /**
   * Evict least recently used entry
   */
  private evictLRU(): void {
    let oldestKey: string | undefined;
    let oldestTime = Infinity;

    for (const [key, lastAccess] of this.accessOrder.entries()) {
      if (lastAccess < oldestTime) {
        oldestTime = lastAccess;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.accessOrder.delete(oldestKey);
      if (this.config.enableStats) this.stats.evictions++;
    }
  }

  /**
   * Calculate total memory usage
   */
  private calculateTotalMemory(): number {
    let total = 0;
    for (const entry of this.cache.values()) {
      total += entry.size;
    }
    return total;
  }

  /**
   * Estimate size of value in bytes (rough approximation)
   */
  private estimateSize(value: any): number {
    if (value === null || value === undefined) return 8;
    
    const type = typeof value;
    
    if (type === 'boolean') return 4;
    if (type === 'number') return 8;
    if (type === 'string') return value.length * 2; // UTF-16
    
    if (Array.isArray(value)) {
      return value.reduce((sum, item) => sum + this.estimateSize(item), 40); // Array overhead
    }
    
    if (type === 'object') {
      // Stringify and measure (rough but effective)
      try {
        return JSON.stringify(value).length * 2 + 40; // Object overhead
      } catch {
        return 1024; // Default for non-serializable objects
      }
    }
    
    return 64; // Default
  }

  /**
   * Get all keys in cache
   */
  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  /**
   * Check if key exists and is not expired
   */
  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Get cache size
   */
  size(): number {
    return this.cache.size;
  }
}

/**
 * Cache key generators for common patterns
 */
export class CacheKeyBuilder {
  /**
   * Generate cache key for AWS API calls
   */
  static aws(service: string, operation: string, params: Record<string, any>): string {
    const sortedParams = this.sortObject(params);
    return `aws:${service}:${operation}:${JSON.stringify(sortedParams)}`;
  }

  /**
   * Generate cache key for Azure API calls
   */
  static azure(resource: string, operation: string, params: Record<string, any>): string {
    const sortedParams = this.sortObject(params);
    return `azure:${resource}:${operation}:${JSON.stringify(sortedParams)}`;
  }

  /**
   * Generate cache key with custom prefix
   */
  static custom(prefix: string, ...parts: any[]): string {
    return `${prefix}:${parts.map(p => JSON.stringify(p)).join(':')}`;
  }

  /**
   * Sort object keys for consistent cache keys
   */
  private static sortObject(obj: Record<string, any>): Record<string, any> {
    if (obj === null || typeof obj !== 'object') return obj;
    
    const sorted: Record<string, any> = {};
    const keys = Object.keys(obj).sort();
    
    for (const key of keys) {
      const value = obj[key];
      sorted[key] = typeof value === 'object' ? this.sortObject(value) : value;
    }
    
    return sorted;
  }
}

/**
 * Default cache instance for AWS server
 */
export const awsCache = new LRUCache({
  defaultTTL: 5 * 60 * 1000, // 5 minutes
  maxEntries: 1000,
  maxMemoryMB: 100,
  enableStats: true,
});

/**
 * Cache TTL presets for different data types
 */
export const CacheTTL = {
  SHORT: 60 * 1000,           // 1 minute - frequently changing data
  MEDIUM: 5 * 60 * 1000,      // 5 minutes - default
  LONG: 30 * 60 * 1000,       // 30 minutes - static config
  VERY_LONG: 24 * 60 * 60 * 1000, // 24 hours - rarely changing
} as const;
