/**
 * Performance Optimization Utilities
 * Parallel execution, batching, connection pooling, and pagination
 */

export interface ParallelConfig {
  concurrency: number; // Max parallel operations
  continueOnError: boolean; // Continue if some fail
  timeout?: number; // Overall timeout in ms
}

export interface BatchResult<T> {
  successful: T[];
  failed: Array<{ error: Error; index: number }>;
  duration: number;
}

export interface PaginationConfig {
  pageSize: number;
  maxPages?: number;
  continueOnError: boolean;
}

/**
 * Execute promises in parallel with concurrency control
 */
export async function executeParallel<T>(
  tasks: Array<() => Promise<T>>,
  config: Partial<ParallelConfig> = {}
): Promise<BatchResult<T>> {
  const {
    concurrency = 10,
    continueOnError = true,
    timeout,
  } = config;

  const startTime = Date.now();
  const successful: T[] = [];
  const failed: Array<{ error: Error; index: number }> = [];

  // Execute with concurrency limit
  const executing: Promise<void>[] = [];
  
  for (let i = 0; i < tasks.length; i++) {
    const task = tasks[i];
    
    const promise = (async () => {
      try {
        const result = await (timeout 
          ? Promise.race([
              task(),
              new Promise<never>((_, reject) => 
                setTimeout(() => reject(new Error('Task timeout')), timeout)
              )
            ])
          : task());
        successful.push(result);
      } catch (error) {
        failed.push({ 
          error: error instanceof Error ? error : new Error(String(error)), 
          index: i 
        });
        if (!continueOnError) {
          throw error;
        }
      }
    })();

    executing.push(promise);

    // Maintain concurrency limit
    if (executing.length >= concurrency) {
      await Promise.race(executing);
      // Remove completed promises
      executing.splice(
        executing.findIndex(p => 
          Promise.race([p, Promise.resolve()]).then(() => true)
        ),
        1
      );
    }
  }

  // Wait for remaining tasks
  await Promise.allSettled(executing);

  return {
    successful,
    failed,
    duration: Date.now() - startTime,
  };
}

/**
 * Batch array into chunks and process in parallel
 */
export async function executeBatched<TInput, TOutput>(
  items: TInput[],
  batchSize: number,
  processFn: (batch: TInput[]) => Promise<TOutput[]>,
  config: Partial<ParallelConfig> = {}
): Promise<BatchResult<TOutput>> {
  const batches: TInput[][] = [];
  
  // Create batches
  for (let i = 0; i < items.length; i += batchSize) {
    batches.push(items.slice(i, i + batchSize));
  }

  // Process batches in parallel
  const tasks = batches.map(batch => () => processFn(batch));
  const batchResults = await executeParallel(tasks, config);

  // Flatten results
  const successful = batchResults.successful.flat();
  const failed = batchResults.failed;

  return {
    successful,
    failed,
    duration: batchResults.duration,
  };
}

/**
 * Retry with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: {
    maxRetries?: number;
    initialDelay?: number;
    maxDelay?: number;
    backoffFactor?: number;
    shouldRetry?: (error: Error) => boolean;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 30000,
    backoffFactor = 2,
    shouldRetry = () => true,
  } = options;

  let lastError: Error;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt === maxRetries - 1 || !shouldRetry(lastError)) {
        throw lastError;
      }

      const delay = Math.min(
        initialDelay * Math.pow(backoffFactor, attempt),
        maxDelay
      );
      
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError!;
}

/**
 * Paginate through results
 */
export async function* paginate<T>(
  fetchPage: (nextToken?: string) => Promise<{ items: T[]; nextToken?: string }>,
  config: Partial<PaginationConfig> = {}
): AsyncGenerator<T[], void, unknown> {
  const {
    pageSize = 100,
    maxPages,
    continueOnError = false,
  } = config;

  let pageCount = 0;
  let nextToken: string | undefined;

  do {
    try {
      const result = await fetchPage(nextToken);
      
      if (result.items.length > 0) {
        yield result.items;
      }

      nextToken = result.nextToken;
      pageCount++;

      if (maxPages && pageCount >= maxPages) {
        break;
      }
    } catch (error) {
      if (!continueOnError) {
        throw error;
      }
      break;
    }
  } while (nextToken);
}

/**
 * Collect all pages into single array
 */
export async function paginateAll<T>(
  fetchPage: (nextToken?: string) => Promise<{ items: T[]; nextToken?: string }>,
  config: Partial<PaginationConfig> = {}
): Promise<T[]> {
  const allItems: T[] = [];
  
  for await (const items of paginate(fetchPage, config)) {
    allItems.push(...items);
  }

  return allItems;
}

/**
 * Debounce function calls
 */
export function debounce<T extends (...args: any[]) => any>(
  fn: T,
  delay: number
): (...args: Parameters<T>) => Promise<ReturnType<T>> {
  let timeoutId: NodeJS.Timeout | null = null;
  let pendingResolve: ((value: ReturnType<T>) => void) | null = null;
  let pendingReject: ((error: Error) => void) | null = null;

  return (...args: Parameters<T>): Promise<ReturnType<T>> => {
    return new Promise((resolve, reject) => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      pendingResolve = resolve;
      pendingReject = reject;

      timeoutId = setTimeout(async () => {
        try {
          const result = await fn(...args);
          pendingResolve?.(result);
        } catch (error) {
          pendingReject?.(error instanceof Error ? error : new Error(String(error)));
        }
      }, delay);
    });
  };
}

/**
 * Throttle function calls (rate limiting)
 */
export function throttle<T extends (...args: any[]) => any>(
  fn: T,
  limit: number
): (...args: Parameters<T>) => Promise<ReturnType<T>> {
  let lastCall = 0;
  let pendingPromise: Promise<ReturnType<T>> | null = null;

  return async (...args: Parameters<T>): Promise<ReturnType<T>> => {
    const now = Date.now();
    const timeSinceLastCall = now - lastCall;

    if (timeSinceLastCall >= limit) {
      lastCall = now;
      return fn(...args);
    }

    // Wait for the delay
    if (pendingPromise) {
      await pendingPromise;
    }

    const delay = limit - timeSinceLastCall;
    pendingPromise = new Promise(resolve => setTimeout(resolve, delay))
      .then(() => {
        lastCall = Date.now();
        pendingPromise = null;
        return fn(...args);
      });

    return pendingPromise;
  };
}

/**
 * Connection pool manager
 */
export class ConnectionPool<T> {
  private pool: T[] = [];
  private inUse = new Set<T>();
  private waiting: Array<(conn: T) => void> = [];
  
  constructor(
    private createConnection: () => Promise<T>,
    private destroyConnection: (conn: T) => Promise<void>,
    private maxSize: number = 10,
    private minSize: number = 2
  ) {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    const promises = [];
    for (let i = 0; i < this.minSize; i++) {
      promises.push(this.createConnection().then(conn => {
        this.pool.push(conn);
      }));
    }
    await Promise.all(promises);
  }

  async acquire(): Promise<T> {
    // Check for available connection
    if (this.pool.length > 0) {
      const conn = this.pool.pop()!;
      this.inUse.add(conn);
      return conn;
    }

    // Create new if under limit
    if (this.inUse.size < this.maxSize) {
      const conn = await this.createConnection();
      this.inUse.add(conn);
      return conn;
    }

    // Wait for available connection
    return new Promise<T>(resolve => {
      this.waiting.push(resolve);
    });
  }

  release(conn: T): void {
    this.inUse.delete(conn);

    // Give to waiting request
    if (this.waiting.length > 0) {
      const resolve = this.waiting.shift()!;
      this.inUse.add(conn);
      resolve(conn);
      return;
    }

    // Return to pool
    this.pool.push(conn);
  }

  async destroy(): Promise<void> {
    const allConnections = [...this.pool, ...this.inUse];
    await Promise.all(allConnections.map(conn => this.destroyConnection(conn)));
    this.pool = [];
    this.inUse.clear();
    this.waiting = [];
  }

  getStats() {
    return {
      poolSize: this.pool.length,
      inUse: this.inUse.size,
      waiting: this.waiting.length,
      total: this.pool.length + this.inUse.size,
    };
  }
}

/**
 * Measure execution time
 */
export async function measureTime<T>(
  fn: () => Promise<T>
): Promise<{ result: T; duration: number }> {
  const start = Date.now();
  const result = await fn();
  const duration = Date.now() - start;
  return { result, duration };
}

/**
 * Memoize async function with TTL
 */
export function memoizeAsync<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  options: {
    ttl?: number;
    maxSize?: number;
    keyFn?: (...args: Parameters<T>) => string;
  } = {}
): T {
  const {
    ttl = 5 * 60 * 1000, // 5 minutes
    maxSize = 100,
    keyFn = (...args) => JSON.stringify(args),
  } = options;

  const cache = new Map<string, { value: any; expiresAt: number }>();
  const pending = new Map<string, Promise<any>>();

  return (async (...args: Parameters<T>) => {
    const key = keyFn(...args);

    // Check cache
    const cached = cache.get(key);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.value;
    }

    // Check pending
    const pendingPromise = pending.get(key);
    if (pendingPromise) {
      return pendingPromise;
    }

    // Execute
    const promise = fn(...args)
      .then(value => {
        cache.set(key, {
          value,
          expiresAt: Date.now() + ttl,
        });
        pending.delete(key);

        // Evict old entries if over limit
        if (cache.size > maxSize) {
          const firstKey = cache.keys().next().value;
          if (firstKey !== undefined) {
            cache.delete(firstKey);
          }
        }

        return value;
      })
      .catch(error => {
        pending.delete(key);
        throw error;
      });

    pending.set(key, promise);
    return promise;
  }) as T;
}
