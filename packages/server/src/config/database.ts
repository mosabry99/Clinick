/**
 * Database Configuration
 * 
 * This module provides comprehensive database configuration and management including:
 * - Prisma client initialization and configuration
 * - Multi-tenant database connection management
 * - Connection pooling and optimization
 * - Health checks and monitoring
 * - Migration management
 * - Backup and restoration
 * - Database seeding
 * - Error handling with retry logic
 * - Performance monitoring
 * - Connection lifecycle management
 */

import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { setTimeout } from 'timers/promises';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger';
import { performance } from 'perf_hooks';
import pg from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { promisify } from 'util';
import { createGzip } from 'zlib';
import { pipeline } from 'stream';
import { createReadStream, createWriteStream } from 'fs';

// Logger for database operations
const logger = createLogger('database');

// Get the directory name for migrations and seeds
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MIGRATIONS_DIR = path.join(__dirname, '../../../prisma/migrations');
const SEEDS_DIR = path.join(__dirname, '../../../prisma/seeds');
const BACKUP_DIR = path.join(__dirname, '../../../backups');

// Ensure backup directory exists
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// Database configuration interface
interface DatabaseConfig {
  url: string;
  poolSize?: number;
  connectionTimeout?: number;
  idleTimeout?: number;
  maxRetries?: number;
  retryDelay?: number;
  logQueries?: boolean;
  logSlowQueries?: boolean;
  slowQueryThreshold?: number; // in milliseconds
  enableQueryCache?: boolean;
  queryCacheSize?: number;
  enableMetrics?: boolean;
  enableSoftDelete?: boolean;
}

// Tenant database configuration
interface TenantDatabaseConfig extends DatabaseConfig {
  tenantId: string;
  name: string;
  schema?: string;
}

// Connection pool statistics
interface ConnectionPoolStats {
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  waitingClients: number;
  maxConnections: number;
}

// Query performance metrics
interface QueryMetrics {
  queryId: string;
  model: string;
  operation: string;
  duration: number;
  timestamp: Date;
  query?: string;
  params?: any;
}

// Database health status
interface DatabaseHealth {
  isConnected: boolean;
  responseTime: number;
  version: string;
  uptime: number;
  connectionPoolStats: ConnectionPoolStats;
  lastError?: {
    message: string;
    timestamp: Date;
  };
}

// Migration info
interface MigrationInfo {
  id: string;
  name: string;
  appliedAt: Date;
  status: 'pending' | 'applied' | 'failed';
}

// Default database configuration
const DEFAULT_CONFIG: DatabaseConfig = {
  url: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/clinick',
  poolSize: parseInt(process.env.DATABASE_POOL_SIZE || '10', 10),
  connectionTimeout: parseInt(process.env.DATABASE_CONNECTION_TIMEOUT || '30000', 10),
  idleTimeout: parseInt(process.env.DATABASE_IDLE_TIMEOUT || '60000', 10),
  maxRetries: parseInt(process.env.DATABASE_MAX_RETRIES || '3', 10),
  retryDelay: parseInt(process.env.DATABASE_RETRY_DELAY || '1000', 10),
  logQueries: process.env.DATABASE_LOG_QUERIES === 'true',
  logSlowQueries: process.env.DATABASE_LOG_SLOW_QUERIES === 'true',
  slowQueryThreshold: parseInt(process.env.DATABASE_SLOW_QUERY_THRESHOLD || '1000', 10),
  enableQueryCache: process.env.DATABASE_ENABLE_QUERY_CACHE === 'true',
  queryCacheSize: parseInt(process.env.DATABASE_QUERY_CACHE_SIZE || '100', 10),
  enableMetrics: process.env.DATABASE_ENABLE_METRICS === 'true',
  enableSoftDelete: process.env.DATABASE_ENABLE_SOFT_DELETE === 'true',
};

/**
 * Database Manager
 * 
 * Manages database connections, Prisma clients, and provides utilities for
 * database operations, migrations, backups, and monitoring.
 */
class DatabaseManager extends EventEmitter {
  private config: DatabaseConfig;
  private mainClient: PrismaClient;
  private tenantClients: Map<string, PrismaClient> = new Map();
  private tenantConfigs: Map<string, TenantDatabaseConfig> = new Map();
  private queryMetrics: QueryMetrics[] = [];
  private queryCache: Map<string, { data: any; timestamp: number }> = new Map();
  private pgPools: Map<string, pg.Pool> = new Map();
  private isShutdown: boolean = false;
  private connectionAttempts: Map<string, number> = new Map();
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsInterval: NodeJS.Timeout | null = null;

  constructor(config: Partial<DatabaseConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    
    // Initialize main Prisma client with middleware for monitoring
    this.mainClient = this.createPrismaClient(this.config.url);
    
    // Initialize PG pool for the main database for lower-level operations
    this.initializePgPool('main', this.config.url);
    
    // Start health check if enabled
    this.startHealthCheck();
    
    // Start metrics collection if enabled
    if (this.config.enableMetrics) {
      this.startMetricsCollection();
    }
    
    // Handle process termination
    process.on('SIGINT', this.shutdown.bind(this));
    process.on('SIGTERM', this.shutdown.bind(this));
    
    logger.info('Database manager initialized');
  }

  /**
   * Create a Prisma client with middleware for monitoring and error handling
   */
  private createPrismaClient(url: string, options: any = {}): PrismaClient {
    const prisma = new PrismaClient({
      datasources: {
        db: {
          url,
        },
      },
      log: [
        { level: 'query', emit: 'event' },
        { level: 'error', emit: 'event' },
        { level: 'info', emit: 'event' },
        { level: 'warn', emit: 'event' },
      ],
      ...options,
    });

    // Add middleware for query monitoring
    if (this.config.logQueries || this.config.logSlowQueries || this.config.enableMetrics) {
      prisma.$use(async (params, next) => {
        const start = performance.now();
        
        // Generate a query ID for tracking
        const queryId = uuidv4();
        
        try {
          // Check cache if enabled
          if (this.config.enableQueryCache && ['findUnique', 'findFirst', 'findMany'].includes(params.action)) {
            const cacheKey = this.generateCacheKey(params);
            const cached = this.queryCache.get(cacheKey);
            
            if (cached && (Date.now() - cached.timestamp < 30000)) { // 30 second cache TTL
              logger.debug(`Cache hit for query: ${params.model}.${params.action}`);
              return cached.data;
            }
            
            const result = await next(params);
            
            // Store in cache
            if (result) {
              this.queryCache.set(cacheKey, {
                data: result,
                timestamp: Date.now(),
              });
              
              // Trim cache if it gets too large
              if (this.queryCache.size > this.config.queryCacheSize!) {
                const oldestKey = [...this.queryCache.entries()]
                  .sort((a, b) => a[1].timestamp - b[1].timestamp)[0][0];
                this.queryCache.delete(oldestKey);
              }
            }
            
            return result;
          }
          
          // Execute query
          const result = await next(params);
          
          // Calculate duration
          const duration = performance.now() - start;
          
          // Log slow queries
          if (this.config.logSlowQueries && duration > this.config.slowQueryThreshold!) {
            logger.warn(`Slow query detected: ${params.model}.${params.action} took ${duration.toFixed(2)}ms`, {
              model: params.model,
              action: params.action,
              args: params.args,
              duration,
            });
          } else if (this.config.logQueries) {
            logger.debug(`Query: ${params.model}.${params.action} took ${duration.toFixed(2)}ms`);
          }
          
          // Store metrics
          if (this.config.enableMetrics) {
            this.queryMetrics.push({
              queryId,
              model: params.model || 'unknown',
              operation: params.action,
              duration,
              timestamp: new Date(),
              query: JSON.stringify(params),
              params: params.args,
            });
            
            // Trim metrics array if it gets too large
            if (this.queryMetrics.length > 1000) {
              this.queryMetrics = this.queryMetrics.slice(-1000);
            }
          }
          
          return result;
        } catch (error: any) {
          // Log the error
          logger.error(`Database error in ${params.model}.${params.action}:`, error);
          
          // Emit error event
          this.emit('error', {
            queryId,
            model: params.model,
            action: params.action,
            error,
            params: params.args,
          });
          
          throw error;
        }
      });
    }

    // Log events
    prisma.$on('query', (e: any) => {
      if (this.config.logQueries) {
        logger.debug(`Query: ${e.query} (${e.duration}ms)`);
      }
    });

    prisma.$on('error', (e: any) => {
      logger.error('Prisma client error:', e);
      this.emit('error', e);
    });

    return prisma;
  }

  /**
   * Initialize a PostgreSQL connection pool for lower-level operations
   */
  private initializePgPool(key: string, url: string): pg.Pool {
    const pool = new pg.Pool({
      connectionString: url,
      max: this.config.poolSize,
      idleTimeoutMillis: this.config.idleTimeout,
      connectionTimeoutMillis: this.config.connectionTimeout,
    });

    // Set up event listeners
    pool.on('connect', (client) => {
      logger.debug(`New database connection established for ${key}`);
      this.emit('connection', { key });
    });

    pool.on('error', (err) => {
      logger.error(`Unexpected error on idle client for ${key}:`, err);
      this.emit('poolError', { key, error: err });
    });

    pool.on('acquire', () => {
      logger.debug(`Client acquired from ${key} pool`);
    });

    pool.on('remove', () => {
      logger.debug(`Client removed from ${key} pool`);
    });

    this.pgPools.set(key, pool);
    return pool;
  }

  /**
   * Generate a cache key for a query
   */
  private generateCacheKey(params: any): string {
    return `${params.model}:${params.action}:${JSON.stringify(params.args)}`;
  }

  /**
   * Start periodic health checks
   */
  private startHealthCheck(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    this.healthCheckInterval = setInterval(async () => {
      try {
        const health = await this.checkHealth();
        this.emit('healthCheck', health);
        
        if (!health.isConnected) {
          logger.warn('Database health check failed, connection lost');
        }
      } catch (error) {
        logger.error('Error during health check:', error);
      }
    }, 30000); // Check every 30 seconds
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    this.metricsInterval = setInterval(() => {
      const metrics = this.getMetrics();
      this.emit('metrics', metrics);
      
      // Log some basic metrics
      logger.info(`Database metrics: ${metrics.totalQueries} queries, avg: ${metrics.averageQueryTime.toFixed(2)}ms`);
    }, 60000); // Collect every minute
  }

  /**
   * Get the main Prisma client
   */
  getClient(): PrismaClient {
    return this.mainClient;
  }

  /**
   * Get a tenant-specific Prisma client
   */
  async getTenantClient(tenantId: string): Promise<PrismaClient> {
    // Check if client already exists
    if (this.tenantClients.has(tenantId)) {
      return this.tenantClients.get(tenantId)!;
    }

    // Get tenant database configuration
    const tenantConfig = await this.getTenantConfig(tenantId);
    if (!tenantConfig) {
      throw new Error(`No database configuration found for tenant: ${tenantId}`);
    }

    // Create new client
    try {
      const client = this.createPrismaClient(tenantConfig.url, {
        // Add tenant-specific options here
      });
      
      // Test the connection
      await this.testConnection(client);
      
      // Store the client
      this.tenantClients.set(tenantId, client);
      
      // Initialize PG pool for this tenant
      this.initializePgPool(tenantId, tenantConfig.url);
      
      logger.info(`Created database client for tenant: ${tenantId}`);
      
      return client;
    } catch (error) {
      logger.error(`Failed to create database client for tenant: ${tenantId}`, error);
      throw new Error(`Failed to connect to database for tenant: ${tenantId}`);
    }
  }

  /**
   * Get tenant database configuration
   */
  private async getTenantConfig(tenantId: string): Promise<TenantDatabaseConfig | null> {
    // Check cache first
    if (this.tenantConfigs.has(tenantId)) {
      return this.tenantConfigs.get(tenantId)!;
    }

    try {
      // Fetch tenant info from database
      const tenant = await this.mainClient.tenant.findUnique({
        where: { id: tenantId },
        select: {
          id: true,
          name: true,
          databaseUrl: true,
          databaseSchema: true,
        },
      });

      if (!tenant) {
        logger.error(`Tenant not found: ${tenantId}`);
        return null;
      }

      // Use tenant-specific database URL if available, otherwise use schema-based multitenancy
      const url = tenant.databaseUrl || this.config.url;
      const schema = tenant.databaseSchema || `tenant_${tenantId}`;

      const tenantConfig: TenantDatabaseConfig = {
        tenantId,
        name: tenant.name,
        url: tenant.databaseUrl || this.config.url,
        schema: tenant.databaseSchema || `tenant_${tenantId}`,
        // Inherit other settings from main config
        poolSize: this.config.poolSize,
        connectionTimeout: this.config.connectionTimeout,
        idleTimeout: this.config.idleTimeout,
        maxRetries: this.config.maxRetries,
        retryDelay: this.config.retryDelay,
        logQueries: this.config.logQueries,
        logSlowQueries: this.config.logSlowQueries,
        slowQueryThreshold: this.config.slowQueryThreshold,
        enableQueryCache: this.config.enableQueryCache,
        queryCacheSize: this.config.queryCacheSize,
        enableMetrics: this.config.enableMetrics,
      };

      // Cache the config
      this.tenantConfigs.set(tenantId, tenantConfig);

      return tenantConfig;
    } catch (error) {
      logger.error(`Error fetching tenant database configuration: ${tenantId}`, error);
      return null;
    }
  }

  /**
   * Test a database connection
   */
  private async testConnection(client: PrismaClient): Promise<boolean> {
    try {
      // Simple query to test connection
      await client.$queryRaw`SELECT 1 as result`;
      return true;
    } catch (error) {
      logger.error('Connection test failed:', error);
      return false;
    }
  }

  /**
   * Execute a function with retry logic
   */
  async withRetry<T>(fn: () => Promise<T>, options: { maxRetries?: number; retryDelay?: number } = {}): Promise<T> {
    const maxRetries = options.maxRetries || this.config.maxRetries || 3;
    const retryDelay = options.retryDelay || this.config.retryDelay || 1000;
    
    let lastError: any;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error: any) {
        lastError = error;
        
        // Check if error is retryable
        if (this.isRetryableError(error)) {
          logger.warn(`Database operation failed, retrying (${attempt}/${maxRetries}):`, error);
          
          if (attempt < maxRetries) {
            // Wait before retrying
            await setTimeout(retryDelay * attempt);
            continue;
          }
        } else {
          // Non-retryable error, break immediately
          logger.error('Non-retryable database error:', error);
          break;
        }
      }
    }
    
    // If we get here, all retries failed
    logger.error(`Database operation failed after ${maxRetries} attempts:`, lastError);
    throw lastError;
  }

  /**
   * Check if an error is retryable
   */
  private isRetryableError(error: any): boolean {
    // Common retryable errors:
    // - Connection errors
    // - Deadlocks
    // - Serialization failures
    // - Temporary server errors
    
    const retryableCodes = [
      '40001', // serialization_failure
      '40P01', // deadlock_detected
      '57P01', // admin_shutdown
      '57P02', // crash_shutdown
      '57P03', // cannot_connect_now
      '08000', // connection_exception
      '08003', // connection_does_not_exist
      '08006', // connection_failure
      '08001', // sqlclient_unable_to_establish_sqlconnection
      '08004', // sqlserver_rejected_establishment_of_sqlconnection
      '53300', // too_many_connections
    ];
    
    // Check PostgreSQL error code
    if (error.code && retryableCodes.includes(error.code)) {
      return true;
    }
    
    // Check error message patterns
    const retryablePatterns = [
      /connection.*?lost/i,
      /timeout/i,
      /deadlock/i,
      /serialization/i,
      /throttl/i,
      /too many connections/i,
      /temporarily unavailable/i,
      /shutdown in progress/i,
      /server closed/i,
    ];
    
    if (error.message && retryablePatterns.some(pattern => pattern.test(error.message))) {
      return true;
    }
    
    return false;
  }

  /**
   * Check database health
   */
  async checkHealth(): Promise<DatabaseHealth> {
    try {
      const startTime = performance.now();
      
      // Test connection with a simple query
      const result = await this.withRetry(async () => {
        return await this.mainClient.$queryRaw`SELECT version(), pg_postmaster_start_time() as start_time`;
      });
      
      const responseTime = performance.now() - startTime;
      
      // Get connection pool stats
      const poolStats = await this.getConnectionPoolStats('main');
      
      // Calculate uptime
      const row = result as any;
      const startTime1 = row[0]?.start_time;
      const uptime = startTime1 
        ? Math.floor((new Date().getTime() - new Date(startTime1).getTime()) / 1000) 
        : 0;
      
      return {
        isConnected: true,
        responseTime,
        version: row[0]?.version || 'Unknown',
        uptime,
        connectionPoolStats: poolStats,
      };
    } catch (error: any) {
      logger.error('Health check failed:', error);
      
      return {
        isConnected: false,
        responseTime: -1,
        version: 'Unknown',
        uptime: 0,
        connectionPoolStats: {
          totalConnections: 0,
          activeConnections: 0,
          idleConnections: 0,
          waitingClients: 0,
          maxConnections: this.config.poolSize || 10,
        },
        lastError: {
          message: error.message,
          timestamp: new Date(),
        },
      };
    }
  }

  /**
   * Get connection pool statistics
   */
  private async getConnectionPoolStats(key: string = 'main'): Promise<ConnectionPoolStats> {
    const pool = this.pgPools.get(key);
    
    if (!pool) {
      return {
        totalConnections: 0,
        activeConnections: 0,
        idleConnections: 0,
        waitingClients: 0,
        maxConnections: this.config.poolSize || 10,
      };
    }
    
    return {
      totalConnections: pool.totalCount,
      activeConnections: pool.activeCount,
      idleConnections: pool.idleCount,
      waitingClients: pool.waitingCount,
      maxConnections: pool.options.max || this.config.poolSize || 10,
    };
  }

  /**
   * Get database metrics
   */
  getMetrics(): any {
    // Calculate query statistics
    const totalQueries = this.queryMetrics.length;
    let totalTime = 0;
    let slowestQuery: QueryMetrics | null = null;
    let fastestQuery: QueryMetrics | null = null;
    
    const modelStats: Record<string, { count: number; totalTime: number }> = {};
    const operationStats: Record<string, { count: number; totalTime: number }> = {};
    
    this.queryMetrics.forEach(metric => {
      totalTime += metric.duration;
      
      // Track slowest query
      if (!slowestQuery || metric.duration > slowestQuery.duration) {
        slowestQuery = metric;
      }
      
      // Track fastest query
      if (!fastestQuery || metric.duration < fastestQuery.duration) {
        fastestQuery = metric;
      }
      
      // Aggregate by model
      if (!modelStats[metric.model]) {
        modelStats[metric.model] = { count: 0, totalTime: 0 };
      }
      modelStats[metric.model].count++;
      modelStats[metric.model].totalTime += metric.duration;
      
      // Aggregate by operation
      if (!operationStats[metric.operation]) {
        operationStats[metric.operation] = { count: 0, totalTime: 0 };
      }
      operationStats[metric.operation].count++;
      operationStats[metric.operation].totalTime += metric.duration;
    });
    
    // Calculate averages
    const averageQueryTime = totalQueries > 0 ? totalTime / totalQueries : 0;
    
    // Format model stats with averages
    const formattedModelStats = Object.entries(modelStats).map(([model, stats]) => ({
      model,
      queryCount: stats.count,
      totalTime: stats.totalTime,
      averageTime: stats.count > 0 ? stats.totalTime / stats.count : 0,
      percentage: totalQueries > 0 ? (stats.count / totalQueries) * 100 : 0,
    }));
    
    // Format operation stats with averages
    const formattedOperationStats = Object.entries(operationStats).map(([operation, stats]) => ({
      operation,
      queryCount: stats.count,
      totalTime: stats.totalTime,
      averageTime: stats.count > 0 ? stats.totalTime / stats.count : 0,
      percentage: totalQueries > 0 ? (stats.count / totalQueries) * 100 : 0,
    }));
    
    // Get connection pool stats
    const poolStats = Object.fromEntries(
      [...this.pgPools.entries()].map(([key, pool]) => [
        key,
        {
          totalConnections: pool.totalCount,
          activeConnections: pool.activeCount,
          idleConnections: pool.idleCount,
          waitingClients: pool.waitingCount,
        },
      ])
    );
    
    return {
      timestamp: new Date(),
      totalQueries,
      totalQueryTime: totalTime,
      averageQueryTime,
      slowestQuery: slowestQuery ? {
        model: slowestQuery.model,
        operation: slowestQuery.operation,
        duration: slowestQuery.duration,
        timestamp: slowestQuery.timestamp,
      } : null,
      fastestQuery: fastestQuery ? {
        model: fastestQuery.model,
        operation: fastestQuery.operation,
        duration: fastestQuery.duration,
        timestamp: fastestQuery.timestamp,
      } : null,
      modelStats: formattedModelStats,
      operationStats: formattedOperationStats,
      connectionPools: poolStats,
      cacheSize: this.queryCache.size,
      cacheHitRate: 0, // Would need to track hits/misses to calculate this
    };
  }

  /**
   * Clear metrics data
   */
  clearMetrics(): void {
    this.queryMetrics = [];
    logger.info('Database metrics cleared');
  }

  /**
   * Run database migrations
   */
  async runMigrations(options: { tenantId?: string; reset?: boolean } = {}): Promise<void> {
    try {
      logger.info(`Running migrations${options.tenantId ? ` for tenant ${options.tenantId}` : ''}`);
      
      const client = options.tenantId ? await this.getTenantClient(options.tenantId) : this.mainClient;
      
      if (options.reset) {
        // Reset database (dangerous operation, use with caution)
        logger.warn(`Resetting database${options.tenantId ? ` for tenant ${options.tenantId}` : ''}`);
        await client.$executeRaw`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`;
      }
      
      // Use Prisma migrate to run migrations
      const databaseUrl = options.tenantId 
        ? this.tenantConfigs.get(options.tenantId)?.url || this.config.url
        : this.config.url;
      
      // Set environment variable for Prisma CLI
      process.env.DATABASE_URL = databaseUrl;
      
      // Run migrations using Prisma CLI
      execSync('npx prisma migrate deploy', {
        stdio: 'inherit',
        env: { ...process.env, DATABASE_URL: databaseUrl },
      });
      
      logger.info(`Migrations completed${options.tenantId ? ` for tenant ${options.tenantId}` : ''}`);
    } catch (error) {
      logger.error(`Migration failed${options.tenantId ? ` for tenant ${options.tenantId}` : ''}:`, error);
      throw error;
    }
  }

  /**
   * Get migration status
   */
  async getMigrationStatus(options: { tenantId?: string } = {}): Promise<MigrationInfo[]> {
    try {
      const client = options.tenantId ? await this.getTenantClient(options.tenantId) : this.mainClient;
      
      // Check if _prisma_migrations table exists
      const tableExists = await client.$queryRaw`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = '_prisma_migrations'
        );
      `;
      
      if (!(tableExists as any)[0].exists) {
        return [];
      }
      
      // Get applied migrations
      const appliedMigrations = await client.$queryRaw`
        SELECT id, checksum, finished_at, migration_name, logs, rolled_back_at, started_at, applied_steps_count
        FROM _prisma_migrations
        ORDER BY started_at DESC;
      `;
      
      // Read available migrations from the filesystem
      const migrationFiles = fs.existsSync(MIGRATIONS_DIR) 
        ? fs.readdirSync(MIGRATIONS_DIR)
        : [];
      
      // Map to migration info objects
      const migrations: MigrationInfo[] = [];
      
      // Add applied migrations
      for (const migration of appliedMigrations as any[]) {
        migrations.push({
          id: migration.id,
          name: migration.migration_name,
          appliedAt: migration.finished_at,
          status: migration.rolled_back_at ? 'failed' : 'applied',
        });
      }
      
      // Check for pending migrations
      for (const dir of migrationFiles) {
        const migrationPath = path.join(MIGRATIONS_DIR, dir, 'migration.sql');
        
        if (fs.existsSync(migrationPath) && !migrations.some(m => m.name === dir)) {
          migrations.push({
            id: dir.split('_')[0],
            name: dir,
            appliedAt: new Date(0), // placeholder date
            status: 'pending',
          });
        }
      }
      
      return migrations;
    } catch (error) {
      logger.error(`Failed to get migration status${options.tenantId ? ` for tenant ${options.tenantId}` : ''}:`, error);
      throw error;
    }
  }

  /**
   * Create a database backup
   */
  async createBackup(options: { tenantId?: string; includeSchema?: boolean; includeData?: boolean } = {}): Promise<string> {
    const includeSchema = options.includeSchema !== false;
    const includeData = options.includeData !== false;
    
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupName = options.tenantId 
        ? `backup_${options.tenantId}_${timestamp}`
        : `backup_main_${timestamp}`;
      
      const backupPath = path.join(BACKUP_DIR, `${backupName}.sql`);
      const compressedPath = `${backupPath}.gz`;
      
      // Get database connection info
      const dbConfig = options.tenantId 
        ? this.tenantConfigs.get(options.tenantId)
        : { url: this.config.url };
      
      if (!dbConfig) {
        throw new Error(`No database configuration found for tenant: ${options.tenantId}`);
      }
      
      // Parse connection URL to get credentials
      const url = new URL(dbConfig.url);
      const host = url.hostname;
      const port = url.port || '5432';
      const database = url.pathname.substring(1);
      const username = url.username;
      const password = url.password;
      
      // Set up environment for pg_dump
      const env = {
        ...process.env,
        PGHOST: host,
        PGPORT: port,
        PGDATABASE: database,
        PGUSER: username,
        PGPASSWORD: password,
      };
      
      // Build pg_dump command
      let command = `pg_dump --format=plain --no-owner`;
      
      if (!includeSchema) {
        command += ' --data-only';
      }
      
      if (!includeData) {
        command += ' --schema-only';
      }
      
      // Add schema if tenant uses schema-based multitenancy
      if (options.tenantId && dbConfig.schema) {
        command += ` --schema=${dbConfig.schema}`;
      }
      
      // Execute pg_dump and write to file
      logger.info(`Creating database backup: ${backupPath}`);
      execSync(`${command} > "${backupPath}"`, { env });
      
      // Compress the backup
      await this.compressFile(backupPath, compressedPath);
      
      // Remove the uncompressed file
      fs.unlinkSync(backupPath);
      
      logger.info(`Backup created successfully: ${compressedPath}`);
      
      return compressedPath;
    } catch (error) {
      logger.error(`Backup failed${options.tenantId ? ` for tenant ${options.tenantId}` : ''}:`, error);
      throw error;
    }
  }

  /**
   * Restore a database from backup
   */
  async restoreBackup(backupPath: string, options: { tenantId?: string } = {}): Promise<void> {
    try {
      logger.info(`Restoring database from backup: ${backupPath}`);
      
      // Check if the backup file exists
      if (!fs.existsSync(backupPath)) {
        throw new Error(`Backup file not found: ${backupPath}`);
      }
      
      // Decompress if it's a compressed file
      let sqlFilePath = backupPath;
      if (backupPath.endsWith('.gz')) {
        sqlFilePath = backupPath.slice(0, -3);
        await this.decompressFile(backupPath, sqlFilePath);
      }
      
      // Get database connection info
      const dbConfig = options.tenantId 
        ? this.tenantConfigs.get(options.tenantId)
        : { url: this.config.url };
      
      if (!dbConfig) {
        throw new Error(`No database configuration found for tenant: ${options.tenantId}`);
      }
      
      // Parse connection URL to get credentials
      const url = new URL(dbConfig.url);
      const host = url.hostname;
      const port = url.port || '5432';
      const database = url.pathname.substring(1);
      const username = url.username;
      const password = url.password;
      
      // Set up environment for psql
      const env = {
        ...process.env,
        PGHOST: host,
        PGPORT: port,
        PGDATABASE: database,
        PGUSER: username,
        PGPASSWORD: password,
      };
      
      // Execute psql to restore the backup
      execSync(`psql -f "${sqlFilePath}"`, { env });
      
      // Clean up decompressed file if we created it
      if (backupPath.endsWith('.gz')) {
        fs.unlinkSync(sqlFilePath);
      }
      
      logger.info(`Backup restored successfully${options.tenantId ? ` for tenant ${options.tenantId}` : ''}`);
    } catch (error) {
      logger.error(`Restore failed${options.tenantId ? ` for tenant ${options.tenantId}` : ''}:`, error);
      throw error;
    }
  }

  /**
   * Compress a file using gzip
   */
  private async compressFile(inputPath: string, outputPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const gzip = createGzip();
      const source = createReadStream(inputPath);
      const destination = createWriteStream(outputPath);
      
      pipeline(source, gzip, destination, (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  /**
   * Decompress a gzipped file
   */
  private async decompressFile(inputPath: string, outputPath: string): Promise<void> {
    const { createGunzip } = await import('zlib');
    
    return new Promise((resolve, reject) => {
      const gunzip = createGunzip();
      const source = createReadStream(inputPath);
      const destination = createWriteStream(outputPath);
      
      pipeline(source, gunzip, destination, (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  /**
   * Seed the database with initial data
   */
  async seedDatabase(options: { tenantId?: string; seedFile?: string } = {}): Promise<void> {
    try {
      const client = options.tenantId ? await this.getTenantClient(options.tenantId) : this.mainClient;
      
      // Determine seed file path
      let seedFilePath: string;
      if (options.seedFile) {
        seedFilePath = path.isAbsolute(options.seedFile) 
          ? options.seedFile 
          : path.join(SEEDS_DIR, options.seedFile);
      } else {
        seedFilePath = options.tenantId 
          ? path.join(SEEDS_DIR, `tenant_${options.tenantId}.ts`) 
          : path.join(SEEDS_DIR, 'main.ts');
        
        // Fall back to default seed if specific one doesn't exist
        if (!fs.existsSync(seedFilePath)) {
          seedFilePath = path.join(SEEDS_DIR, 'default.ts');
        }
      }
      
      // Check if seed file exists
      if (!fs.existsSync(seedFilePath)) {
        logger.warn(`Seed file not found: ${seedFilePath}`);
        return;
      }
      
      logger.info(`Seeding database${options.tenantId ? ` for tenant ${options.tenantId}` : ''} using ${seedFilePath}`);
      
      // Import and execute the seed function
      const seedModule = await import(seedFilePath);
      const seedFn = seedModule.default || seedModule.seed;
      
      if (typeof seedFn !== 'function') {
        throw new Error(`Invalid seed file: ${seedFilePath}. No seed function exported.`);
      }
      
      await seedFn(client);
      
      logger.info(`Database seeding completed${options.tenantId ? ` for tenant ${options.tenantId}` : ''}`);
    } catch (error) {
      logger.error(`Database seeding failed${options.tenantId ? ` for tenant ${options.tenantId}` : ''}:`, error);
      throw error;
    }
  }

  /**
   * Create a new tenant database
   */
  async createTenantDatabase(tenantId: string, tenantName: string, options: { createSchema?: boolean } = {}): Promise<void> {
    try {
      logger.info(`Creating database for tenant: ${tenantId} (${tenantName})`);
      
      // Check if tenant exists
      const existingTenant = await this.mainClient.tenant.findUnique({
        where: { id: tenantId },
      });
      
      if (existingTenant) {
        throw new Error(`Tenant already exists: ${tenantId}`);
      }
      
      // Determine if we're using separate databases or schemas
      const useSchema = !process.env.MULTI_TENANT_SEPARATE_DBS || process.env.MULTI_TENANT_SEPARATE_DBS === 'false';
      
      let databaseUrl: string | null = null;
      let schema: string | null = null;
      
      if (useSchema) {
        // Use schema-based multitenancy
        schema = `tenant_${tenantId}`;
        
        // Create schema in the main database
        if (options.createSchema !== false) {
          await this.mainClient.$executeRaw`CREATE SCHEMA IF NOT EXISTS ${schema}`;
          logger.info(`Created schema: ${schema}`);
        }
      } else {
        // Use database-based multitenancy
        const mainDbUrl = new URL(this.config.url);
        const tenantDbName = `${mainDbUrl.pathname.substring(1)}_${tenantId}`;
        
        // Create a new database
        const pgPool = this.pgPools.get('main');
        if (!pgPool) {
          throw new Error('Main database pool not initialized');
        }
        
        // Connect to postgres database to create new database
        const pgClient = await pgPool.connect();
        try {
          // Disconnect other clients from the database if it exists
          await pgClient.query(`
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = $1
              AND pid <> pg_backend_pid();
          `, [tenantDbName]);
          
          // Drop database if it exists
          await pgClient.query(`DROP DATABASE IF EXISTS "${tenantDbName}"`);
          
          // Create new database
          await pgClient.query(`CREATE DATABASE "${tenantDbName}"`);
          
          logger.info(`Created database: ${tenantDbName}`);
          
          // Construct new database URL
          mainDbUrl.pathname = `/${tenantDbName}`;
          databaseUrl = mainDbUrl.toString();
        } finally {
          pgClient.release();
        }
      }
      
      // Create tenant record
      await this.mainClient.tenant.create({
        data: {
          id: tenantId,
          name: tenantName,
          databaseUrl,
          databaseSchema: schema,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      });
      
      logger.info(`Tenant created: ${tenantId} (${tenantName})`);
      
      // Run migrations for the new tenant
      if (databaseUrl) {
        await this.runMigrations({ tenantId });
      }
    } catch (error) {
      logger.error(`Failed to create tenant database: ${tenantId}`, error);
      throw error;
    }
  }

  /**
   * Delete a tenant database
   */
  async deleteTenantDatabase(tenantId: string, options: { keepBackup?: boolean } = {}): Promise<void> {
    try {
      logger.warn(`Deleting database for tenant: ${tenantId}`);
      
      // Get tenant info
      const tenant = await this.mainClient.tenant.findUnique({
        where: { id: tenantId },
        select: {
          id: true,
          name: true,
          databaseUrl: true,
          databaseSchema: true,
        },
      });
      
      if (!tenant) {
        throw new Error(`Tenant not found: ${tenantId}`);
      }
      
      // Create backup if requested
      if (options.keepBackup) {
        await this.createBackup({ tenantId });
      }
      
      // Remove client from cache
      if (this.tenantClients.has(tenantId)) {
        const client = this.tenantClients.get(tenantId)!;
        await client.$disconnect();
        this.tenantClients.delete(tenantId);
      }
      
      // Remove pool from cache
      if (this.pgPools.has(tenantId)) {
        const pool = this.pgPools.get(tenantId)!;
        await pool.end();
        this.pgPools.delete(tenantId);
      }
      
      // Check if we're using schema or separate database
      if (tenant.databaseSchema) {
        // Schema-based multitenancy
        await this.mainClient.$executeRaw`DROP SCHEMA IF EXISTS ${tenant.databaseSchema} CASCADE`;
        logger.info(`Dropped schema: ${tenant.databaseSchema}`);
      } else if (tenant.databaseUrl) {
        // Database-based multitenancy
        const dbUrl = new URL(tenant.databaseUrl);
        const dbName = dbUrl.pathname.substring(1);
        
        // Connect to postgres database to drop the tenant database
        const pgPool = this.pgPools.get('main');
        if (!pgPool) {
          throw new Error('Main database pool not initialized');
        }
        
        const pgClient = await pgPool.connect();
        try {
          // Disconnect other clients from the database
          await pgClient.query(`
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = $1
              AND pid <> pg_backend_pid();
          `, [dbName]);
          
          // Drop the database
          await pgClient.query(`DROP DATABASE IF EXISTS "${dbName}"`);
          
          logger.info(`Dropped database: ${dbName}`);
        } finally {
          pgClient.release();
        }
      }
      
      // Update tenant record
      await this.mainClient.tenant.update({
        where: { id: tenantId },
        data: {
          isActive: false,
          databaseUrl: null,
          databaseSchema: null,
          deletedAt: new Date(),
        },
      });
      
      // Remove from config cache
      this.tenantConfigs.delete(tenantId);
      
      logger.info(`Tenant database deleted: ${tenantId}`);
    } catch (error) {
      logger.error(`Failed to delete tenant database: ${tenantId}`, error);
      throw error;
    }
  }

  /**
   * Execute raw SQL query
   */
  async executeRawQuery(sql: string, params: any[] = [], options: { tenantId?: string } = {}): Promise<any> {
    try {
      const client = options.tenantId ? await this.getTenantClient(options.tenantId) : this.mainClient;
      
      return await this.withRetry(async () => {
        return await client.$queryRawUnsafe(sql, ...params);
      });
    } catch (error) {
      logger.error(`Failed to execute raw query${options.tenantId ? ` for tenant ${options.tenantId}` : ''}:`, error);
      throw error;
    }
  }

  /**
   * Clean up old database backups
   */
  async cleanupOldBackups(options: { keepDays?: number; tenantId?: string } = {}): Promise<void> {
    try {
      const keepDays = options.keepDays || 30;
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - keepDays);
      
      logger.info(`Cleaning up backups older than ${keepDays} days`);
      
      // Get list of backup files
      const files = fs.readdirSync(BACKUP_DIR);
      
      // Filter backups by tenant if specified
      const tenantPattern = options.tenantId ? new RegExp(`backup_${options.tenantId}_`) : null;
      
      let deletedCount = 0;
      
      for (const file of files) {
        // Skip if not matching tenant pattern
        if (tenantPattern && !tenantPattern.test(file)) {
          continue;
        }
        
        const filePath = path.join(BACKUP_DIR, file);
        const stats = fs.statSync(filePath);
        
        // Check if file is old enough to delete
        if (stats.mtime < cutoffDate) {
          fs.unlinkSync(filePath);
          deletedCount++;
          logger.debug(`Deleted old backup: ${file}`);
        }
      }
      
      logger.info(`Cleanup completed: ${deletedCount} old backups deleted`);
    } catch (error) {
      logger.error('Failed to clean up old backups:', error);
      throw error;
    }
  }

  /**
   * Shutdown the database manager
   */
  async shutdown(): Promise<void> {
    if (this.isShutdown) {
      return;
    }
    
    logger.info('Shutting down database manager');
    this.isShutdown = true;
    
    // Clear intervals
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
      this.metricsInterval = null;
    }
    
    // Disconnect all clients
    try {
      logger.info('Disconnecting Prisma clients');
      
      // Disconnect main client
      await this.mainClient.$disconnect();
      
      // Disconnect tenant clients
      for (const [tenantId, client] of this.tenantClients.entries()) {
        try {
          await client.$disconnect();
          logger.debug(`Disconnected client for tenant: ${tenantId}`);
        } catch (error) {
          logger.error(`Error disconnecting client for tenant: ${tenantId}`, error);
        }
      }
      
      // Close all PG pools
      logger.info('Closing PostgreSQL connection pools');
      for (const [key, pool] of this.pgPools.entries()) {
        try {
          await pool.end();
          logger.debug(`Closed pool: ${key}`);
        } catch (error) {
          logger.error(`Error closing pool: ${key}`, error);
        }
      }
      
      logger.info('Database manager shutdown complete');
    } catch (error) {
      logger.error('Error during database manager shutdown:', error);
    }
  }
}

// Create and export the database manager instance
const databaseManager = new DatabaseManager();

export default databaseManager;
