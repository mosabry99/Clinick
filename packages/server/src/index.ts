/**
 * Main Server Entry Point
 * 
 * This is the main entry point for the Clinick Medical Clinic Management System server.
 * It handles:
 * - Environment validation
 * - Server startup
 * - Process-level error handling
 * - Graceful shutdown
 */

import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { startServer } from './app.js';
import { createLogger } from './utils/logger.js';
import databaseManager from './config/database.js';

// Initialize logger
const logger = createLogger('server');

// Load environment variables
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(process.cwd(), '.env');

// Check if .env file exists and load it
if (fs.existsSync(envPath)) {
  logger.info(`Loading environment from ${envPath}`);
  dotenv.config({ path: envPath });
} else {
  logger.warn('No .env file found, using environment variables from the system');
  dotenv.config();
}

// Validate required environment variables
const requiredEnvVars = [
  'NODE_ENV',
  'PORT',
  'DATABASE_URL',
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  logger.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

// Log startup information
logger.info(`Starting Clinick server in ${process.env.NODE_ENV} mode`);
logger.info(`Node.js version: ${process.version}`);
logger.info(`Process ID: ${process.pid}`);

// Handle uncaught exceptions at the process level
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception:', error);
  
  // Attempt to perform cleanup
  cleanup().catch(cleanupError => {
    logger.error('Error during cleanup after uncaught exception:', cleanupError);
  }).finally(() => {
    // Exit with error
    process.exit(1);
  });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection at:', promise, 'reason:', reason);
  
  // Don't exit the process, but log the error
  // This allows the application to continue running despite the unhandled rejection
});

// Cleanup function for graceful shutdown
async function cleanup(): Promise<void> {
  logger.info('Cleaning up resources before shutdown...');
  
  try {
    // Disconnect from database
    await databaseManager.shutdown();
    logger.info('Database connections closed');
    
    // Add any other cleanup tasks here
    
    logger.info('Cleanup completed successfully');
  } catch (error) {
    logger.error('Error during cleanup:', error);
    throw error;
  }
}

// Initialize database and start server
async function initialize(): Promise<void> {
  try {
    // Check database connection
    const dbHealth = await databaseManager.checkHealth();
    
    if (!dbHealth.isConnected) {
      logger.error('Failed to connect to database:', dbHealth.lastError);
      process.exit(1);
    }
    
    logger.info('Successfully connected to database');
    
    // Run migrations if enabled
    if (process.env.AUTO_RUN_MIGRATIONS === 'true') {
      logger.info('Running database migrations...');
      await databaseManager.runMigrations();
      logger.info('Database migrations completed');
    }
    
    // Start the server
    startServer();
    
    logger.info('Server initialization completed');
  } catch (error) {
    logger.error('Failed to initialize server:', error);
    process.exit(1);
  }
}

// Start the application
initialize().catch(error => {
  logger.error('Initialization failed:', error);
  process.exit(1);
});
