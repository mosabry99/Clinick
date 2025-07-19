/**
 * Main Express Application
 * 
 * This is the main entry point for the Express application that sets up:
 * - Express app with comprehensive middleware stack
 * - Multi-tenant routing and isolation
 * - Security configurations (CORS, Helmet, Rate limiting)
 * - WebSocket support for real-time features
 * - API documentation with OpenAPI/Swagger
 * - Global error handling
 * - Graceful shutdown handling
 * - Performance monitoring
 * - Health check endpoints
 */

import express, { Request, Response, NextFunction, Application } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import { rateLimit } from 'express-rate-limit';
import slowDown from 'express-slow-down';
import multer from 'multer';
import path from 'path';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import swaggerUi from 'swagger-ui-express';
import swaggerJSDoc from 'swagger-jsdoc';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createLogger, format, transports } from 'winston';
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';
import cluster from 'cluster';
import os from 'os';
import { DateTime } from 'luxon';
import responseTime from 'response-time';
import { createGzip } from 'zlib';
import { promisify } from 'util';
import { pipeline } from 'stream';

// Import custom modules
import databaseManager from './config/database';
import authenticate, { enforceTenantIsolation } from './middleware/auth';
import { createAuditLog } from './middleware/auth';
import { createLogger as createAppLogger } from './utils/logger';

// Import routes
import authRoutes from './modules/auth/routes';
import userRoutes from './modules/users/routes';
import patientRoutes from './modules/patients/routes';
import appointmentRoutes from './modules/appointments/routes';
import billingRoutes from './modules/billing/routes';
import medicalRecordsRoutes from './modules/medical-records/routes';
import reportsRoutes from './modules/reports/routes';
import inventoryRoutes from './modules/inventory/routes';
import communicationRoutes from './modules/communication/routes';
import settingsRoutes from './modules/settings/routes';
import integrationRoutes from './modules/integrations/routes';
import analyticsRoutes from './modules/analytics/routes';

// Load environment variables
dotenv.config();

// Environment variables
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const ENABLE_CLUSTERING = process.env.ENABLE_CLUSTERING === 'true';
const ENABLE_RATE_LIMITING = process.env.ENABLE_RATE_LIMITING !== 'false';
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10); // 15 minutes
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '100', 10); // 100 requests per window
const ENABLE_COMPRESSION = process.env.ENABLE_COMPRESSION !== 'false';
const ENABLE_HTTPS_REDIRECT = process.env.ENABLE_HTTPS_REDIRECT === 'true';
const ENABLE_WEBSOCKETS = process.env.ENABLE_WEBSOCKETS !== 'false';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const TENANT_HEADER = process.env.TENANT_HEADER || 'X-Tenant-ID';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const MAX_UPLOAD_SIZE = parseInt(process.env.MAX_UPLOAD_SIZE || '10485760', 10); // 10MB
const ENABLE_API_DOCS = process.env.ENABLE_API_DOCS !== 'false';
const API_VERSION = process.env.API_VERSION || 'v1';
const ENABLE_PERFORMANCE_MONITORING = process.env.ENABLE_PERFORMANCE_MONITORING === 'true';

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create logger
const logger = createAppLogger('app');

// Create upload directory if it doesn't exist
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Create tenant-specific directory if using multi-tenancy
    const tenantId = req.headers[TENANT_HEADER.toLowerCase()] as string;
    let uploadPath = UPLOAD_DIR;
    
    if (tenantId) {
      uploadPath = path.join(UPLOAD_DIR, tenantId);
      if (!fs.existsSync(uploadPath)) {
        fs.mkdirSync(uploadPath, { recursive: true });
      }
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  }
});

const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  // Validate file types - adjust as needed for your application
  const allowedMimeTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/csv',
    'application/zip', 'application/x-zip-compressed',
    'text/plain',
    'application/json',
    'application/dicom'
  ];
  
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type not allowed. Allowed types: ${allowedMimeTypes.join(', ')}`));
  }
};

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_UPLOAD_SIZE,
  },
  fileFilter,
});

// Configure Swagger documentation
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Clinick API',
      version: API_VERSION,
      description: 'API documentation for the Clinick medical clinic management system',
      contact: {
        name: 'Support',
        email: 'support@clinick.app',
      },
    },
    servers: [
      {
        url: `http://localhost:${PORT}/api/${API_VERSION}`,
        description: 'Development server',
      },
      {
        url: `https://api.clinick.app/${API_VERSION}`,
        description: 'Production server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        apiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-API-Key',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [
    './src/modules/**/routes.ts',
    './src/modules/**/schemas.ts',
    './src/modules/**/controllers.ts',
  ],
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

/**
 * Create and configure Express application
 */
export function createApp(): { app: Application; httpServer: any } {
  // Create Express app
  const app = express();
  const httpServer = createServer(app);
  
  // Set up WebSocket server if enabled
  let io: SocketIOServer | null = null;
  if (ENABLE_WEBSOCKETS) {
    io = new SocketIOServer(httpServer, {
      cors: {
        origin: CORS_ORIGIN,
        methods: ['GET', 'POST'],
        credentials: true,
      },
    });
    
    // Set up socket authentication and event handlers
    setupWebSockets(io);
  }
  
  // Request ID middleware
  app.use((req, res, next) => {
    req.id = uuidv4();
    res.setHeader('X-Request-ID', req.id);
    next();
  });
  
  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: NODE_ENV === 'production',
    crossOriginEmbedderPolicy: NODE_ENV === 'production',
    crossOriginOpenerPolicy: NODE_ENV === 'production',
    crossOriginResourcePolicy: NODE_ENV === 'production',
  }));
  
  // CORS configuration
  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl requests)
      if (!origin) return callback(null, true);
      
      // Check against allowed origins
      if (CORS_ORIGIN === '*') {
        return callback(null, true);
      }
      
      const allowedOrigins = CORS_ORIGIN.split(',');
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      }
      
      // Check for tenant-specific domains
      // This would be expanded in a real multi-tenant application
      if (origin.endsWith('.clinick.app')) {
        return callback(null, true);
      }
      
      callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', TENANT_HEADER, 'X-API-Key', 'X-Requested-With'],
    exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  }));
  
  // Redirect to HTTPS in production
  if (NODE_ENV === 'production' && ENABLE_HTTPS_REDIRECT) {
    app.use((req, res, next) => {
      if (req.header('x-forwarded-proto') !== 'https') {
        res.redirect(`https://${req.header('host')}${req.url}`);
      } else {
        next();
      }
    });
  }
  
  // Compression middleware
  if (ENABLE_COMPRESSION) {
    app.use(compression({
      filter: (req, res) => {
        if (req.headers['x-no-compression']) {
          return false;
        }
        return compression.filter(req, res);
      },
      level: 6, // Default compression level
    }));
  }
  
  // Rate limiting middleware
  if (ENABLE_RATE_LIMITING) {
    // Apply general rate limiting
    const limiter = rateLimit({
      windowMs: RATE_LIMIT_WINDOW_MS,
      max: RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later.',
        },
      },
      keyGenerator: (req) => {
        // Use tenant ID + IP for multi-tenant rate limiting
        const tenantId = req.headers[TENANT_HEADER.toLowerCase()] as string || 'default';
        return `${tenantId}:${req.ip}`;
      },
    });
    
    // Speed limiter for brute force protection
    const speedLimiter = slowDown({
      windowMs: 15 * 60 * 1000, // 15 minutes
      delayAfter: 100, // Allow 100 requests per 15 minutes
      delayMs: (hits) => hits * 100, // Add 100ms delay per hit above threshold
      keyGenerator: (req) => {
        const tenantId = req.headers[TENANT_HEADER.toLowerCase()] as string || 'default';
        return `${tenantId}:${req.ip}`;
      },
    });
    
    // Apply rate limiting to all routes
    app.use(limiter);
    app.use(speedLimiter);
  }
  
  // Logging middleware
  if (NODE_ENV === 'production') {
    // Use combined format with request IDs for production
    app.use(morgan(':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms :req[x-request-id]', {
      stream: {
        write: (message: string) => logger.http(message.trim()),
      },
    }));
  } else {
    // Use dev format for development
    app.use(morgan('dev'));
  }
  
  // Performance monitoring
  if (ENABLE_PERFORMANCE_MONITORING) {
    app.use(responseTime((req, res, time) => {
      // Log slow responses
      if (time > 1000) {
        logger.warn(`Slow response: ${req.method} ${req.originalUrl} - ${time.toFixed(2)}ms`);
      }
      
      // Collect metrics (would integrate with monitoring tools in a real app)
      const endpoint = req.route ? req.baseUrl + req.route.path : req.originalUrl;
      const tenantId = req.headers[TENANT_HEADER.toLowerCase()] as string || 'default';
      
      // In a real app, you'd send these metrics to your monitoring system
      const metrics = {
        endpoint,
        method: req.method,
        statusCode: res.statusCode,
        responseTime: time,
        timestamp: new Date(),
        tenantId,
        requestId: req.id,
      };
      
      // For now, just log the metrics in development
      if (NODE_ENV === 'development') {
        logger.debug('Performance metrics:', metrics);
      }
    }));
  }
  
  // Body parsing middleware
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  
  // Tenant context middleware
  app.use(async (req, res, next) => {
    const tenantId = req.headers[TENANT_HEADER.toLowerCase()] as string;
    
    // Skip for authentication routes
    if (req.path.startsWith('/api/auth') && !req.path.includes('/tenant/')) {
      return next();
    }
    
    if (tenantId) {
      try {
        // Get tenant-specific Prisma client
        req.tenantPrisma = await databaseManager.getTenantClient(tenantId);
        req.tenantId = tenantId;
        
        // Add tenant info to response headers
        res.setHeader('X-Tenant-ID', tenantId);
      } catch (error) {
        logger.error(`Failed to get tenant client for ${tenantId}:`, error);
        
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_TENANT',
            message: 'Invalid tenant ID',
          },
        });
      }
    }
    
    // Always set the main Prisma client
    req.prisma = databaseManager.getClient();
    
    next();
  });
  
  // Health check endpoint
  app.get('/health', async (req, res) => {
    try {
      // Check database connection
      const dbHealth = await databaseManager.checkHealth();
      
      // Basic health check response
      const health = {
        status: 'ok',
        timestamp: new Date(),
        version: process.env.npm_package_version || '1.0.0',
        environment: NODE_ENV,
        database: {
          status: dbHealth.isConnected ? 'connected' : 'disconnected',
          responseTime: dbHealth.responseTime,
          version: dbHealth.version,
        },
        uptime: process.uptime(),
        memory: process.memoryUsage(),
      };
      
      // Return detailed health information
      res.json(health);
    } catch (error) {
      logger.error('Health check failed:', error);
      
      res.status(500).json({
        status: 'error',
        timestamp: new Date(),
        error: (error as Error).message,
      });
    }
  });
  
  // Readiness check endpoint
  app.get('/ready', async (req, res) => {
    try {
      // Check if all services are ready
      const dbHealth = await databaseManager.checkHealth();
      
      if (!dbHealth.isConnected) {
        return res.status(503).json({
          status: 'not_ready',
          reason: 'Database connection failed',
        });
      }
      
      // All services are ready
      res.json({
        status: 'ready',
        timestamp: new Date(),
      });
    } catch (error) {
      logger.error('Readiness check failed:', error);
      
      res.status(503).json({
        status: 'not_ready',
        timestamp: new Date(),
        error: (error as Error).message,
      });
    }
  });
  
  // API documentation
  if (ENABLE_API_DOCS) {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }',
    }));
    
    // Serve OpenAPI spec as JSON
    app.get('/api-docs.json', (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(swaggerSpec);
    });
  }
  
  // API routes
  const apiRouter = express.Router();
  
  // Mount API routes
  apiRouter.use('/auth', authRoutes);
  apiRouter.use('/users', authenticate(), enforceTenantIsolation(), userRoutes);
  apiRouter.use('/patients', authenticate(), enforceTenantIsolation(), patientRoutes);
  apiRouter.use('/appointments', authenticate(), enforceTenantIsolation(), appointmentRoutes);
  apiRouter.use('/billing', authenticate(), enforceTenantIsolation(), billingRoutes);
  apiRouter.use('/medical-records', authenticate(), enforceTenantIsolation(), medicalRecordsRoutes);
  apiRouter.use('/reports', authenticate(), enforceTenantIsolation(), reportsRoutes);
  apiRouter.use('/inventory', authenticate(), enforceTenantIsolation(), inventoryRoutes);
  apiRouter.use('/communication', authenticate(), enforceTenantIsolation(), communicationRoutes);
  apiRouter.use('/settings', authenticate(), enforceTenantIsolation(), settingsRoutes);
  apiRouter.use('/integrations', authenticate(), enforceTenantIsolation(), integrationRoutes);
  apiRouter.use('/analytics', authenticate(), enforceTenantIsolation(), analyticsRoutes);
  
  // Mount API router with version prefix
  app.use(`/api/${API_VERSION}`, apiRouter);
  app.use('/api', apiRouter); // Also mount without version for backward compatibility
  
  // Serve static files for production build
  if (NODE_ENV === 'production') {
    const staticPath = path.join(__dirname, '../../client/dist');
    if (fs.existsSync(staticPath)) {
      app.use(express.static(staticPath));
      
      // Serve index.html for any unmatched routes (SPA fallback)
      app.get('*', (req, res) => {
        // Skip API routes
        if (req.url.startsWith('/api/')) {
          return next();
        }
        
        res.sendFile(path.join(staticPath, 'index.html'));
      });
    }
  }
  
  // 404 handler
  app.use((req, res, next) => {
    res.status(404).json({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: `Route not found: ${req.method} ${req.originalUrl}`,
      },
    });
  });
  
  // Global error handler
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    // Log the error
    logger.error('Unhandled error:', {
      error: err.message,
      stack: err.stack,
      requestId: req.id,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
      tenant: req.headers[TENANT_HEADER.toLowerCase()],
    });
    
    // Create audit log for server errors
    if (req.auth && req.prisma) {
      createAuditLog(req.prisma, {
        userId: req.auth.sub,
        tenantId: req.auth.tenantId,
        action: 'SERVER_ERROR',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        deviceId: req.auth.deviceId,
        sessionId: req.auth.sessionId,
        status: 'failure',
        details: {
          error: err.message,
          path: req.path,
          method: req.method,
        },
      }).catch(logError => {
        logger.error('Failed to create audit log for error:', logError);
      });
    }
    
    // Handle specific error types
    if (err.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: err.details || err.message,
        },
      });
    }
    
    if (err.name === 'UnauthorizedError' || err.message.includes('invalid token')) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid or expired authentication',
        },
      });
    }
    
    if (err.name === 'ForbiddenError') {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'You do not have permission to perform this action',
        },
      });
    }
    
    if (err.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: {
          code: 'CONFLICT',
          message: 'Resource already exists',
          details: err.meta?.target || err.message,
        },
      });
    }
    
    if (err.code === 'P2025') {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'Resource not found',
          details: err.meta?.cause || err.message,
        },
      });
    }
    
    // Default error response
    const statusCode = err.statusCode || err.status || 500;
    
    // In production, don't expose internal server errors
    const errorMessage = statusCode === 500 && NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message || 'Something went wrong';
    
    res.status(statusCode).json({
      success: false,
      error: {
        code: err.code || 'SERVER_ERROR',
        message: errorMessage,
        requestId: req.id,
      },
    });
  });
  
  return { app, httpServer };
}

/**
 * Set up WebSocket server
 */
function setupWebSockets(io: SocketIOServer): void {
  // Authentication middleware for sockets
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication required'));
      }
      
      // Import auth functions
      const { verifyToken } = await import('./middleware/auth');
      
      // Verify the token
      const decoded = await verifyToken(token);
      
      // Store auth context in socket
      socket.data.auth = decoded;
      
      // Get tenant ID
      const tenantId = socket.handshake.auth.tenantId || socket.handshake.headers[TENANT_HEADER.toLowerCase()];
      
      if (tenantId) {
        // Get tenant-specific Prisma client
        socket.data.tenantPrisma = await databaseManager.getTenantClient(tenantId);
        socket.data.tenantId = tenantId;
      }
      
      // Set the main Prisma client
      socket.data.prisma = databaseManager.getClient();
      
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });
  
  // Connection handler
  io.on('connection', (socket) => {
    const auth = socket.data.auth;
    const tenantId = socket.data.tenantId;
    
    logger.info(`WebSocket connected: ${socket.id}`, {
      userId: auth?.sub,
      tenantId,
    });
    
    // Join user-specific room
    if (auth?.sub) {
      socket.join(`user:${auth.sub}`);
    }
    
    // Join tenant-specific room if applicable
    if (tenantId) {
      socket.join(`tenant:${tenantId}`);
    }
    
    // Handle disconnection
    socket.on('disconnect', () => {
      logger.info(`WebSocket disconnected: ${socket.id}`, {
        userId: auth?.sub,
        tenantId,
      });
    });
    
    // Set up event handlers
    setupSocketEventHandlers(socket);
  });
  
  // Set up namespaces
  const appointmentsNamespace = io.of('/appointments');
  const notificationsNamespace = io.of('/notifications');
  const chatNamespace = io.of('/chat');
  
  // Set up namespace-specific handlers
  setupAppointmentsNamespace(appointmentsNamespace);
  setupNotificationsNamespace(notificationsNamespace);
  setupChatNamespace(chatNamespace);
}

/**
 * Set up event handlers for individual sockets
 */
function setupSocketEventHandlers(socket: any): void {
  // General presence events
  socket.on('presence:update', (status: string) => {
    const auth = socket.data.auth;
    
    if (!auth) return;
    
    // Broadcast to relevant rooms
    socket.to(`tenant:${socket.data.tenantId}`).emit('presence:updated', {
      userId: auth.sub,
      status,
      timestamp: new Date(),
    });
  });
  
  // Handle errors
  socket.on('error', (error: any) => {
    logger.error('WebSocket error:', error);
  });
}

/**
 * Set up appointments namespace
 */
function setupAppointmentsNamespace(namespace: any): void {
  // Apply authentication middleware
  namespace.use(async (socket: any, next: any) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication required'));
      }
      
      // Import auth functions
      const { verifyToken } = await import('./middleware/auth');
      
      // Verify the token
      const decoded = await verifyToken(token);
      
      // Store auth context in socket
      socket.data.auth = decoded;
      
      // Get tenant ID
      const tenantId = socket.handshake.auth.tenantId || socket.handshake.headers[TENANT_HEADER.toLowerCase()];
      
      if (tenantId) {
        // Get tenant-specific Prisma client
        socket.data.tenantPrisma = await databaseManager.getTenantClient(tenantId);
        socket.data.tenantId = tenantId;
      }
      
      // Set the main Prisma client
      socket.data.prisma = databaseManager.getClient();
      
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });
  
  namespace.on('connection', (socket: any) => {
    const auth = socket.data.auth;
    const tenantId = socket.data.tenantId;
    const prisma = socket.data.tenantPrisma || socket.data.prisma;
    
    logger.info(`Appointments WebSocket connected: ${socket.id}`, {
      userId: auth?.sub,
      tenantId,
    });
    
    // Join rooms based on user role
    if (auth?.roles.includes('DOCTOR')) {
      socket.join(`doctor:${auth.sub}`);
    } else if (auth?.roles.includes('PATIENT')) {
      socket.join(`patient:${auth.sub}`);
    }
    
    // Handle appointment status updates
    socket.on('appointment:update', async (data: any) => {
      try {
        const { appointmentId, status, notes } = data;
        
        // Validate permissions
        const canUpdate = auth?.roles.includes('DOCTOR') || 
                          auth?.roles.includes('ADMIN') || 
                          auth?.roles.includes('RECEPTIONIST');
        
        if (!canUpdate) {
          socket.emit('error', {
            message: 'You do not have permission to update appointments',
          });
          return;
        }
        
        // Update appointment
        const appointment = await prisma.appointment.update({
          where: { id: appointmentId },
          data: {
            status,
            notes: notes ? {
              create: {
                content: notes,
                createdById: auth.sub,
              }
            } : undefined,
            updatedById: auth.sub,
          },
          include: {
            patient: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                userId: true,
              },
            },
            doctor: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                userId: true,
              },
            },
          },
        });
        
        // Broadcast to relevant users
        namespace.to(`doctor:${appointment.doctor.userId}`).emit('appointment:updated', appointment);
        namespace.to(`patient:${appointment.patient.userId}`).emit('appointment:updated', appointment);
        
        // Create audit log
        if (prisma) {
          createAuditLog(prisma, {
            userId: auth.sub,
            tenantId,
            action: 'APPOINTMENT_UPDATED',
            resourceType: 'Appointment',
            resourceId: appointmentId,
            ipAddress: socket.handshake.address,
            userAgent: socket.handshake.headers['user-agent'],
            status: 'success',
            details: {
              appointmentId,
              newStatus: status,
              hasNotes: !!notes,
            },
          }).catch(error => {
            logger.error('Failed to create audit log:', error);
          });
        }
      } catch (error) {
        logger.error('Error updating appointment:', error);
        socket.emit('error', {
          message: 'Failed to update appointment',
          details: (error as Error).message,
        });
      }
    });
    
    // Handle disconnection
    socket.on('disconnect', () => {
      logger.info(`Appointments WebSocket disconnected: ${socket.id}`, {
        userId: auth?.sub,
        tenantId,
      });
    });
  });
}

/**
 * Set up notifications namespace
 */
function setupNotificationsNamespace(namespace: any): void {
  // Apply authentication middleware (similar to appointments)
  namespace.use(async (socket: any, next: any) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication required'));
      }
      
      // Import auth functions
      const { verifyToken } = await import('./middleware/auth');
      
      // Verify the token
      const decoded = await verifyToken(token);
      
      // Store auth context in socket
      socket.data.auth = decoded;
      
      // Get tenant ID
      const tenantId = socket.handshake.auth.tenantId || socket.handshake.headers[TENANT_HEADER.toLowerCase()];
      
      if (tenantId) {
        // Get tenant-specific Prisma client
        socket.data.tenantPrisma = await databaseManager.getTenantClient(tenantId);
        socket.data.tenantId = tenantId;
      }
      
      // Set the main Prisma client
      socket.data.prisma = databaseManager.getClient();
      
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });
  
  namespace.on('connection', (socket: any) => {
    const auth = socket.data.auth;
    const tenantId = socket.data.tenantId;
    const prisma = socket.data.tenantPrisma || socket.data.prisma;
    
    logger.info(`Notifications WebSocket connected: ${socket.id}`, {
      userId: auth?.sub,
      tenantId,
    });
    
    // Join user-specific notification room
    socket.join(`notifications:${auth.sub}`);
    
    // Handle notification acknowledgment
    socket.on('notification:acknowledge', async (data: any) => {
      try {
        const { notificationId } = data;
        
        // Update notification
        await prisma.notification.update({
          where: {
            id: notificationId,
            userId: auth.sub,
          },
          data: {
            isRead: true,
            readAt: new Date(),
          },
        });
        
        // Emit acknowledgment
        socket.emit('notification:acknowledged', { notificationId });
      } catch (error) {
        logger.error('Error acknowledging notification:', error);
        socket.emit('error', {
          message: 'Failed to acknowledge notification',
          details: (error as Error).message,
        });
      }
    });
    
    // Handle disconnection
    socket.on('disconnect', () => {
      logger.info(`Notifications WebSocket disconnected: ${socket.id}`, {
        userId: auth?.sub,
        tenantId,
      });
    });
  });
}

/**
 * Set up chat namespace
 */
function setupChatNamespace(namespace: any): void {
  // Apply authentication middleware (similar to above)
  namespace.use(async (socket: any, next: any) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication required'));
      }
      
      // Import auth functions
      const { verifyToken } = await import('./middleware/auth');
      
      // Verify the token
      const decoded = await verifyToken(token);
      
      // Store auth context in socket
      socket.data.auth = decoded;
      
      // Get tenant ID
      const tenantId = socket.handshake.auth.tenantId || socket.handshake.headers[TENANT_HEADER.toLowerCase()];
      
      if (tenantId) {
        // Get tenant-specific Prisma client
        socket.data.tenantPrisma = await databaseManager.getTenantClient(tenantId);
        socket.data.tenantId = tenantId;
      }
      
      // Set the main Prisma client
      socket.data.prisma = databaseManager.getClient();
      
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });
  
  namespace.on('connection', (socket: any) => {
    const auth = socket.data.auth;
    const tenantId = socket.data.tenantId;
    const prisma = socket.data.tenantPrisma || socket.data.prisma;
    
    logger.info(`Chat WebSocket connected: ${socket.id}`, {
      userId: auth?.sub,
      tenantId,
    });
    
    // Join user-specific chat room
    socket.join(`user:${auth.sub}`);
    
    // Handle joining conversation
    socket.on('conversation:join', async (data: any) => {
      try {
        const { conversationId } = data;
        
        // Check if user is part of conversation
        const conversation = await prisma.conversation.findFirst({
          where: {
            id: conversationId,
            participants: {
              some: {
                userId: auth.sub,
              },
            },
          },
        });
        
        if (!conversation) {
          socket.emit('error', {
            message: 'You are not a participant in this conversation',
          });
          return;
        }
        
        // Join conversation room
        socket.join(`conversation:${conversationId}`);
        
        // Mark messages as read
        await prisma.message.updateMany({
          where: {
            conversationId,
            senderId: { not: auth.sub },
            readBy: {
              none: {
                userId: auth.sub,
              },
            },
          },
          data: {
            readBy: {
              create: {
                userId: auth.sub,
                readAt: new Date(),
              },
            },
          },
        });
        
        // Emit join event
        socket.to(`conversation:${conversationId}`).emit('conversation:user_joined', {
          conversationId,
          userId: auth.sub,
          timestamp: new Date(),
        });
      } catch (error) {
        logger.error('Error joining conversation:', error);
        socket.emit('error', {
          message: 'Failed to join conversation',
          details: (error as Error).message,
        });
      }
    });
    
    // Handle sending message
    socket.on('message:send', async (data: any) => {
      try {
        const { conversationId, content, attachmentIds } = data;
        
        // Check if user is part of conversation
        const conversation = await prisma.conversation.findFirst({
          where: {
            id: conversationId,
            participants: {
              some: {
                userId: auth.sub,
              },
            },
          },
          include: {
            participants: {
              select: {
                userId: true,
              },
            },
          },
        });
        
        if (!conversation) {
          socket.emit('error', {
            message: 'You are not a participant in this conversation',
          });
          return;
        }
        
        // Create message
        const message = await prisma.message.create({
          data: {
            conversationId,
            content,
            senderId: auth.sub,
            attachments: attachmentIds ? {
              connect: attachmentIds.map((id: string) => ({ id })),
            } : undefined,
            readBy: {
              create: {
                userId: auth.sub,
                readAt: new Date(),
              },
            },
          },
          include: {
            sender: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
              },
            },
            attachments: true,
          },
        });
        
        // Broadcast to conversation participants
        namespace.to(`conversation:${conversationId}`).emit('message:received', message);
        
        // Send notifications to offline users
        const participantIds = conversation.participants.map(p => p.userId).filter(id => id !== auth.sub);
        
        // In a real app, you would check which users are online and only send notifications to offline users
        for (const participantId of participantIds) {
          // Create notification
          await prisma.notification.create({
            data: {
              userId: participantId,
              type: 'NEW_MESSAGE',
              title: 'New Message',
              content: `${auth.name} sent you a message`,
              data: {
                conversationId,
                messageId: message.id,
                senderId: auth.sub,
                senderName: auth.name,
              },
              isRead: false,
            },
          });
          
          // Notify user if they're connected to the notifications namespace
          namespace.server.of('/notifications').to(`notifications:${participantId}`).emit('notification:new', {
            type: 'NEW_MESSAGE',
            title: 'New Message',
            content: `${auth.name} sent you a message`,
            data: {
              conversationId,
              messageId: message.id,
              senderId: auth.sub,
              senderName: auth.name,
            },
            timestamp: new Date(),
          });
        }
      } catch (error) {
        logger.error('Error sending message:', error);
        socket.emit('error', {
          message: 'Failed to send message',
          details: (error as Error).message,
        });
      }
    });
    
    // Handle typing indicator
    socket.on('typing:start', (data: any) => {
      const { conversationId } = data;
      
      socket.to(`conversation:${conversationId}`).emit('typing:update', {
        conversationId,
        userId: auth.sub,
        userName: auth.name,
        isTyping: true,
        timestamp: new Date(),
      });
    });
    
    socket.on('typing:stop', (data: any) => {
      const { conversationId } = data;
      
      socket.to(`conversation:${conversationId}`).emit('typing:update', {
        conversationId,
        userId: auth.sub,
        userName: auth.name,
        isTyping: false,
        timestamp: new Date(),
      });
    });
    
    // Handle disconnection
    socket.on('disconnect', () => {
      logger.info(`Chat WebSocket disconnected: ${socket.id}`, {
        userId: auth?.sub,
        tenantId,
      });
    });
  });
}

/**
 * Start the server
 */
export function startServer(): void {
  // Check if clustering is enabled
  if (ENABLE_CLUSTERING && cluster.isPrimary && NODE_ENV === 'production') {
    // Get the number of CPUs
    const numCPUs = os.cpus().length;
    
    // Fork workers
    for (let i = 0; i < numCPUs; i++) {
      cluster.fork();
    }
    
    // Handle worker events
    cluster.on('exit', (worker, code, signal) => {
      logger.warn(`Worker ${worker.process.pid} died with code ${code} and signal ${signal}`);
      // Replace the dead worker
      cluster.fork();
    });
    
    // Log master process info
    logger.info(`Master process running with PID ${process.pid}`);
  } else {
    // Create and start the server
    const { app, httpServer } = createApp();
    
    // Start listening
    httpServer.listen(PORT, HOST, () => {
      logger.info(`Server running in ${NODE_ENV} mode on http://${HOST}:${PORT}`);
      logger.info(`Health check: http://${HOST}:${PORT}/health`);
      
      if (ENABLE_API_DOCS) {
        logger.info(`API docs: http://${HOST}:${PORT}/api-docs`);
      }
    });
    
    // Handle graceful shutdown
    setupGracefulShutdown(httpServer);
  }
}

/**
 * Set up graceful shutdown
 */
function setupGracefulShutdown(server: any): void {
  // Handle termination signals
  const signals = ['SIGTERM', 'SIGINT'];
  
  for (const signal of signals) {
    process.on(signal, async () => {
      logger.info(`Received ${signal}, shutting down gracefully`);
      
      // Stop accepting new connections
      server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
          // Disconnect from database
          await databaseManager.shutdown();
          logger.info('Database connections closed');
          
          // Close any other resources
          
          // Exit process
          logger.info('Shutdown complete');
          process.exit(0);
        } catch (error) {
          logger.error('Error during shutdown:', error);
          process.exit(1);
        }
      });
      
      // Force shutdown after timeout
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    });
  }
  
  // Handle uncaught exceptions and rejections
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught exception:', error);
    
    // Exit with error
    process.exit(1);
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled rejection at:', promise, 'reason:', reason);
  });
}

// Start the server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      id: string;
      prisma: PrismaClient;
      tenantPrisma?: PrismaClient;
      tenantId?: string;
      auth?: any;
    }
  }
}

// Export default app for testing
export default createApp;
