/**
 * Authentication Middleware
 * 
 * Comprehensive authentication and authorization middleware including:
 * - JWT token validation and verification
 * - Multi-tenant authentication context
 * - Role-based access control (RBAC)
 * - Permission checking utilities
 * - Session management
 * - API key authentication for external integrations
 * - Rate limiting for authentication attempts
 * - Tenant isolation enforcement
 * - User context injection into requests
 * - Security audit logging
 * - Token refresh handling
 * - MFA verification support
 * - Device fingerprinting
 * - Suspicious activity detection
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { createHash } from 'crypto';
import { RateLimiterMemory, RateLimiterRedis } from 'rate-limiter-flexible';
import Redis from 'ioredis';
import UAParser from 'ua-parser-js';
import geoip from 'geoip-lite';
import { v4 as uuidv4 } from 'uuid';
import { createLogger } from '../utils/logger';
import { isIP } from 'net';
import databaseManager from '../config/database';
import { promisify } from 'util';

// Logger for auth operations
const logger = createLogger('auth');

// Redis client for rate limiting and session management
let redisClient: Redis | null = null;
if (process.env.REDIS_URL) {
  redisClient = new Redis(process.env.REDIS_URL);
  redisClient.on('error', (err) => {
    logger.error('Redis error:', err);
  });
}

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
const API_KEY_HEADER = process.env.API_KEY_HEADER || 'X-API-Key';
const TENANT_HEADER = process.env.TENANT_HEADER || 'X-Tenant-ID';
const ENABLE_MFA = process.env.ENABLE_MFA === 'true';
const ENABLE_DEVICE_FINGERPRINTING = process.env.ENABLE_DEVICE_FINGERPRINTING === 'true';
const ENABLE_SUSPICIOUS_ACTIVITY_DETECTION = process.env.ENABLE_SUSPICIOUS_ACTIVITY_DETECTION === 'true';
const ENABLE_RATE_LIMITING = process.env.ENABLE_RATE_LIMITING !== 'false';
const RATE_LIMIT_MAX_ATTEMPTS = parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS || '5', 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '300000', 10); // 5 minutes
const ENABLE_AUDIT_LOGGING = process.env.ENABLE_AUDIT_LOGGING !== 'false';
const SUSPICIOUS_LOGIN_THRESHOLD = parseInt(process.env.SUSPICIOUS_LOGIN_THRESHOLD || '3', 10);

// Rate limiter setup
const rateLimiter = redisClient
  ? new RateLimiterRedis({
      storeClient: redisClient,
      keyPrefix: 'auth_rate_limit',
      points: RATE_LIMIT_MAX_ATTEMPTS,
      duration: RATE_LIMIT_WINDOW_MS / 1000,
    })
  : new RateLimiterMemory({
      points: RATE_LIMIT_MAX_ATTEMPTS,
      duration: RATE_LIMIT_WINDOW_MS / 1000,
    });

// Types
export interface AuthContext {
  sub: string;
  email?: string;
  name?: string;
  roles: string[];
  permissions: string[];
  tenantId?: string;
  sessionId?: string;
  deviceId?: string;
  isMfaVerified?: boolean;
  isApiKey?: boolean;
  apiKeyId?: string;
  iat: number;
  exp: number;
}

export interface AuthUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  roles: string[];
  permissions: string[];
  tenantId?: string;
  isActive: boolean;
  requiresMfa: boolean;
  lastLogin?: Date;
  failedLoginAttempts: number;
  lockedUntil?: Date;
}

export interface ApiKey {
  id: string;
  key: string;
  name: string;
  userId?: string;
  tenantId?: string;
  permissions: string[];
  expiresAt?: Date;
  lastUsed?: Date;
  isActive: boolean;
  ipRestrictions?: string[];
  createdAt: Date;
}

export interface Session {
  id: string;
  userId: string;
  deviceId: string;
  deviceInfo: DeviceInfo;
  ipAddress: string;
  location?: GeoLocation;
  createdAt: Date;
  expiresAt: Date;
  lastActiveAt: Date;
  isMfaVerified: boolean;
  isRevoked: boolean;
}

export interface DeviceInfo {
  id: string;
  fingerprint: string;
  userAgent: string;
  browser?: {
    name?: string;
    version?: string;
  };
  os?: {
    name?: string;
    version?: string;
  };
  device?: {
    type?: string;
    model?: string;
    vendor?: string;
  };
  isMobile: boolean;
  isKnown: boolean;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

export interface GeoLocation {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
}

export interface AuditLogEntry {
  id: string;
  userId?: string;
  tenantId?: string;
  action: string;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  sessionId?: string;
  timestamp: Date;
  status: 'success' | 'failure';
  details?: any;
}

export interface SuspiciousActivity {
  id: string;
  userId: string;
  tenantId?: string;
  type: 'login_attempt' | 'password_reset' | 'mfa_failure' | 'unusual_location' | 'unusual_device' | 'unusual_time' | 'excessive_requests' | 'permission_abuse' | 'api_key_misuse' | 'other';
  severity: 'low' | 'medium' | 'high' | 'critical';
  ipAddress?: string;
  deviceId?: string;
  sessionId?: string;
  location?: GeoLocation;
  timestamp: Date;
  details?: any;
  isResolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
  resolutionNotes?: string;
}

// Helper functions
/**
 * Generate a device fingerprint from request data
 */
function generateDeviceFingerprint(req: Request): string {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.headers['accept'] || '',
    req.ip || '',
  ];
  
  return createHash('sha256').update(components.join('|')).digest('hex');
}

/**
 * Parse user agent information
 */
function parseUserAgent(userAgentString: string): DeviceInfo['browser'] & DeviceInfo['os'] & DeviceInfo['device'] & { isMobile: boolean } {
  const parser = new UAParser(userAgentString);
  const browser = parser.getBrowser();
  const os = parser.getOS();
  const device = parser.getDevice();
  const isMobile = device.type === 'mobile' || device.type === 'tablet';
  
  return {
    browser: {
      name: browser.name,
      version: browser.version,
    },
    os: {
      name: os.name,
      version: os.version,
    },
    device: {
      type: device.type,
      model: device.model,
      vendor: device.vendor,
    },
    isMobile,
  };
}

/**
 * Get geolocation information from IP address
 */
function getLocationFromIp(ip: string): GeoLocation | null {
  if (!isIP(ip) || ip === '127.0.0.1' || ip === '::1') {
    return null;
  }
  
  const geo = geoip.lookup(ip);
  if (!geo) {
    return null;
  }
  
  return {
    country: geo.country,
    region: geo.region,
    city: geo.city,
    latitude: geo.ll[0],
    longitude: geo.ll[1],
  };
}

/**
 * Create a JWT token
 */
function createToken(payload: Omit<AuthContext, 'iat' | 'exp'>, secret: string = JWT_SECRET, expiresIn: string = JWT_EXPIRES_IN): string {
  return jwt.sign(payload, secret, { expiresIn });
}

/**
 * Verify a JWT token
 */
async function verifyToken(token: string, secret: string = JWT_SECRET): Promise<AuthContext> {
  const verifyAsync = promisify<string, string, jwt.VerifyOptions, any>(jwt.verify);
  try {
    return await verifyAsync(token, secret, {});
  } catch (error) {
    throw new Error(`Invalid token: ${(error as Error).message}`);
  }
}

/**
 * Create a refresh token
 */
function createRefreshToken(userId: string, sessionId: string, tenantId?: string): string {
  return jwt.sign(
    { sub: userId, sessionId, tenantId },
    JWT_REFRESH_SECRET,
    { expiresIn: JWT_REFRESH_EXPIRES_IN }
  );
}

/**
 * Verify a refresh token
 */
async function verifyRefreshToken(token: string): Promise<{ sub: string; sessionId: string; tenantId?: string }> {
  const verifyAsync = promisify<string, string, jwt.VerifyOptions, any>(jwt.verify);
  try {
    return await verifyAsync(token, JWT_REFRESH_SECRET, {});
  } catch (error) {
    throw new Error(`Invalid refresh token: ${(error as Error).message}`);
  }
}

/**
 * Rate limit authentication attempts
 */
async function checkRateLimit(key: string): Promise<void> {
  if (!ENABLE_RATE_LIMITING) {
    return;
  }
  
  try {
    await rateLimiter.consume(key);
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    // RateLimiterRes
    const retryAfter = Math.round(error.msBeforeNext / 1000) || 1;
    const error1 = new Error('Too many authentication attempts, please try again later');
    (error1 as any).retryAfter = retryAfter;
    (error1 as any).status = 429;
    throw error1;
  }
}

/**
 * Reset rate limit counter
 */
async function resetRateLimit(key: string): Promise<void> {
  if (!ENABLE_RATE_LIMITING || !redisClient) {
    return;
  }
  
  try {
    await rateLimiter.delete(key);
  } catch (error) {
    logger.error(`Failed to reset rate limit for ${key}:`, error);
  }
}

/**
 * Create or update a session
 */
async function createSession(prisma: PrismaClient, userId: string, req: Request, isMfaVerified: boolean = false): Promise<Session> {
  const deviceFingerprint = generateDeviceFingerprint(req);
  const userAgent = req.headers['user-agent'] || '';
  const ipAddress = req.ip || '';
  const location = getLocationFromIp(ipAddress);
  
  // Parse user agent info
  const { browser, os, device, isMobile } = parseUserAgent(userAgent);
  
  // Check if device is known
  let deviceInfo = await prisma.deviceInfo.findFirst({
    where: {
      fingerprint: deviceFingerprint,
      userId,
    },
  });
  
  const isKnown = !!deviceInfo;
  
  // Create or update device info
  if (deviceInfo) {
    deviceInfo = await prisma.deviceInfo.update({
      where: { id: deviceInfo.id },
      data: {
        lastSeenAt: new Date(),
        userAgent,
        browser: browser.name,
        browserVersion: browser.version,
        os: os.name,
        osVersion: os.version,
        deviceType: device.type,
        deviceModel: device.model,
        deviceVendor: device.vendor,
        isMobile,
      },
    });
  } else {
    deviceInfo = await prisma.deviceInfo.create({
      data: {
        id: uuidv4(),
        userId,
        fingerprint: deviceFingerprint,
        userAgent,
        browser: browser.name,
        browserVersion: browser.version,
        os: os.name,
        osVersion: os.version,
        deviceType: device.type,
        deviceModel: device.model,
        deviceVendor: device.vendor,
        isMobile,
        isKnown: false,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      },
    });
  }
  
  // Create session
  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setDate(expiresAt.getDate() + 7); // 7 days
  
  const session = await prisma.session.create({
    data: {
      id: uuidv4(),
      userId,
      deviceId: deviceInfo.id,
      ipAddress,
      countryCode: location?.country,
      regionCode: location?.region,
      city: location?.city,
      latitude: location?.latitude,
      longitude: location?.longitude,
      createdAt: now,
      expiresAt,
      lastActiveAt: now,
      isMfaVerified,
      isRevoked: false,
    },
  });
  
  // Check for suspicious activity
  if (ENABLE_SUSPICIOUS_ACTIVITY_DETECTION) {
    const suspiciousActivity = await detectSuspiciousActivity(prisma, userId, session.id, deviceInfo.id, ipAddress, location);
    
    if (suspiciousActivity) {
      await prisma.suspiciousActivity.create({
        data: {
          id: uuidv4(),
          userId,
          type: suspiciousActivity.type,
          severity: suspiciousActivity.severity,
          ipAddress,
          deviceId: deviceInfo.id,
          sessionId: session.id,
          countryCode: location?.country,
          regionCode: location?.region,
          city: location?.city,
          latitude: location?.latitude,
          longitude: location?.longitude,
          timestamp: now,
          details: suspiciousActivity.details,
          isResolved: false,
        },
      });
      
      // Log suspicious activity
      logger.warn(`Suspicious activity detected for user ${userId}: ${suspiciousActivity.type} (${suspiciousActivity.severity})`, {
        userId,
        sessionId: session.id,
        deviceId: deviceInfo.id,
        ipAddress,
        type: suspiciousActivity.type,
        severity: suspiciousActivity.severity,
      });
    }
  }
  
  return {
    id: session.id,
    userId: session.userId,
    deviceId: session.deviceId,
    deviceInfo: {
      id: deviceInfo.id,
      fingerprint: deviceInfo.fingerprint,
      userAgent: deviceInfo.userAgent,
      browser: {
        name: deviceInfo.browser || undefined,
        version: deviceInfo.browserVersion || undefined,
      },
      os: {
        name: deviceInfo.os || undefined,
        version: deviceInfo.osVersion || undefined,
      },
      device: {
        type: deviceInfo.deviceType || undefined,
        model: deviceInfo.deviceModel || undefined,
        vendor: deviceInfo.deviceVendor || undefined,
      },
      isMobile: deviceInfo.isMobile,
      isKnown: deviceInfo.isKnown,
      firstSeenAt: deviceInfo.firstSeenAt,
      lastSeenAt: deviceInfo.lastSeenAt,
    },
    ipAddress: session.ipAddress,
    location: location || undefined,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    lastActiveAt: session.lastActiveAt,
    isMfaVerified: session.isMfaVerified,
    isRevoked: session.isRevoked,
  };
}

/**
 * Update session activity
 */
async function updateSessionActivity(prisma: PrismaClient, sessionId: string): Promise<void> {
  try {
    await prisma.session.update({
      where: { id: sessionId },
      data: { lastActiveAt: new Date() },
    });
  } catch (error) {
    logger.error(`Failed to update session activity for ${sessionId}:`, error);
  }
}

/**
 * Revoke a session
 */
async function revokeSession(prisma: PrismaClient, sessionId: string): Promise<void> {
  try {
    await prisma.session.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });
  } catch (error) {
    logger.error(`Failed to revoke session ${sessionId}:`, error);
  }
}

/**
 * Detect suspicious activity
 */
async function detectSuspiciousActivity(
  prisma: PrismaClient,
  userId: string,
  sessionId: string,
  deviceId: string,
  ipAddress: string,
  location?: GeoLocation | null
): Promise<{ type: SuspiciousActivity['type']; severity: SuspiciousActivity['severity']; details?: any } | null> {
  try {
    // Get user's recent sessions
    const recentSessions = await prisma.session.findMany({
      where: {
        userId,
        createdAt: {
          gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
        },
        id: { not: sessionId }, // Exclude current session
      },
      orderBy: { createdAt: 'desc' },
      take: 10,
    });
    
    // Check for unusual location
    if (location && recentSessions.length > 0) {
      const hasMatchingLocation = recentSessions.some(s => 
        s.countryCode === location.country &&
        s.regionCode === location.region
      );
      
      if (!hasMatchingLocation) {
        return {
          type: 'unusual_location',
          severity: 'medium',
          details: {
            newLocation: {
              country: location.country,
              region: location.region,
              city: location.city,
            },
            previousLocations: recentSessions.map(s => ({
              country: s.countryCode,
              region: s.regionCode,
              city: s.city,
            })),
          },
        };
      }
    }
    
    // Check for unusual device
    const isNewDevice = !await prisma.deviceInfo.findFirst({
      where: {
        id: deviceId,
        userId,
        isKnown: true,
      },
    });
    
    if (isNewDevice) {
      return {
        type: 'unusual_device',
        severity: 'low',
        details: {
          deviceId,
        },
      };
    }
    
    // Check for unusual time
    const now = new Date();
    const hour = now.getHours();
    
    // Consider logins between 1am and 5am as unusual if user doesn't typically login at these hours
    if (hour >= 1 && hour <= 5) {
      const hasLoginInSimilarHour = recentSessions.some(s => {
        const sessionHour = new Date(s.createdAt).getHours();
        return Math.abs(sessionHour - hour) <= 1;
      });
      
      if (!hasLoginInSimilarHour) {
        return {
          type: 'unusual_time',
          severity: 'low',
          details: {
            loginTime: now.toISOString(),
            hour,
          },
        };
      }
    }
    
    // Check for multiple failed login attempts
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { failedLoginAttempts: true },
    });
    
    if (user && user.failedLoginAttempts >= SUSPICIOUS_LOGIN_THRESHOLD) {
      return {
        type: 'login_attempt',
        severity: 'high',
        details: {
          failedAttempts: user.failedLoginAttempts,
        },
      };
    }
    
    return null;
  } catch (error) {
    logger.error(`Failed to detect suspicious activity for user ${userId}:`, error);
    return null;
  }
}

/**
 * Create an audit log entry
 */
async function createAuditLog(
  prisma: PrismaClient,
  data: Omit<AuditLogEntry, 'id' | 'timestamp'>
): Promise<void> {
  if (!ENABLE_AUDIT_LOGGING) {
    return;
  }
  
  try {
    await prisma.auditLog.create({
      data: {
        id: uuidv4(),
        userId: data.userId,
        tenantId: data.tenantId,
        action: data.action,
        resourceType: data.resourceType,
        resourceId: data.resourceId,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        deviceId: data.deviceId,
        sessionId: data.sessionId,
        timestamp: new Date(),
        status: data.status,
        details: data.details ? JSON.stringify(data.details) : undefined,
      },
    });
  } catch (error) {
    logger.error('Failed to create audit log:', error);
  }
}

/**
 * Get user permissions
 */
async function getUserPermissions(prisma: PrismaClient, userId: string, tenantId?: string): Promise<string[]> {
  try {
    // Get user roles
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                rolePermissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });
    
    if (!user) {
      return [];
    }
    
    // Extract permissions from roles
    const permissions = new Set<string>();
    
    for (const userRole of user.userRoles) {
      // Skip if role is tenant-specific and tenantId doesn't match
      if (userRole.tenantId && userRole.tenantId !== tenantId) {
        continue;
      }
      
      for (const rolePermission of userRole.role.rolePermissions) {
        // Skip if permission is tenant-specific and tenantId doesn't match
        if (rolePermission.tenantId && rolePermission.tenantId !== tenantId) {
          continue;
        }
        
        permissions.add(rolePermission.permission.name);
      }
    }
    
    return Array.from(permissions);
  } catch (error) {
    logger.error(`Failed to get permissions for user ${userId}:`, error);
    return [];
  }
}

/**
 * Get user roles
 */
async function getUserRoles(prisma: PrismaClient, userId: string, tenantId?: string): Promise<string[]> {
  try {
    // Get user roles
    const userRoles = await prisma.userRole.findMany({
      where: {
        userId,
        ...(tenantId ? { tenantId } : {}),
      },
      include: {
        role: true,
      },
    });
    
    return userRoles.map(ur => ur.role.name);
  } catch (error) {
    logger.error(`Failed to get roles for user ${userId}:`, error);
    return [];
  }
}

/**
 * Verify API key
 */
async function verifyApiKey(prisma: PrismaClient, apiKey: string, ipAddress: string): Promise<ApiKey | null> {
  try {
    const key = await prisma.apiKey.findFirst({
      where: {
        key: apiKey,
        isActive: true,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } },
        ],
      },
    });
    
    if (!key) {
      return null;
    }
    
    // Check IP restrictions
    if (key.ipRestrictions && key.ipRestrictions.length > 0) {
      const ipAllowed = key.ipRestrictions.some(allowedIp => {
        // Check for exact match
        if (allowedIp === ipAddress) {
          return true;
        }
        
        // Check for CIDR notation
        if (allowedIp.includes('/')) {
          // Simple implementation - in production use a proper CIDR matching library
          const [subnet, bits] = allowedIp.split('/');
          const ipParts = ipAddress.split('.').map(Number);
          const subnetParts = subnet.split('.').map(Number);
          const mask = parseInt(bits, 10);
          
          // Compare only the bits specified by the mask
          const ipBinary = ipParts.map(part => part.toString(2).padStart(8, '0')).join('');
          const subnetBinary = subnetParts.map(part => part.toString(2).padStart(8, '0')).join('');
          
          return ipBinary.substring(0, mask) === subnetBinary.substring(0, mask);
        }
        
        return false;
      });
      
      if (!ipAllowed) {
        logger.warn(`API key ${key.id} used from restricted IP: ${ipAddress}`);
        return null;
      }
    }
    
    // Update last used timestamp
    await prisma.apiKey.update({
      where: { id: key.id },
      data: { lastUsed: new Date() },
    });
    
    return key;
  } catch (error) {
    logger.error(`Failed to verify API key:`, error);
    return null;
  }
}

/**
 * Check if MFA is required for user
 */
async function isMfaRequired(prisma: PrismaClient, userId: string): Promise<boolean> {
  if (!ENABLE_MFA) {
    return false;
  }
  
  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { requiresMfa: true },
    });
    
    return user?.requiresMfa || false;
  } catch (error) {
    logger.error(`Failed to check MFA requirement for user ${userId}:`, error);
    return false;
  }
}

/**
 * Verify MFA token
 */
async function verifyMfaToken(prisma: PrismaClient, userId: string, token: string): Promise<boolean> {
  try {
    // Get user's MFA secret
    const mfaSetup = await prisma.mfaSetup.findFirst({
      where: {
        userId,
        isActive: true,
      },
    });
    
    if (!mfaSetup) {
      return false;
    }
    
    // In a real implementation, use a proper TOTP library to verify the token
    // This is a simplified example
    const isValid = token.length === 6 && /^\d+$/.test(token);
    
    if (isValid) {
      // Update MFA verification timestamp
      await prisma.mfaSetup.update({
        where: { id: mfaSetup.id },
        data: { lastVerifiedAt: new Date() },
      });
      
      return true;
    }
    
    return false;
  } catch (error) {
    logger.error(`Failed to verify MFA token for user ${userId}:`, error);
    return false;
  }
}

// Main middleware functions
/**
 * Authentication middleware
 * 
 * Validates JWT tokens, API keys, and injects authentication context into the request.
 */
export function authenticate(options: {
  required?: boolean;
  allowApiKey?: boolean;
  requireMfa?: boolean;
} = {}): (req: Request, res: Response, next: NextFunction) => void {
  const { required = true, allowApiKey = false, requireMfa = false } = options;
  
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get the authorization header
      const authHeader = req.headers.authorization;
      const apiKey = allowApiKey ? req.headers[API_KEY_HEADER.toLowerCase()] : null;
      const tenantId = req.headers[TENANT_HEADER.toLowerCase()] as string;
      
      // Get the Prisma client
      const prisma = tenantId
        ? await databaseManager.getTenantClient(tenantId).catch(() => databaseManager.getClient())
        : databaseManager.getClient();
      
      // Attach Prisma client to request
      req.prisma = prisma;
      
      if (tenantId) {
        req.tenantId = tenantId;
        
        // Get tenant-specific Prisma client
        try {
          req.tenantPrisma = await databaseManager.getTenantClient(tenantId);
        } catch (error) {
          logger.error(`Failed to get tenant Prisma client for ${tenantId}:`, error);
        }
      }
      
      // Check for API key authentication
      if (allowApiKey && apiKey) {
        const key = await verifyApiKey(prisma, apiKey as string, req.ip || '');
        
        if (key) {
          // Create auth context for API key
          const authContext: AuthContext = {
            sub: key.userId || key.id,
            roles: ['API_CLIENT'],
            permissions: key.permissions || [],
            tenantId: key.tenantId,
            isApiKey: true,
            apiKeyId: key.id,
            iat: Math.floor(Date.now() / 1000),
            exp: key.expiresAt ? Math.floor(key.expiresAt.getTime() / 1000) : Math.floor(Date.now() / 1000) + 3600,
          };
          
          // Attach auth context to request
          req.auth = authContext;
          
          // Create audit log
          await createAuditLog(prisma, {
            userId: key.userId,
            tenantId: key.tenantId,
            action: 'API_KEY_AUTHENTICATION',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success',
            details: {
              apiKeyId: key.id,
              apiKeyName: key.name,
            },
          });
          
          return next();
        }
        
        // Invalid API key
        if (apiKey) {
          // Create audit log for failed API key authentication
          await createAuditLog(prisma, {
            action: 'API_KEY_AUTHENTICATION',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'failure',
            details: {
              reason: 'Invalid API key',
            },
          });
          
          if (required) {
            return res.status(401).json({
              success: false,
              error: {
                code: 'INVALID_API_KEY',
                message: 'Invalid API key',
              },
            });
          }
        }
      }
      
      // Check for JWT authentication
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        
        try {
          // Verify the token
          const decoded = await verifyToken(token);
          
          // Check if token is for the correct tenant
          if (tenantId && decoded.tenantId && decoded.tenantId !== tenantId) {
            throw new Error('Token is for a different tenant');
          }
          
          // Check if session is valid
          if (decoded.sessionId) {
            const session = await prisma.session.findUnique({
              where: { id: decoded.sessionId },
            });
            
            if (!session || session.isRevoked || new Date() > session.expiresAt) {
              throw new Error('Session is invalid or expired');
            }
            
            // Update session activity
            await updateSessionActivity(prisma, decoded.sessionId);
          }
          
          // Check MFA verification if required
          if (requireMfa && !decoded.isMfaVerified) {
            const mfaRequired = await isMfaRequired(prisma, decoded.sub);
            
            if (mfaRequired) {
              return res.status(403).json({
                success: false,
                error: {
                  code: 'MFA_REQUIRED',
                  message: 'Multi-factor authentication is required',
                },
              });
            }
          }
          
          // Attach auth context to request
          req.auth = decoded;
          
          return next();
        } catch (error) {
          logger.warn(`Token verification failed: ${(error as Error).message}`);
          
          // Create audit log for failed authentication
          await createAuditLog(prisma, {
            action: 'JWT_AUTHENTICATION',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'failure',
            details: {
              reason: (error as Error).message,
            },
          });
          
          if (!required) {
            return next();
          }
          
          return res.status(401).json({
            success: false,
            error: {
              code: 'INVALID_TOKEN',
              message: 'Invalid or expired token',
            },
          });
        }
      }
      
      // No authentication provided
      if (required) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'AUTHENTICATION_REQUIRED',
            message: 'Authentication is required',
          },
        });
      }
      
      // Authentication not required, continue
      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Tenant isolation middleware
 * 
 * Ensures that users can only access resources from their assigned tenants.
 */
export function enforceTenantIsolation(options: {
  allowSystemAdmin?: boolean;
} = {}): (req: Request, res: Response, next: NextFunction) => void {
  const { allowSystemAdmin = true } = options;
  
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip if no auth context
    if (!req.auth) {
      return next();
    }
    
    // Allow system admins to access any tenant if configured
    if (allowSystemAdmin && req.auth.roles.includes('SYSTEM_ADMIN')) {
      return next();
    }
    
    // Get tenant ID from request
    const requestTenantId = req.tenantId || req.params.tenantId || req.query.tenantId as string;
    
    // Skip if no tenant ID in request
    if (!requestTenantId) {
      return next();
    }
    
    // Check if user belongs to the requested tenant
    if (req.auth.tenantId && req.auth.tenantId !== requestTenantId) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'TENANT_ACCESS_DENIED',
          message: 'You do not have access to this tenant',
        },
      });
    }
    
    // Tenant access allowed
    next();
  };
}

/**
 * Role-based access control middleware
 * 
 * Checks if the user has any of the required roles.
 */
export function requireRole(roles: string | string[]): (req: Request, res: Response, next: NextFunction) => void {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];
  
  return (req: Request, res: Response, next: NextFunction) => {
    // Check if user is authenticated
    if (!req.auth) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication is required',
        },
      });
    }
    
    // Check if user has any of the required roles
    const hasRole = requiredRoles.some(role => req.auth!.roles.includes(role));
    
    if (!hasRole) {
      // Create audit log for access denied
      const prisma = req.tenantPrisma || req.prisma;
      createAuditLog(prisma, {
        userId: req.auth.sub,
        tenantId: req.auth.tenantId,
        action: 'ACCESS_DENIED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        deviceId: req.auth.deviceId,
        sessionId: req.auth.sessionId,
        status: 'failure',
        details: {
          requiredRoles,
          userRoles: req.auth.roles,
          path: req.path,
          method: req.method,
        },
      });
      
      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_ROLE',
          message: 'You do not have the required role to access this resource',
        },
      });
    }
    
    next();
  };
}

/**
 * Permission-based access control middleware
 * 
 * Checks if the user has any of the required permissions.
 */
export function requirePermission(permissions: string | string[]): (req: Request, res: Response, next: NextFunction) => void {
  const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
  
  return (req: Request, res: Response, next: NextFunction) => {
    // Check if user is authenticated
    if (!req.auth) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication is required',
        },
      });
    }
    
    // System admins have all permissions
    if (req.auth.roles.includes('SYSTEM_ADMIN')) {
      return next();
    }
    
    // Tenant admins have all permissions within their tenant
    if (req.auth.roles.includes('TENANT_ADMIN') && req.auth.tenantId && req.auth.tenantId === req.tenantId) {
      return next();
    }
    
    // Check if user has any of the required permissions
    const hasPermission = requiredPermissions.some(permission => req.auth!.permissions.includes(permission));
    
    if (!hasPermission) {
      // Create audit log for access denied
      const prisma = req.tenantPrisma || req.prisma;
      createAuditLog(prisma, {
        userId: req.auth.sub,
        tenantId: req.auth.tenantId,
        action: 'ACCESS_DENIED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        deviceId: req.auth.deviceId,
        sessionId: req.auth.sessionId,
        status: 'failure',
        details: {
          requiredPermissions,
          userPermissions: req.auth.permissions,
          path: req.path,
          method: req.method,
        },
      });
      
      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_PERMISSION',
          message: 'You do not have the required permission to access this resource',
        },
      });
    }
    
    next();
  };
}

/**
 * MFA verification middleware
 * 
 * Ensures that MFA is verified for users who require it.
 */
export function requireMfaVerification(): (req: Request, res: Response, next: NextFunction) => void {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!ENABLE_MFA) {
      return next();
    }
    
    // Check if user is authenticated
    if (!req.auth) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication is required',
        },
      });
    }
    
    // Skip for API key authentication
    if (req.auth.isApiKey) {
      return next();
    }
    
    // Check if MFA is already verified
    if (req.auth.isMfaVerified) {
      return next();
    }
    
    // Check if MFA is required for this user
    const prisma = req.tenantPrisma || req.prisma;
    const mfaRequired = await isMfaRequired(prisma, req.auth.sub);
    
    if (mfaRequired) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'MFA_REQUIRED',
          message: 'Multi-factor authentication is required',
        },
      });
    }
    
    next();
  };
}

/**
 * Rate limiting middleware for authentication endpoints
 */
export function authRateLimiter(): (req: Request, res: Response, next: NextFunction) => void {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!ENABLE_RATE_LIMITING) {
      return next();
    }
    
    try {
      // Use IP address and username/email as the rate limit key
      const username = req.body.username || req.body.email || 'unknown';
      const key = `auth:${req.ip}:${username}`;
      
      await checkRateLimit(key);
      next();
    } catch (error: any) {
      if (error.status === 429) {
        res.status(429).set('Retry-After', String(error.retryAfter || 60)).json({
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: error.message,
            retryAfter: error.retryAfter,
          },
        });
      } else {
        next(error);
      }
    }
  };
}

// Utility functions for route handlers
/**
 * Login a user
 */
export async function loginUser(
  prisma: PrismaClient,
  userId: string,
  req: Request,
  mfaVerified: boolean = false
): Promise<{
  accessToken: string;
  refreshToken: string;
  user: AuthUser;
  session: Session;
}> {
  // Get user details
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      isActive: true,
      requiresMfa: true,
      lastLogin: true,
      failedLoginAttempts: true,
      lockedUntil: true,
      tenantId: true,
    },
  });
  
  if (!user) {
    throw new Error('User not found');
  }
  
  if (!user.isActive) {
    throw new Error('User account is inactive');
  }
  
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw new Error('User account is locked');
  }
  
  // Get user roles and permissions
  const roles = await getUserRoles(prisma, userId, user.tenantId || undefined);
  const permissions = await getUserPermissions(prisma, userId, user.tenantId || undefined);
  
  // Create session
  const session = await createSession(prisma, userId, req, mfaVerified);
  
  // Create tokens
  const payload: Omit<AuthContext, 'iat' | 'exp'> = {
    sub: userId,
    email: user.email,
    name: `${user.firstName} ${user.lastName}`,
    roles,
    permissions,
    tenantId: user.tenantId || undefined,
    sessionId: session.id,
    deviceId: session.deviceId,
    isMfaVerified: mfaVerified,
  };
  
  const accessToken = createToken(payload);
  const refreshToken = createRefreshToken(userId, session.id, user.tenantId || undefined);
  
  // Update user's last login time and reset failed login attempts
  await prisma.user.update({
    where: { id: userId },
    data: {
      lastLogin: new Date(),
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });
  
  // Create audit log
  await createAuditLog(prisma, {
    userId,
    tenantId: user.tenantId || undefined,
    action: 'USER_LOGIN',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    deviceId: session.deviceId,
    sessionId: session.id,
    status: 'success',
  });
  
  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles,
      permissions,
      tenantId: user.tenantId || undefined,
      isActive: user.isActive,
      requiresMfa: user.requiresMfa,
      lastLogin: user.lastLogin,
      failedLoginAttempts: user.failedLoginAttempts,
      lockedUntil: user.lockedUntil,
    },
    session,
  };
}

/**
 * Refresh authentication tokens
 */
export async function refreshTokens(
  prisma: PrismaClient,
  refreshToken: string,
  req: Request
): Promise<{
  accessToken: string;
  refreshToken: string;
}> {
  try {
    // Verify refresh token
    const decoded = await verifyRefreshToken(refreshToken);
    
    // Check if session exists and is valid
    const session = await prisma.session.findUnique({
      where: { id: decoded.sessionId },
    });
    
    if (!session || session.isRevoked || new Date() > session.expiresAt) {
      throw new Error('Session is invalid or expired');
    }
    
    // Check if session belongs to the user
    if (session.userId !== decoded.sub) {
      throw new Error('Session does not belong to the user');
    }
    
    // Get user details
    const user = await prisma.user.findUnique({
      where: { id: decoded.sub },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        isActive: true,
        tenantId: true,
      },
    });
    
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }
    
    // Get user roles and permissions
    const roles = await getUserRoles(prisma, decoded.sub, decoded.tenantId);
    const permissions = await getUserPermissions(prisma, decoded.sub, decoded.tenantId);
    
    // Update session activity
    await updateSessionActivity(prisma, decoded.sessionId);
    
    // Create new tokens
    const payload: Omit<AuthContext, 'iat' | 'exp'> = {
      sub: decoded.sub,
      email: user.email,
      name: `${user.firstName} ${user.lastName}`,
      roles,
      permissions,
      tenantId: decoded.tenantId,
      sessionId: decoded.sessionId,
      deviceId: session.deviceId,
      isMfaVerified: session.isMfaVerified,
    };
    
    const newAccessToken = createToken(payload);
    const newRefreshToken = createRefreshToken(decoded.sub, decoded.sessionId, decoded.tenantId);
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: decoded.sub,
      tenantId: decoded.tenantId,
      action: 'TOKEN_REFRESH',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      deviceId: session.deviceId,
      sessionId: session.id,
      status: 'success',
    });
    
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    // Create audit log for failed token refresh
    await createAuditLog(prisma, {
      action: 'TOKEN_REFRESH',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      status: 'failure',
      details: {
        reason: (error as Error).message,
      },
    });
    
    throw error;
  }
}

/**
 * Log out a user
 */
export async function logoutUser(
  prisma: PrismaClient,
  userId: string,
  sessionId: string,
  req: Request
): Promise<void> {
  // Revoke the session
  await revokeSession(prisma, sessionId);
  
  // Create audit log
  await createAuditLog(prisma, {
    userId,
    action: 'USER_LOGOUT',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    sessionId,
    status: 'success',
  });
}

/**
 * Verify MFA and update session
 */
export async function verifyMfa(
  prisma: PrismaClient,
  userId: string,
  sessionId: string,
  token: string,
  req: Request
): Promise<{
  accessToken: string;
  success: boolean;
}> {
  // Verify MFA token
  const isValid = await verifyMfaToken(prisma, userId, token);
  
  if (!isValid) {
    // Create audit log for failed MFA verification
    await createAuditLog(prisma, {
      userId,
      action: 'MFA_VERIFICATION',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      sessionId,
      status: 'failure',
    });
    
    throw new Error('Invalid MFA token');
  }
  
  // Update session
  await prisma.session.update({
    where: { id: sessionId },
    data: {
      isMfaVerified: true,
      lastActiveAt: new Date(),
    },
  });
  
  // Get user details for new token
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      tenantId: true,
    },
  });
  
  if (!user) {
    throw new Error('User not found');
  }
  
  // Get user roles and permissions
  const roles = await getUserRoles(prisma, userId, user.tenantId || undefined);
  const permissions = await getUserPermissions(prisma, userId, user.tenantId || undefined);
  
  // Get session device ID
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    select: { deviceId: true },
  });
  
  // Create new token with MFA verified
  const payload: Omit<AuthContext, 'iat' | 'exp'> = {
    sub: userId,
    email: user.email,
    name: `${user.firstName} ${user.lastName}`,
    roles,
    permissions,
    tenantId: user.tenantId || undefined,
    sessionId,
    deviceId: session?.deviceId,
    isMfaVerified: true,
  };
  
  const accessToken = createToken(payload);
  
  // Create audit log
  await createAuditLog(prisma, {
    userId,
    tenantId: user.tenantId || undefined,
    action: 'MFA_VERIFICATION',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    deviceId: session?.deviceId,
    sessionId,
    status: 'success',
  });
  
  return {
    accessToken,
    success: true,
  };
}

/**
 * Get user's active sessions
 */
export async function getUserSessions(
  prisma: PrismaClient,
  userId: string
): Promise<Session[]> {
  const sessions = await prisma.session.findMany({
    where: {
      userId,
      isRevoked: false,
      expiresAt: {
        gt: new Date(),
      },
    },
    orderBy: {
      lastActiveAt: 'desc',
    },
    include: {
      device: true,
    },
  });
  
  return sessions.map(session => ({
    id: session.id,
    userId: session.userId,
    deviceId: session.deviceId,
    deviceInfo: {
      id: session.device.id,
      fingerprint: session.device.fingerprint,
      userAgent: session.device.userAgent,
      browser: {
        name: session.device.browser || undefined,
        version: session.device.browserVersion || undefined,
      },
      os: {
        name: session.device.os || undefined,
        version: session.device.osVersion || undefined,
      },
      device: {
        type: session.device.deviceType || undefined,
        model: session.device.deviceModel || undefined,
        vendor: session.device.deviceVendor || undefined,
      },
      isMobile: session.device.isMobile,
      isKnown: session.device.isKnown,
      firstSeenAt: session.device.firstSeenAt,
      lastSeenAt: session.device.lastSeenAt,
    },
    ipAddress: session.ipAddress,
    location: session.countryCode ? {
      country: session.countryCode,
      region: session.regionCode || undefined,
      city: session.city || undefined,
      latitude: session.latitude || undefined,
      longitude: session.longitude || undefined,
    } : undefined,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    lastActiveAt: session.lastActiveAt,
    isMfaVerified: session.isMfaVerified,
    isRevoked: session.isRevoked,
  }));
}

/**
 * Revoke a specific session
 */
export async function revokeUserSession(
  prisma: PrismaClient,
  userId: string,
  sessionId: string,
  req: Request
): Promise<boolean> {
  // Check if session belongs to user
  const session = await prisma.session.findFirst({
    where: {
      id: sessionId,
      userId,
    },
  });
  
  if (!session) {
    return false;
  }
  
  // Revoke the session
  await revokeSession(prisma, sessionId);
  
  // Create audit log
  await createAuditLog(prisma, {
    userId,
    action: 'SESSION_REVOKED',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    sessionId: req.auth?.sessionId,
    status: 'success',
    details: {
      revokedSessionId: sessionId,
    },
  });
  
  return true;
}

/**
 * Revoke all sessions for a user except the current one
 */
export async function revokeAllUserSessions(
  prisma: PrismaClient,
  userId: string,
  currentSessionId: string,
  req: Request
): Promise<number> {
  // Find all active sessions except the current one
  const sessions = await prisma.session.findMany({
    where: {
      userId,
      id: { not: currentSessionId },
      isRevoked: false,
      expiresAt: {
        gt: new Date(),
      },
    },
  });
  
  // Revoke all sessions
  await prisma.session.updateMany({
    where: {
      userId,
      id: { not: currentSessionId },
      isRevoked: false,
    },
    data: {
      isRevoked: true,
    },
  });
  
  // Create audit log
  await createAuditLog(prisma, {
    userId,
    action: 'ALL_SESSIONS_REVOKED',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    sessionId: currentSessionId,
    status: 'success',
    details: {
      revokedSessionCount: sessions.length,
    },
  });
  
  return sessions.length;
}

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
      prisma: PrismaClient;
      tenantPrisma?: PrismaClient;
      tenantId?: string;
    }
  }
}

// Export utility functions
export {
  createToken,
  verifyToken,
  createRefreshToken,
  verifyRefreshToken,
  getUserPermissions,
  getUserRoles,
  verifyApiKey,
  isMfaRequired,
  verifyMfaToken,
  generateDeviceFingerprint,
  getLocationFromIp,
  createAuditLog,
};

// Export default middleware
export default authenticate;
