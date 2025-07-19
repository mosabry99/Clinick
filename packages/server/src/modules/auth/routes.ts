/**
 * Authentication Routes
 * 
 * This module handles all authentication-related routes including:
 * - Login/logout with JWT token generation
 * - User registration with email verification
 * - Password reset functionality
 * - Two-factor authentication
 * - Session management and token refresh
 * - Account lockout after failed attempts
 * - Email verification workflow
 * - User profile management
 * - Security logging and audit trails
 */

import { Router, Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { expressjwt } from 'express-jwt';
import rateLimit from 'express-rate-limit';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import nodemailer from 'nodemailer';
import { createTransport } from 'nodemailer';
import { DateTime } from 'luxon';

// Create router
const router = Router();

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'clinick_development_secret_key';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '8h';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const NODE_ENV = process.env.NODE_ENV || 'development';
const EMAIL_FROM = process.env.EMAIL_FROM || 'noreply@clinick.app';

// Email transporter
const transporter = createTransport({
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: parseInt(process.env.SMTP_PORT || '2525', 10),
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
  },
  secure: process.env.SMTP_SECURE === 'true',
});

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Only count failed attempts
  message: { 
    success: false, 
    error: { 
      code: 'TOO_MANY_ATTEMPTS', 
      message: 'Too many login attempts, please try again later.' 
    } 
  },
  skip: (req) => NODE_ENV === 'development', // Skip in development
});

// Validation schemas
const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
  tenantId: z.string().optional(),
  rememberMe: z.boolean().optional().default(false),
  twoFactorCode: z.string().optional(),
});

const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  confirmPassword: z.string(),
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  phoneNumber: z.string().optional(),
  tenantId: z.string().optional(),
  agreedToTerms: z.boolean().refine(val => val === true, {
    message: 'You must agree to the terms and conditions',
  }),
}).refine(data => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email format'),
  tenantId: z.string().optional(),
});

const resetPasswordSchema = z.object({
  token: z.string(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  confirmPassword: z.string(),
}).refine(data => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

const updateProfileSchema = z.object({
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  displayName: z.string().optional(),
  phoneNumber: z.string().optional(),
  avatar: z.string().optional(),
  preferences: z.record(z.any()).optional(),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  confirmPassword: z.string(),
}).refine(data => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

const refreshTokenSchema = z.object({
  refreshToken: z.string(),
});

const setupTwoFactorSchema = z.object({
  enable: z.boolean(),
  code: z.string().optional(),
});

const verifyTwoFactorSchema = z.object({
  code: z.string(),
});

// Helper functions
const generateToken = (user: any, expiresIn: string = JWT_EXPIRY): string => {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions || [],
      tenantId: user.tenantId,
    },
    JWT_SECRET,
    { expiresIn }
  );
};

const generateRefreshToken = async (
  prisma: PrismaClient,
  userId: string,
  tenantId: string | null,
  expiresIn: string = REFRESH_TOKEN_EXPIRY
): Promise<string> => {
  const token = crypto.randomBytes(40).toString('hex');
  const expiresAt = DateTime.now().plus({ days: 7 }).toJSDate(); // 7 days

  await prisma.refreshToken.create({
    data: {
      token,
      userId,
      tenantId,
      expiresAt,
      createdByIp: '0.0.0.0', // This should be replaced with actual IP
    },
  });

  return token;
};

const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

const sendEmail = async (options: {
  to: string;
  subject: string;
  text?: string;
  html: string;
}): Promise<void> => {
  await transporter.sendMail({
    from: EMAIL_FROM,
    ...options,
  });
};

const createAuditLog = async (
  prisma: PrismaClient,
  data: {
    userId?: string;
    tenantId?: string;
    action: string;
    resourceType: string;
    resourceId?: string;
    description: string;
    ipAddress?: string;
    userAgent?: string;
    metadata?: any;
  }
): Promise<void> => {
  await prisma.auditLog.create({
    data,
  });
};

const validateRecaptcha = async (token: string): Promise<boolean> => {
  if (NODE_ENV === 'development') {
    return true;
  }

  try {
    const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;
    if (!RECAPTCHA_SECRET) {
      console.warn('RECAPTCHA_SECRET_KEY not configured');
      return true;
    }

    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `secret=${RECAPTCHA_SECRET}&response=${token}`,
    });

    const data = await response.json();
    return data.success;
  } catch (error) {
    console.error('Error validating reCAPTCHA:', error);
    return false;
  }
};

// Middleware to validate request body against a schema
const validateRequest = (schema: z.ZodType<any, any>) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Validation failed',
            details: error.errors,
          },
        });
      }
      next(error);
    }
  };
};

/**
 * @route POST /api/auth/login
 * @desc Authenticate user and return JWT token
 * @access Public
 */
router.post('/login', loginLimiter, validateRequest(loginSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, tenantId, rememberMe, twoFactorCode } = req.body;
    const prisma = req.tenantPrisma || req.prisma;

    // Find user
    const user = await prisma.user.findFirst({
      where: {
        email,
        tenantId: tenantId || null,
      },
    });

    if (!user) {
      // Don't reveal if user exists or not for security
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    }

    // Check if account is active
    if (user.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: {
          code: 'ACCOUNT_INACTIVE',
          message: `Your account is ${user.status}. Please contact support.`,
        },
      });
    }

    // Check if email is verified
    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'EMAIL_NOT_VERIFIED',
          message: 'Please verify your email address before logging in',
          details: {
            requiresEmailVerification: true,
            email: user.email,
          },
        },
      });
    }

    // Check for account lockout
    const lockoutThreshold = 5; // 5 failed attempts
    const lockoutDuration = 15 * 60 * 1000; // 15 minutes

    if (user.failedLoginAttempts >= lockoutThreshold) {
      const lastFailedLogin = user.lastFailedLoginAt;
      
      if (lastFailedLogin && Date.now() - lastFailedLogin.getTime() < lockoutDuration) {
        const remainingLockoutTime = Math.ceil((lockoutDuration - (Date.now() - lastFailedLogin.getTime())) / 60000);
        
        return res.status(403).json({
          success: false,
          error: {
            code: 'ACCOUNT_LOCKED',
            message: `Account is temporarily locked. Please try again in ${remainingLockoutTime} minutes.`,
          },
        });
      } else {
        // Reset failed attempts if lockout period has passed
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: 0,
            lastFailedLoginAt: null,
          },
        });
      }
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.passwordHash);

    if (!isPasswordValid) {
      // Increment failed login attempts
      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: {
            increment: 1,
          },
          lastFailedLoginAt: new Date(),
        },
      });

      // Create audit log for failed login
      await createAuditLog(prisma, {
        userId: user.id,
        tenantId: user.tenantId || undefined,
        action: 'LOGIN_FAILED',
        resourceType: 'User',
        resourceId: user.id,
        description: 'Failed login attempt',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    }

    // Check for 2FA if enabled
    if (user.twoFactorEnabled) {
      // If 2FA code wasn't provided, return that 2FA is required
      if (!twoFactorCode) {
        return res.status(200).json({
          success: true,
          data: {
            requiresTwoFactor: true,
            userId: user.id,
            email: user.email,
          },
        });
      }

      // Verify 2FA code
      const isValidTwoFactorCode = speakeasy.totp.verify({
        secret: user.twoFactorSecret!,
        encoding: 'base32',
        token: twoFactorCode,
        window: 1, // Allow 1 period before and after for clock skew
      });

      if (!isValidTwoFactorCode) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_2FA_CODE',
            message: 'Invalid two-factor authentication code',
          },
        });
      }
    }

    // Reset failed login attempts
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lastFailedLoginAt: null,
        lastLoginAt: new Date(),
      },
    });

    // Generate tokens
    const accessToken = generateToken(user);
    const refreshToken = await generateRefreshToken(
      prisma,
      user.id,
      user.tenantId,
      rememberMe ? '30d' : REFRESH_TOKEN_EXPIRY
    );

    // Create audit log for successful login
    await createAuditLog(prisma, {
      userId: user.id,
      tenantId: user.tenantId || undefined,
      action: 'LOGIN_SUCCESS',
      resourceType: 'User',
      resourceId: user.id,
      description: 'Successful login',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000, // 30 days or 7 days
    });

    // Return user data and token
    return res.status(200).json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          displayName: user.displayName || `${user.firstName} ${user.lastName}`,
          avatar: user.avatar,
          roles: user.roles,
          permissions: user.permissions,
          tenantId: user.tenantId,
          preferences: user.preferences,
        },
        token: accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/register
 * @desc Register a new user
 * @access Public
 */
router.post('/register', validateRequest(registerSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      email,
      password,
      firstName,
      lastName,
      phoneNumber,
      tenantId,
      agreedToTerms,
    } = req.body;

    // Get the appropriate Prisma client
    const prisma = req.tenantPrisma || req.prisma;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        email,
        tenantId: tenantId || null,
      },
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'USER_EXISTS',
          message: 'A user with this email already exists',
        },
      });
    }

    // Check tenant user limits if registering for a tenant
    if (tenantId) {
      const tenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
        include: { license: true },
      });

      if (!tenant) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'TENANT_NOT_FOUND',
            message: 'Tenant not found',
          },
        });
      }

      if (tenant.status !== 'active') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'TENANT_INACTIVE',
            message: 'This tenant is not active',
          },
        });
      }

      // Check if user limit is reached
      const userCount = await prisma.user.count({
        where: { tenantId },
      });

      const maxUsers = tenant.license?.maxUsers || tenant.maxUsers;

      if (userCount >= maxUsers) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'USER_LIMIT_REACHED',
            message: 'Maximum number of users reached for this tenant',
          },
        });
      }
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create user
    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
        displayName: `${firstName} ${lastName}`,
        phoneNumber,
        tenantId: tenantId || null,
        roles: tenantId ? ['USER'] : ['SYSTEM_ADMIN'],
        verificationToken,
        status: 'active',
        emailVerified: false,
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: newUser.id,
      tenantId: newUser.tenantId || undefined,
      action: 'REGISTER',
      resourceType: 'User',
      resourceId: newUser.id,
      description: 'User registration',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Send verification email
    const verificationUrl = `${FRONTEND_URL}/verify-email/${verificationToken}`;
    
    await sendEmail({
      to: email,
      subject: 'Verify your Clinick account',
      html: `
        <h1>Welcome to Clinick!</h1>
        <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
        <p><a href="${verificationUrl}">Verify Email Address</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you did not create an account, no further action is required.</p>
      `,
    });

    return res.status(201).json({
      success: true,
      data: {
        message: 'User registered successfully. Please check your email to verify your account.',
        userId: newUser.id,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/logout
 * @desc Logout user and invalidate refresh token
 * @access Private
 */
router.post('/logout', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    
    if (refreshToken) {
      const prisma = req.tenantPrisma || req.prisma;
      
      // Delete refresh token from database
      await prisma.refreshToken.deleteMany({
        where: {
          token: refreshToken,
        },
      });

      // Create audit log
      if (req.auth?.sub) {
        await createAuditLog(prisma, {
          userId: req.auth.sub,
          tenantId: req.auth.tenantId,
          action: 'LOGOUT',
          resourceType: 'User',
          resourceId: req.auth.sub,
          description: 'User logout',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
      }
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    return res.status(200).json({
      success: true,
      data: {
        message: 'Logged out successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/refresh-token
 * @desc Refresh access token using refresh token
 * @access Public
 */
router.post('/refresh-token', validateRequest(refreshTokenSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    const prisma = req.prisma; // Use system prisma for refresh tokens

    // Find refresh token in database
    const storedToken = await prisma.refreshToken.findFirst({
      where: {
        token: refreshToken,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
    });

    if (!storedToken) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_REFRESH_TOKEN',
          message: 'Invalid or expired refresh token',
        },
      });
    }

    // Check if user is still active
    if (storedToken.user.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: {
          code: 'ACCOUNT_INACTIVE',
          message: `Your account is ${storedToken.user.status}. Please contact support.`,
        },
      });
    }

    // Generate new tokens
    const accessToken = generateToken(storedToken.user);
    const newRefreshToken = await generateRefreshToken(
      prisma,
      storedToken.user.id,
      storedToken.user.tenantId
    );

    // Delete old refresh token
    await prisma.refreshToken.delete({
      where: {
        id: storedToken.id,
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: storedToken.user.id,
      tenantId: storedToken.user.tenantId || undefined,
      action: 'TOKEN_REFRESH',
      resourceType: 'User',
      resourceId: storedToken.user.id,
      description: 'Token refresh',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Set new refresh token as HTTP-only cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      success: true,
      data: {
        token: accessToken,
        refreshToken: newRefreshToken,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/forgot-password
 * @desc Send password reset email
 * @access Public
 */
router.post('/forgot-password', validateRequest(forgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, tenantId } = req.body;
    const prisma = req.tenantPrisma || req.prisma;

    // Find user
    const user = await prisma.user.findFirst({
      where: {
        email,
        tenantId: tenantId || null,
      },
    });

    // Don't reveal if user exists or not
    if (!user) {
      return res.status(200).json({
        success: true,
        data: {
          message: 'If your email is registered, you will receive a password reset link',
        },
      });
    }

    // Check if account is active
    if (user.status !== 'active') {
      return res.status(200).json({
        success: true,
        data: {
          message: 'If your email is registered, you will receive a password reset link',
        },
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Save reset token to database
    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken,
        resetTokenExpiresAt: resetTokenExpiry,
      },
    });

    // Create reset URL
    const resetUrl = `${FRONTEND_URL}/reset-password/${resetToken}`;

    // Send email
    await sendEmail({
      to: user.email,
      subject: 'Reset your Clinick password',
      html: `
        <h1>Password Reset Request</h1>
        <p>You requested a password reset for your Clinick account. Click the link below to reset your password:</p>
        <p><a href="${resetUrl}">Reset Password</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
      `,
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: user.id,
      tenantId: user.tenantId || undefined,
      action: 'PASSWORD_RESET_REQUEST',
      resourceType: 'User',
      resourceId: user.id,
      description: 'Password reset requested',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      data: {
        message: 'If your email is registered, you will receive a password reset link',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/reset-password/:token
 * @desc Reset password using token
 * @access Public
 */
router.post('/reset-password/:token', validateRequest(resetPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    const prisma = req.prisma; // Use system prisma since we don't know the tenant yet

    // Find user by reset token
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_RESET_TOKEN',
          message: 'Invalid or expired password reset token',
        },
      });
    }

    // Hash new password
    const passwordHash = await hashPassword(password);

    // Update user password and clear reset token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        resetToken: null,
        resetTokenExpiresAt: null,
        passwordChangedAt: new Date(),
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: user.id,
      tenantId: user.tenantId || undefined,
      action: 'PASSWORD_RESET',
      resourceType: 'User',
      resourceId: user.id,
      description: 'Password reset completed',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      data: {
        message: 'Password has been reset successfully. You can now log in with your new password.',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/auth/verify-email/:token
 * @desc Verify email address
 * @access Public
 */
router.get('/verify-email/:token', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.params;
    const prisma = req.prisma; // Use system prisma since we don't know the tenant yet

    // Find user by verification token
    const user = await prisma.user.findFirst({
      where: {
        verificationToken: token,
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_VERIFICATION_TOKEN',
          message: 'Invalid or expired email verification token',
        },
      });
    }

    // Update user as verified
    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        verificationToken: null,
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: user.id,
      tenantId: user.tenantId || undefined,
      action: 'EMAIL_VERIFIED',
      resourceType: 'User',
      resourceId: user.id,
      description: 'Email verification completed',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Redirect to frontend
    return res.redirect(`${FRONTEND_URL}/login?verified=true`);
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/resend-verification
 * @desc Resend email verification
 * @access Public
 */
router.post('/resend-verification', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, tenantId } = req.body;
    const prisma = req.tenantPrisma || req.prisma;

    // Find user
    const user = await prisma.user.findFirst({
      where: {
        email,
        tenantId: tenantId || null,
      },
    });

    // Don't reveal if user exists or not
    if (!user || user.emailVerified) {
      return res.status(200).json({
        success: true,
        data: {
          message: 'If your email is registered and not verified, you will receive a verification email',
        },
      });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Update user with new token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        verificationToken,
      },
    });

    // Send verification email
    const verificationUrl = `${FRONTEND_URL}/verify-email/${verificationToken}`;
    
    await sendEmail({
      to: email,
      subject: 'Verify your Clinick account',
      html: `
        <h1>Verify Your Email</h1>
        <p>Please verify your email address by clicking the link below:</p>
        <p><a href="${verificationUrl}">Verify Email Address</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you did not create an account, no further action is required.</p>
      `,
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: user.id,
      tenantId: user.tenantId || undefined,
      action: 'VERIFICATION_EMAIL_RESENT',
      resourceType: 'User',
      resourceId: user.id,
      description: 'Verification email resent',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      data: {
        message: 'If your email is registered and not verified, you will receive a verification email',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/auth/me
 * @desc Get current user profile
 * @access Private
 */
router.get('/me', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;

    // Find user
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        avatar: true,
        phoneNumber: true,
        roles: true,
        permissions: true,
        tenantId: true,
        emailVerified: true,
        twoFactorEnabled: true,
        lastLoginAt: true,
        status: true,
        preferences: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: {
        user,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/auth/profile
 * @desc Update user profile
 * @access Private
 */
router.put('/profile', validateRequest(updateProfileSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;
    const { firstName, lastName, displayName, phoneNumber, avatar, preferences } = req.body;

    // Update user
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        firstName,
        lastName,
        displayName: displayName || `${firstName} ${lastName}`,
        phoneNumber,
        avatar,
        preferences,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        avatar: true,
        phoneNumber: true,
        roles: true,
        permissions: true,
        tenantId: true,
        emailVerified: true,
        twoFactorEnabled: true,
        lastLoginAt: true,
        status: true,
        preferences: true,
        updatedAt: true,
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId,
      tenantId: req.auth?.tenantId,
      action: 'PROFILE_UPDATE',
      resourceType: 'User',
      resourceId: userId,
      description: 'User profile updated',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      data: {
        user: updatedUser,
        message: 'Profile updated successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/auth/change-password
 * @desc Change user password
 * @access Private
 */
router.put('/change-password', validateRequest(changePasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;
    const { currentPassword, newPassword } = req.body;

    // Find user
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        passwordHash: true,
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }

    // Verify current password
    const isPasswordValid = await comparePassword(currentPassword, user.passwordHash);

    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_CURRENT_PASSWORD',
          message: 'Current password is incorrect',
        },
      });
    }

    // Hash new password
    const passwordHash = await hashPassword(newPassword);

    // Update user password
    await prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash,
        passwordChangedAt: new Date(),
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId,
      tenantId: req.auth?.tenantId,
      action: 'PASSWORD_CHANGE',
      resourceType: 'User',
      resourceId: userId,
      description: 'User password changed',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      data: {
        message: 'Password changed successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/setup-two-factor
 * @desc Setup two-factor authentication
 * @access Private
 */
router.post('/setup-two-factor', validateRequest(setupTwoFactorSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;
    const { enable, code } = req.body;

    // Find user
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }

    // If enabling 2FA
    if (enable) {
      // If user already has 2FA enabled, require verification
      if (user.twoFactorEnabled) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'TWO_FACTOR_ALREADY_ENABLED',
            message: 'Two-factor authentication is already enabled',
          },
        });
      }

      // If no secret exists, generate one
      if (!user.twoFactorSecret) {
        const secret = speakeasy.generateSecret({
          name: `Clinick:${user.email}`,
        });

        // Generate QR code
        const qrCode = await qrcode.toDataURL(secret.otpauth_url || '');

        // Save secret to user
        await prisma.user.update({
          where: { id: userId },
          data: {
            twoFactorSecret: secret.base32,
          },
        });

        return res.status(200).json({
          success: true,
          data: {
            secret: secret.base32,
            qrCode,
            message: 'Two-factor authentication setup initiated. Scan the QR code with your authenticator app and enter the code to verify.',
          },
        });
      }

      // Verify the code
      if (!code) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VERIFICATION_CODE_REQUIRED',
            message: 'Verification code is required to enable two-factor authentication',
          },
        });
      }

      const isValidCode = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: code,
        window: 1,
      });

      if (!isValidCode) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_VERIFICATION_CODE',
            message: 'Invalid verification code',
          },
        });
      }

      // Enable 2FA
      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: true,
        },
      });

      // Create audit log
      await createAuditLog(prisma, {
        userId,
        tenantId: req.auth?.tenantId,
        action: 'TWO_FACTOR_ENABLED',
        resourceType: 'User',
        resourceId: userId,
        description: 'Two-factor authentication enabled',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(200).json({
        success: true,
        data: {
          message: 'Two-factor authentication has been enabled successfully',
        },
      });
    } else {
      // Disabling 2FA
      if (!user.twoFactorEnabled) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'TWO_FACTOR_NOT_ENABLED',
            message: 'Two-factor authentication is not enabled',
          },
        });
      }

      // Verify the code
      if (!code) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VERIFICATION_CODE_REQUIRED',
            message: 'Verification code is required to disable two-factor authentication',
          },
        });
      }

      const isValidCode = speakeasy.totp.verify({
        secret: user.twoFactorSecret || '',
        encoding: 'base32',
        token: code,
        window: 1,
      });

      if (!isValidCode) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_VERIFICATION_CODE',
            message: 'Invalid verification code',
          },
        });
      }

      // Disable 2FA
      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
        },
      });

      // Create audit log
      await createAuditLog(prisma, {
        userId,
        tenantId: req.auth?.tenantId,
        action: 'TWO_FACTOR_DISABLED',
        resourceType: 'User',
        resourceId: userId,
        description: 'Two-factor authentication disabled',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(200).json({
        success: true,
        data: {
          message: 'Two-factor authentication has been disabled successfully',
        },
      });
    }
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/auth/verify-two-factor
 * @desc Verify two-factor authentication code
 * @access Public
 */
router.post('/verify-two-factor', validateRequest(verifyTwoFactorSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { code, userId } = req.body;
    const prisma = req.tenantPrisma || req.prisma;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'USER_ID_REQUIRED',
          message: 'User ID is required',
        },
      });
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'TWO_FACTOR_NOT_ENABLED',
          message: 'Two-factor authentication is not enabled for this user',
        },
      });
    }

    // Verify the code
    const isValidCode = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1,
    });

    if (!isValidCode) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_VERIFICATION_CODE',
          message: 'Invalid verification code',
        },
      });
    }

    // Generate tokens
    const accessToken = generateToken(user);
    const refreshToken = await generateRefreshToken(
      prisma,
      user.id,
      user.tenantId
    );

    // Update last login time
    await prisma.user.update({
      where: { id: userId },
      data: {
        lastLoginAt: new Date(),
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId: user.id,
      tenantId: user.tenantId || undefined,
      action: 'TWO_FACTOR_VERIFIED',
      resourceType: 'User',
      resourceId: user.id,
      description: 'Two-factor authentication verified',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          displayName: user.displayName || `${user.firstName} ${user.lastName}`,
          avatar: user.avatar,
          roles: user.roles,
          permissions: user.permissions,
          tenantId: user.tenantId,
          preferences: user.preferences,
        },
        token: accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/auth/sessions
 * @desc Get user active sessions
 * @access Private
 */
router.get('/sessions', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;

    // Get active refresh tokens
    const activeSessions = await prisma.refreshToken.findMany({
      where: {
        userId,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
      select: {
        id: true,
        createdAt: true,
        expiresAt: true,
        createdByIp: true,
        userAgent: true,
      },
    });

    return res.status(200).json({
      success: true,
      data: {
        sessions: activeSessions,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/auth/sessions/:id
 * @desc Revoke a specific session
 * @access Private
 */
router.delete('/sessions/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    const sessionId = req.params.id;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;

    // Find the session
    const session = await prisma.refreshToken.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'SESSION_NOT_FOUND',
          message: 'Session not found',
        },
      });
    }

    // Delete the session
    await prisma.refreshToken.delete({
      where: {
        id: sessionId,
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId,
      tenantId: req.auth?.tenantId,
      action: 'SESSION_REVOKED',
      resourceType: 'RefreshToken',
      resourceId: sessionId,
      description: 'Session revoked',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      data: {
        message: 'Session revoked successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/auth/sessions
 * @desc Revoke all sessions except current
 * @access Private
 */
router.delete('/sessions', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    const currentRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;

    // Delete all sessions except current
    const { count } = await prisma.refreshToken.deleteMany({
      where: {
        userId,
        token: {
          not: currentRefreshToken,
        },
      },
    });

    // Create audit log
    await createAuditLog(prisma, {
      userId,
      tenantId: req.auth?.tenantId,
      action: 'ALL_SESSIONS_REVOKED',
      resourceType: 'User',
      resourceId: userId,
      description: 'All sessions revoked except current',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        sessionsRevoked: count,
      },
    });

    return res.status(200).json({
      success: true,
      data: {
        message: `${count} sessions revoked successfully`,
        count,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/auth/security-logs
 * @desc Get user security logs
 * @access Private
 */
router.get('/security-logs', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.auth?.sub;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Not authenticated',
        },
      });
    }

    const prisma = req.tenantPrisma || req.prisma;
    const page = parseInt(req.query.page as string || '1', 10);
    const limit = parseInt(req.query.limit as string || '20', 10);
    const skip = (page - 1) * limit;

    // Get security-related audit logs
    const securityActions = [
      'LOGIN_SUCCESS',
      'LOGIN_FAILED',
      'LOGOUT',
      'PASSWORD_CHANGE',
      'PASSWORD_RESET_REQUEST',
      'PASSWORD_RESET',
      'EMAIL_VERIFIED',
      'TWO_FACTOR_ENABLED',
      'TWO_FACTOR_DISABLED',
      'TWO_FACTOR_VERIFIED',
      'SESSION_REVOKED',
      'ALL_SESSIONS_REVOKED',
      'TOKEN_REFRESH',
    ];

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where: {
          userId,
          action: {
            in: securityActions,
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
        skip,
        take: limit,
      }),
      prisma.auditLog.count({
        where: {
          userId,
          action: {
            in: securityActions,
          },
        },
      }),
    ]);

    return res.status(200).json({
      success: true,
      data: {
        logs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    next(error);
  }
});

export default router;
