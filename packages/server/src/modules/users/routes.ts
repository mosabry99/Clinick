/**
 * User Management Routes
 * 
 * This module handles all user management operations including:
 * - CRUD operations for users
 * - Role and permission management
 * - User search and filtering
 * - User profile management
 * - User status management (active/inactive/suspended)
 * - Bulk user operations
 * - User role assignments
 * - User statistics and activity tracking
 */

import { Router, Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { DateTime } from 'luxon';

// Create router
const router = Router();

// Environment variables
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const EMAIL_FROM = process.env.EMAIL_FROM || 'noreply@clinick.app';

// Permission constants
const REQUIRED_PERMISSIONS = {
  LIST: ['users:list'],
  VIEW: ['users:view'],
  CREATE: ['users:create'],
  UPDATE: ['users:update'],
  DELETE: ['users:delete'],
  MANAGE_ROLES: ['users:manage-roles'],
  MANAGE_PERMISSIONS: ['users:manage-permissions'],
  BULK_OPERATIONS: ['users:bulk-operations'],
};

// Validation schemas
const createUserSchema = z.object({
  email: z.string().email('Invalid email format'),
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character')
    .optional(),
  phoneNumber: z.string().optional(),
  roles: z.array(z.string()).min(1, 'At least one role is required'),
  permissions: z.array(z.string()).optional(),
  status: z.enum(['active', 'inactive', 'suspended']).default('active'),
  sendInvitation: z.boolean().default(true),
  displayName: z.string().optional(),
  avatar: z.string().optional(),
  preferences: z.record(z.any()).optional(),
});

const updateUserSchema = z.object({
  email: z.string().email('Invalid email format').optional(),
  firstName: z.string().min(1, 'First name is required').optional(),
  lastName: z.string().min(1, 'Last name is required').optional(),
  phoneNumber: z.string().optional(),
  displayName: z.string().optional(),
  avatar: z.string().optional(),
  preferences: z.record(z.any()).optional(),
  status: z.enum(['active', 'inactive', 'suspended']).optional(),
});

const updateUserRolesSchema = z.object({
  roles: z.array(z.string()).min(1, 'At least one role is required'),
});

const updateUserPermissionsSchema = z.object({
  permissions: z.array(z.string()),
});

const updateUserStatusSchema = z.object({
  status: z.enum(['active', 'inactive', 'suspended']),
  reason: z.string().optional(),
});

const resetUserPasswordSchema = z.object({
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  sendEmail: z.boolean().default(true),
});

const bulkUsersSchema = z.object({
  userIds: z.array(z.string()).min(1, 'At least one user ID is required'),
  action: z.enum(['activate', 'deactivate', 'suspend', 'delete', 'assign-roles']),
  data: z.record(z.any()).optional(),
});

const userFilterSchema = z.object({
  search: z.string().optional(),
  status: z.enum(['active', 'inactive', 'suspended', 'all']).optional(),
  roles: z.array(z.string()).optional(),
  sortBy: z.enum(['firstName', 'lastName', 'email', 'createdAt', 'lastLoginAt']).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().positive().optional(),
  limit: z.number().int().positive().optional(),
});

// Helper functions
const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
};

const generateRandomPassword = (): string => {
  const length = 12;
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+';
  let password = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset[randomIndex];
  }
  
  // Ensure password meets requirements
  if (!/[A-Z]/.test(password)) password = password.replace(password[0], 'A');
  if (!/[a-z]/.test(password)) password = password.replace(password[1], 'a');
  if (!/[0-9]/.test(password)) password = password.replace(password[2], '1');
  if (!/[^A-Za-z0-9]/.test(password)) password = password.replace(password[3], '!');
  
  return password;
};

const sendInvitationEmail = async (
  email: string,
  firstName: string,
  lastName: string,
  password: string | null,
  invitationToken: string
): Promise<void> => {
  try {
    const invitationUrl = `${FRONTEND_URL}/accept-invitation/${invitationToken}`;
    
    // This is a placeholder. In a real application, you would use a proper email service
    console.log(`
      To: ${email}
      Subject: Invitation to join Clinick
      
      Hello ${firstName} ${lastName},
      
      You have been invited to join Clinick. Please click the link below to accept the invitation:
      
      ${invitationUrl}
      
      ${password ? `Your temporary password is: ${password}` : 'You will be asked to set a password when you accept the invitation.'}
      
      This invitation will expire in 7 days.
      
      Thank you,
      Clinick Team
    `);
  } catch (error) {
    console.error('Error sending invitation email:', error);
  }
};

const createAuditLog = async (
  prisma: PrismaClient,
  data: {
    userId: string;
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

const checkPermission = (req: Request, permissions: string[]): boolean => {
  const userPermissions = req.auth?.permissions || [];
  
  // System admins have all permissions
  if (req.auth?.roles?.includes('SYSTEM_ADMIN')) {
    return true;
  }
  
  // Tenant admins have all permissions within their tenant
  if (req.auth?.roles?.includes('TENANT_ADMIN')) {
    return true;
  }
  
  // Check if user has any of the required permissions
  return permissions.some(permission => userPermissions.includes(permission));
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

// Middleware to check permissions
const requirePermission = (permissions: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!checkPermission(req, permissions)) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'You do not have permission to perform this action',
        },
      });
    }
    next();
  };
};

/**
 * @route GET /api/users
 * @desc Get list of users with filtering and pagination
 * @access Private (requires users:list permission)
 */
router.get('/', requirePermission(REQUIRED_PERMISSIONS.LIST), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prisma = req.tenantPrisma || req.prisma;
    
    // Parse and validate query parameters
    const filters = userFilterSchema.parse({
      search: req.query.search as string,
      status: req.query.status as string,
      roles: req.query.roles ? (req.query.roles as string).split(',') : undefined,
      sortBy: req.query.sortBy as string,
      sortOrder: req.query.sortOrder as string,
      page: req.query.page ? parseInt(req.query.page as string, 10) : 1,
      limit: req.query.limit ? parseInt(req.query.limit as string, 10) : 20,
    });
    
    const {
      search,
      status,
      roles,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      page = 1,
      limit = 20,
    } = filters;
    
    // Build where clause
    const where: any = {
      tenantId: req.auth?.tenantId,
    };
    
    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { displayName: { contains: search, mode: 'insensitive' } },
      ];
    }
    
    if (status && status !== 'all') {
      where.status = status;
    }
    
    if (roles && roles.length > 0) {
      where.roles = {
        hasSome: roles,
      };
    }
    
    // Calculate pagination
    const skip = (page - 1) * limit;
    
    // Build order by
    const orderBy: any = {};
    orderBy[sortBy] = sortOrder;
    
    // Get users with pagination
    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
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
          status: true,
          lastLoginAt: true,
          createdAt: true,
          updatedAt: true,
          emailVerified: true,
          twoFactorEnabled: true,
        },
        orderBy,
        skip,
        take: limit,
      }),
      prisma.user.count({ where }),
    ]);
    
    // Return users with pagination info
    return res.status(200).json({
      success: true,
      data: {
        users,
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

/**
 * @route GET /api/users/:id
 * @desc Get user by ID
 * @access Private (requires users:view permission)
 */
router.get('/:id', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Get user
    const user = await prisma.user.findUnique({
      where: {
        id,
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
        status: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true,
        emailVerified: true,
        twoFactorEnabled: true,
        preferences: true,
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
    
    // Get user statistics
    const [
      loginCount,
      lastAuditLogs,
      patientCount,
      appointmentCount,
    ] = await Promise.all([
      prisma.auditLog.count({
        where: {
          userId: id,
          action: 'LOGIN_SUCCESS',
        },
      }),
      prisma.auditLog.findMany({
        where: {
          userId: id,
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: 5,
      }),
      user.roles.includes('DOCTOR') 
        ? prisma.patient.count({
            where: {
              appointments: {
                some: {
                  doctorId: id,
                },
              },
            },
          })
        : 0,
      user.roles.includes('DOCTOR')
        ? prisma.appointment.count({
            where: {
              doctorId: id,
            },
          })
        : 0,
    ]);
    
    // Get doctor details if user is a doctor
    let doctorDetails = null;
    if (user.roles.includes('DOCTOR')) {
      doctorDetails = await prisma.doctor.findUnique({
        where: {
          userId: id,
        },
        include: {
          departments: {
            include: {
              department: true,
            },
          },
        },
      });
    }
    
    // Return user with additional data
    return res.status(200).json({
      success: true,
      data: {
        user,
        statistics: {
          loginCount,
          patientCount: user.roles.includes('DOCTOR') ? patientCount : null,
          appointmentCount: user.roles.includes('DOCTOR') ? appointmentCount : null,
        },
        recentActivity: lastAuditLogs,
        doctorDetails,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/users
 * @desc Create a new user
 * @access Private (requires users:create permission)
 */
router.post('/', requirePermission(REQUIRED_PERMISSIONS.CREATE), validateRequest(createUserSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      email,
      firstName,
      lastName,
      password,
      phoneNumber,
      roles,
      permissions,
      status,
      sendInvitation,
      displayName,
      avatar,
      preferences,
    } = req.body;
    
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if email is already in use
    const existingUser = await prisma.user.findFirst({
      where: {
        email,
        tenantId: req.auth?.tenantId,
      },
    });
    
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'EMAIL_IN_USE',
          message: 'Email is already in use',
        },
      });
    }
    
    // Check if tenant has reached user limit
    if (req.auth?.tenantId) {
      const tenant = await prisma.tenant.findUnique({
        where: { id: req.auth.tenantId },
        include: { license: true },
      });
      
      if (tenant) {
        const userCount = await prisma.user.count({
          where: { tenantId: req.auth.tenantId },
        });
        
        const maxUsers = tenant.license?.maxUsers || tenant.maxUsers;
        
        if (userCount >= maxUsers) {
          return res.status(403).json({
            success: false,
            error: {
              code: 'USER_LIMIT_REACHED',
              message: 'Maximum number of users reached for this tenant',
              details: {
                currentUsers: userCount,
                maxUsers,
              },
            },
          });
        }
      }
    }
    
    // Generate password if not provided
    let userPassword = password;
    let passwordToSend = null;
    
    if (!userPassword && sendInvitation) {
      userPassword = generateRandomPassword();
      passwordToSend = userPassword;
    }
    
    // Hash password
    const passwordHash = userPassword ? await hashPassword(userPassword) : '';
    
    // Generate invitation token if sending invitation
    const invitationToken = sendInvitation ? crypto.randomBytes(32).toString('hex') : null;
    const invitationExpiry = sendInvitation ? DateTime.now().plus({ days: 7 }).toJSDate() : null;
    
    // Create user
    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
        displayName: displayName || `${firstName} ${lastName}`,
        phoneNumber,
        roles,
        permissions: permissions || [],
        status,
        tenantId: req.auth?.tenantId,
        emailVerified: !sendInvitation,
        invitationToken: invitationToken || null,
        invitationExpiry,
        preferences,
        avatar,
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
        status: true,
        createdAt: true,
      },
    });
    
    // Create doctor record if user is a doctor
    if (roles.includes('DOCTOR')) {
      await prisma.doctor.create({
        data: {
          userId: newUser.id,
          specialization: 'General',
          licenseNumber: 'PENDING',
          qualifications: [],
          status: 'active',
        },
      });
    }
    
    // Send invitation email if requested
    if (sendInvitation && invitationToken) {
      await sendInvitationEmail(
        email,
        firstName,
        lastName,
        passwordToSend,
        invitationToken
      );
    }
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_CREATED',
      resourceType: 'User',
      resourceId: newUser.id,
      description: `User ${newUser.email} created`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        roles,
        status,
        sendInvitation,
      },
    });
    
    return res.status(201).json({
      success: true,
      data: {
        user: newUser,
        message: sendInvitation
          ? 'User created and invitation sent'
          : 'User created successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/users/:id
 * @desc Update user
 * @access Private (requires users:update permission)
 */
router.put('/:id', requirePermission(REQUIRED_PERMISSIONS.UPDATE), validateRequest(updateUserSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const {
      email,
      firstName,
      lastName,
      phoneNumber,
      displayName,
      avatar,
      preferences,
      status,
    } = req.body;
    
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Check if email is already in use by another user
    if (email && email !== existingUser.email) {
      const emailInUse = await prisma.user.findFirst({
        where: {
          email,
          tenantId: req.auth?.tenantId,
          id: { not: id },
        },
      });
      
      if (emailInUse) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'EMAIL_IN_USE',
            message: 'Email is already in use',
          },
        });
      }
    }
    
    // Update user
    const updatedUser = await prisma.user.update({
      where: { id },
      data: {
        ...(email && { email }),
        ...(firstName && { firstName }),
        ...(lastName && { lastName }),
        ...(phoneNumber !== undefined && { phoneNumber }),
        ...(displayName !== undefined && { displayName }),
        ...(avatar !== undefined && { avatar }),
        ...(preferences !== undefined && { preferences }),
        ...(status && { status }),
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
        status: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_UPDATED',
      resourceType: 'User',
      resourceId: id,
      description: `User ${updatedUser.email} updated`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        changes: req.body,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        user: updatedUser,
        message: 'User updated successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/users/:id
 * @desc Delete user
 * @access Private (requires users:delete permission)
 */
router.delete('/:id', requirePermission(REQUIRED_PERMISSIONS.DELETE), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        roles: true,
      },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Prevent deletion of the last tenant admin
    if (existingUser.roles.includes('TENANT_ADMIN')) {
      const tenantAdminCount = await prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          roles: {
            hasSome: ['TENANT_ADMIN'],
          },
        },
      });
      
      if (tenantAdminCount <= 1) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'LAST_TENANT_ADMIN',
            message: 'Cannot delete the last tenant admin',
          },
        });
      }
    }
    
    // Create audit log before deletion
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_DELETED',
      resourceType: 'User',
      resourceId: id,
      description: `User ${existingUser.email} deleted`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Delete user
    await prisma.user.delete({
      where: { id },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'User deleted successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/users/:id/roles
 * @desc Update user roles
 * @access Private (requires users:manage-roles permission)
 */
router.put('/:id/roles', requirePermission(REQUIRED_PERMISSIONS.MANAGE_ROLES), validateRequest(updateUserRolesSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const { roles } = req.body;
    
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        roles: true,
      },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Prevent removal of TENANT_ADMIN role from the last tenant admin
    if (
      existingUser.roles.includes('TENANT_ADMIN') &&
      !roles.includes('TENANT_ADMIN')
    ) {
      const tenantAdminCount = await prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          roles: {
            hasSome: ['TENANT_ADMIN'],
          },
        },
      });
      
      if (tenantAdminCount <= 1) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'LAST_TENANT_ADMIN',
            message: 'Cannot remove admin role from the last tenant admin',
          },
        });
      }
    }
    
    // Check if adding DOCTOR role
    const addingDoctorRole = !existingUser.roles.includes('DOCTOR') && roles.includes('DOCTOR');
    
    // Update user roles
    const updatedUser = await prisma.user.update({
      where: { id },
      data: {
        roles,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        roles: true,
      },
    });
    
    // Create doctor record if adding DOCTOR role
    if (addingDoctorRole) {
      await prisma.doctor.create({
        data: {
          userId: id,
          specialization: 'General',
          licenseNumber: 'PENDING',
          qualifications: [],
          status: 'active',
        },
      });
    }
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_ROLES_UPDATED',
      resourceType: 'User',
      resourceId: id,
      description: `Roles updated for user ${updatedUser.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        previousRoles: existingUser.roles,
        newRoles: roles,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        user: updatedUser,
        message: 'User roles updated successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/users/:id/permissions
 * @desc Update user permissions
 * @access Private (requires users:manage-permissions permission)
 */
router.put('/:id/permissions', requirePermission(REQUIRED_PERMISSIONS.MANAGE_PERMISSIONS), validateRequest(updateUserPermissionsSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const { permissions } = req.body;
    
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        permissions: true,
      },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Update user permissions
    const updatedUser = await prisma.user.update({
      where: { id },
      data: {
        permissions,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        roles: true,
        permissions: true,
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_PERMISSIONS_UPDATED',
      resourceType: 'User',
      resourceId: id,
      description: `Permissions updated for user ${updatedUser.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        previousPermissions: existingUser.permissions,
        newPermissions: permissions,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        user: updatedUser,
        message: 'User permissions updated successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/users/:id/status
 * @desc Update user status
 * @access Private (requires users:update permission)
 */
router.put('/:id/status', requirePermission(REQUIRED_PERMISSIONS.UPDATE), validateRequest(updateUserStatusSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const { status, reason } = req.body;
    
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        roles: true,
        status: true,
      },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Prevent deactivation of the last tenant admin
    if (
      existingUser.roles.includes('TENANT_ADMIN') &&
      existingUser.status === 'active' &&
      status !== 'active'
    ) {
      const activeAdminCount = await prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          roles: {
            hasSome: ['TENANT_ADMIN'],
          },
          status: 'active',
        },
      });
      
      if (activeAdminCount <= 1) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'LAST_ACTIVE_ADMIN',
            message: 'Cannot deactivate the last active tenant admin',
          },
        });
      }
    }
    
    // Update user status
    const updatedUser = await prisma.user.update({
      where: { id },
      data: {
        status,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        status: true,
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_STATUS_UPDATED',
      resourceType: 'User',
      resourceId: id,
      description: `Status updated for user ${updatedUser.email} to ${status}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        previousStatus: existingUser.status,
        newStatus: status,
        reason,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        user: updatedUser,
        message: `User ${status === 'active' ? 'activated' : status === 'inactive' ? 'deactivated' : 'suspended'} successfully`,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/users/:id/reset-password
 * @desc Reset user password
 * @access Private (requires users:update permission)
 */
router.put('/:id/reset-password', requirePermission(REQUIRED_PERMISSIONS.UPDATE), validateRequest(resetUserPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const { password, sendEmail } = req.body;
    
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
      },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Hash password
    const passwordHash = await hashPassword(password);
    
    // Update user password
    await prisma.user.update({
      where: { id },
      data: {
        passwordHash,
        passwordChangedAt: new Date(),
      },
    });
    
    // Send email notification if requested
    if (sendEmail) {
      // Placeholder for email sending functionality
      console.log(`
        To: ${existingUser.email}
        Subject: Your password has been reset
        
        Hello ${existingUser.firstName} ${existingUser.lastName},
        
        Your password has been reset by an administrator. Your new password is:
        
        ${password}
        
        Please log in and change your password as soon as possible.
        
        Thank you,
        Clinick Team
      `);
    }
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_PASSWORD_RESET',
      resourceType: 'User',
      resourceId: id,
      description: `Password reset for user ${existingUser.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        sendEmail,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'User password reset successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/users/:id/resend-invitation
 * @desc Resend user invitation
 * @access Private (requires users:update permission)
 */
router.post('/:id/resend-invitation', requirePermission(REQUIRED_PERMISSIONS.UPDATE), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        emailVerified: true,
      },
    });
    
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
        },
      });
    }
    
    // Check if user is already verified
    if (existingUser.emailVerified) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'USER_ALREADY_VERIFIED',
          message: 'User has already verified their account',
        },
      });
    }
    
    // Generate new invitation token
    const invitationToken = crypto.randomBytes(32).toString('hex');
    const invitationExpiry = DateTime.now().plus({ days: 7 }).toJSDate();
    
    // Update user with new invitation token
    await prisma.user.update({
      where: { id },
      data: {
        invitationToken,
        invitationExpiry,
      },
    });
    
    // Generate a temporary password
    const temporaryPassword = generateRandomPassword();
    const passwordHash = await hashPassword(temporaryPassword);
    
    // Update user password
    await prisma.user.update({
      where: { id },
      data: {
        passwordHash,
        passwordChangedAt: new Date(),
      },
    });
    
    // Send invitation email
    await sendInvitationEmail(
      existingUser.email,
      existingUser.firstName,
      existingUser.lastName,
      temporaryPassword,
      invitationToken
    );
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'USER_INVITATION_RESENT',
      resourceType: 'User',
      resourceId: id,
      description: `Invitation resent to user ${existingUser.email}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'Invitation resent successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/users/bulk
 * @desc Perform bulk operations on users
 * @access Private (requires users:bulk-operations permission)
 */
router.post('/bulk', requirePermission(REQUIRED_PERMISSIONS.BULK_OPERATIONS), validateRequest(bulkUsersSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userIds, action, data } = req.body;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Validate that all users exist
    const users = await prisma.user.findMany({
      where: {
        id: { in: userIds },
      },
      select: {
        id: true,
        email: true,
        roles: true,
        status: true,
      },
    });
    
    if (users.length !== userIds.length) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_USER_IDS',
          message: 'One or more user IDs are invalid',
        },
      });
    }
    
    // Check for tenant admins if deactivating or deleting
    if (action === 'deactivate' || action === 'suspend' || action === 'delete') {
      const adminUsers = users.filter(user => user.roles.includes('TENANT_ADMIN'));
      
      if (adminUsers.length > 0) {
        const activeAdminCount = await prisma.user.count({
          where: {
            tenantId: req.auth?.tenantId,
            roles: {
              hasSome: ['TENANT_ADMIN'],
            },
            status: 'active',
          },
        });
        
        if (activeAdminCount <= adminUsers.length) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'LAST_ACTIVE_ADMIN',
              message: 'Cannot deactivate or delete all tenant admins',
            },
          });
        }
      }
    }
    
    let result;
    let message;
    
    // Perform the requested action
    switch (action) {
      case 'activate':
        result = await prisma.user.updateMany({
          where: {
            id: { in: userIds },
          },
          data: {
            status: 'active',
          },
        });
        message = `${result.count} users activated successfully`;
        break;
        
      case 'deactivate':
        result = await prisma.user.updateMany({
          where: {
            id: { in: userIds },
          },
          data: {
            status: 'inactive',
          },
        });
        message = `${result.count} users deactivated successfully`;
        break;
        
      case 'suspend':
        result = await prisma.user.updateMany({
          where: {
            id: { in: userIds },
          },
          data: {
            status: 'suspended',
          },
        });
        message = `${result.count} users suspended successfully`;
        break;
        
      case 'delete':
        result = await prisma.user.deleteMany({
          where: {
            id: { in: userIds },
          },
        });
        message = `${result.count} users deleted successfully`;
        break;
        
      case 'assign-roles':
        if (!data || !data.roles || !Array.isArray(data.roles) || data.roles.length === 0) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'INVALID_ROLES',
              message: 'Roles must be provided for assign-roles action',
            },
          });
        }
        
        result = await prisma.user.updateMany({
          where: {
            id: { in: userIds },
          },
          data: {
            roles: data.roles,
          },
        });
        message = `Roles assigned to ${result.count} users successfully`;
        break;
        
      default:
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_ACTION',
            message: 'Invalid action specified',
          },
        });
    }
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'BULK_USER_OPERATION',
      resourceType: 'User',
      description: `Bulk operation: ${action}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        action,
        userIds,
        data,
        affectedCount: result.count,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message,
        count: result.count,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/users/stats/overview
 * @desc Get user statistics overview
 * @access Private (requires users:list permission)
 */
router.get('/stats/overview', requirePermission(REQUIRED_PERMISSIONS.LIST), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prisma = req.tenantPrisma || req.prisma;
    
    // Get user counts by status
    const [
      totalUsers,
      activeUsers,
      inactiveUsers,
      suspendedUsers,
      unverifiedUsers,
      newUsersThisMonth,
      activeUsersLast30Days,
    ] = await Promise.all([
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
        },
      }),
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          status: 'active',
        },
      }),
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          status: 'inactive',
        },
      }),
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          status: 'suspended',
        },
      }),
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          emailVerified: false,
        },
      }),
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          createdAt: {
            gte: DateTime.now().startOf('month').toJSDate(),
          },
        },
      }),
      prisma.user.count({
        where: {
          tenantId: req.auth?.tenantId,
          lastLoginAt: {
            gte: DateTime.now().minus({ days: 30 }).toJSDate(),
          },
        },
      }),
    ]);
    
    // Get user counts by role
    const usersByRole = await prisma.$queryRaw`
      SELECT unnest(roles) as role, COUNT(*) as count
      FROM "User"
      WHERE "tenantId" = ${req.auth?.tenantId || null}
      GROUP BY role
      ORDER BY count DESC
    `;
    
    // Get recent user activity
    const recentActivity = await prisma.auditLog.findMany({
      where: {
        tenantId: req.auth?.tenantId,
        action: {
          in: ['LOGIN_SUCCESS', 'USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'USER_STATUS_UPDATED'],
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
      take: 10,
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            avatar: true,
          },
        },
      },
    });
    
    // Return statistics
    return res.status(200).json({
      success: true,
      data: {
        counts: {
          total: totalUsers,
          active: activeUsers,
          inactive: inactiveUsers,
          suspended: suspendedUsers,
          unverified: unverifiedUsers,
          newThisMonth: newUsersThisMonth,
          activeLast30Days: activeUsersLast30Days,
        },
        byRole: usersByRole,
        recentActivity,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/users/roles
 * @desc Get available user roles
 * @access Private (requires users:list permission)
 */
router.get('/roles', requirePermission(REQUIRED_PERMISSIONS.LIST), async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Define available roles with descriptions
    const roles = [
      {
        id: 'SYSTEM_ADMIN',
        name: 'System Administrator',
        description: 'Full access to all system features and settings',
        permissions: ['*'],
      },
      {
        id: 'TENANT_ADMIN',
        name: 'Tenant Administrator',
        description: 'Full access to all tenant features and settings',
        permissions: ['*:*'],
      },
      {
        id: 'DOCTOR',
        name: 'Doctor',
        description: 'Medical practitioner who can manage appointments, patients, and medical records',
        permissions: [
          'appointments:*',
          'patients:*',
          'medical-records:*',
          'prescriptions:*',
          'lab-results:view',
        ],
      },
      {
        id: 'NURSE',
        name: 'Nurse',
        description: 'Assists doctors and manages patient care',
        permissions: [
          'appointments:view',
          'appointments:update',
          'patients:view',
          'patients:update',
          'medical-records:view',
          'medical-records:create',
          'medical-records:update',
          'vital-signs:*',
        ],
      },
      {
        id: 'RECEPTIONIST',
        name: 'Receptionist',
        description: 'Manages appointments and patient registration',
        permissions: [
          'appointments:*',
          'patients:view',
          'patients:create',
          'patients:update',
        ],
      },
      {
        id: 'PHARMACIST',
        name: 'Pharmacist',
        description: 'Manages medications and prescriptions',
        permissions: [
          'prescriptions:view',
          'prescriptions:update',
          'inventory:*',
        ],
      },
      {
        id: 'LAB_TECHNICIAN',
        name: 'Lab Technician',
        description: 'Manages lab tests and results',
        permissions: [
          'lab-results:*',
          'patients:view',
        ],
      },
      {
        id: 'ACCOUNTANT',
        name: 'Accountant',
        description: 'Manages billing and financial records',
        permissions: [
          'invoices:*',
          'payments:*',
          'reports:view',
        ],
      },
      {
        id: 'PATIENT',
        name: 'Patient',
        description: 'Patient with access to their own records',
        permissions: [
          'appointments:view-own',
          'appointments:create-own',
          'appointments:update-own',
          'medical-records:view-own',
          'prescriptions:view-own',
          'lab-results:view-own',
          'invoices:view-own',
          'payments:create-own',
        ],
      },
      {
        id: 'USER',
        name: 'Basic User',
        description: 'Basic user with minimal permissions',
        permissions: [
          'profile:view-own',
          'profile:update-own',
        ],
      },
    ];
    
    return res.status(200).json({
      success: true,
      data: {
        roles,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/users/permissions
 * @desc Get available permissions
 * @access Private (requires users:manage-permissions permission)
 */
router.get('/permissions', requirePermission(REQUIRED_PERMISSIONS.MANAGE_PERMISSIONS), async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Define available permissions grouped by module
    const permissions = [
      {
        module: 'users',
        description: 'User management',
        permissions: [
          { id: 'users:list', description: 'View list of users' },
          { id: 'users:view', description: 'View user details' },
          { id: 'users:create', description: 'Create new users' },
          { id: 'users:update', description: 'Update user details' },
          { id: 'users:delete', description: 'Delete users' },
          { id: 'users:manage-roles', description: 'Manage user roles' },
          { id: 'users:manage-permissions', description: 'Manage user permissions' },
          { id: 'users:bulk-operations', description: 'Perform bulk operations on users' },
        ],
      },
      {
        module: 'appointments',
        description: 'Appointment management',
        permissions: [
          { id: 'appointments:list', description: 'View list of appointments' },
          { id: 'appointments:view', description: 'View appointment details' },
          { id: 'appointments:create', description: 'Create new appointments' },
          { id: 'appointments:update', description: 'Update appointment details' },
          { id: 'appointments:delete', description: 'Delete appointments' },
          { id: 'appointments:view-own', description: 'View own appointments (for patients)' },
          { id: 'appointments:create-own', description: 'Create own appointments (for patients)' },
          { id: 'appointments:update-own', description: 'Update own appointments (for patients)' },
        ],
      },
      {
        module: 'patients',
        description: 'Patient management',
        permissions: [
          { id: 'patients:list', description: 'View list of patients' },
          { id: 'patients:view', description: 'View patient details' },
          { id: 'patients:create', description: 'Create new patients' },
          { id: 'patients:update', description: 'Update patient details' },
          { id: 'patients:delete', description: 'Delete patients' },
        ],
      },
      {
        module: 'medical-records',
        description: 'Medical record management',
        permissions: [
          { id: 'medical-records:list', description: 'View list of medical records' },
          { id: 'medical-records:view', description: 'View medical record details' },
          { id: 'medical-records:create', description: 'Create new medical records' },
          { id: 'medical-records:update', description: 'Update medical record details' },
          { id: 'medical-records:delete', description: 'Delete medical records' },
          { id: 'medical-records:view-own', description: 'View own medical records (for patients)' },
        ],
      },
      {
        module: 'prescriptions',
        description: 'Prescription management',
        permissions: [
          { id: 'prescriptions:list', description: 'View list of prescriptions' },
          { id: 'prescriptions:view', description: 'View prescription details' },
          { id: 'prescriptions:create', description: 'Create new prescriptions' },
          { id: 'prescriptions:update', description: 'Update prescription details' },
          { id: 'prescriptions:delete', description: 'Delete prescriptions' },
          { id: 'prescriptions:view-own', description: 'View own prescriptions (for patients)' },
        ],
      },
      {
        module: 'lab-results',
        description: 'Lab result management',
        permissions: [
          { id: 'lab-results:list', description: 'View list of lab results' },
          { id: 'lab-results:view', description: 'View lab result details' },
          { id: 'lab-results:create', description: 'Create new lab results' },
          { id: 'lab-results:update', description: 'Update lab result details' },
          { id: 'lab-results:delete', description: 'Delete lab results' },
          { id: 'lab-results:view-own', description: 'View own lab results (for patients)' },
        ],
      },
      {
        module: 'invoices',
        description: 'Invoice management',
        permissions: [
          { id: 'invoices:list', description: 'View list of invoices' },
          { id: 'invoices:view', description: 'View invoice details' },
          { id: 'invoices:create', description: 'Create new invoices' },
          { id: 'invoices:update', description: 'Update invoice details' },
          { id: 'invoices:delete', description: 'Delete invoices' },
          { id: 'invoices:view-own', description: 'View own invoices (for patients)' },
        ],
      },
      {
        module: 'payments',
        description: 'Payment management',
        permissions: [
          { id: 'payments:list', description: 'View list of payments' },
          { id: 'payments:view', description: 'View payment details' },
          { id: 'payments:create', description: 'Create new payments' },
          { id: 'payments:update', description: 'Update payment details' },
          { id: 'payments:delete', description: 'Delete payments' },
          { id: 'payments:create-own', description: 'Create own payments (for patients)' },
          { id: 'payments:view-own', description: 'View own payments (for patients)' },
        ],
      },
      {
        module: 'inventory',
        description: 'Inventory management',
        permissions: [
          { id: 'inventory:list', description: 'View list of inventory items' },
          { id: 'inventory:view', description: 'View inventory item details' },
          { id: 'inventory:create', description: 'Create new inventory items' },
          { id: 'inventory:update', description: 'Update inventory item details' },
          { id: 'inventory:delete', description: 'Delete inventory items' },
        ],
      },
      {
        module: 'reports',
        description: 'Report management',
        permissions: [
          { id: 'reports:view', description: 'View reports' },
          { id: 'reports:create', description: 'Create custom reports' },
          { id: 'reports:export', description: 'Export reports' },
        ],
      },
      {
        module: 'settings',
        description: 'System settings',
        permissions: [
          { id: 'settings:view', description: 'View system settings' },
          { id: 'settings:update', description: 'Update system settings' },
        ],
      },
      {
        module: 'profile',
        description: 'User profile',
        permissions: [
          { id: 'profile:view-own', description: 'View own profile' },
          { id: 'profile:update-own', description: 'Update own profile' },
        ],
      },
    ];
    
    return res.status(200).json({
      success: true,
      data: {
        permissions,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/users/activity/:id
 * @desc Get user activity log
 * @access Private (requires users:view permission)
 */
router.get('/activity/:id', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
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
    
    // Parse query parameters
    const page = parseInt(req.query.page as string || '1', 10);
    const limit = parseInt(req.query.limit as string || '20', 10);
    const skip = (page - 1) * limit;
    
    // Get user activity logs
    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where: {
          userId: id,
        },
        orderBy: {
          createdAt: 'desc',
        },
        skip,
        take: limit,
      }),
      prisma.auditLog.count({
        where: {
          userId: id,
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
