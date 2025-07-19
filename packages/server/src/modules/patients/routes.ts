/**
 * Patient Management Routes
 * 
 * This module handles all patient-related operations including:
 * - CRUD operations for patients
 * - Patient search with advanced filters
 * - Medical history management
 * - Vital signs tracking
 * - Allergy and immunization management
 * - File attachment handling
 * - Patient statistics and reports
 * - Patient timeline and activity
 * - Emergency contact management
 * - Insurance information handling
 */

import { Router, Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { DateTime } from 'luxon';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Create router
const router = Router();

// Environment variables
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const EMAIL_FROM = process.env.EMAIL_FROM || 'noreply@clinick.app';

// Get the directory name for file storage
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UPLOAD_DIR = path.join(__dirname, '../../../../data/uploads/patients');

// Create upload directory if it doesn't exist
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const patientId = req.params.id;
    const patientDir = path.join(UPLOAD_DIR, patientId);
    
    if (!fs.existsSync(patientDir)) {
      fs.mkdirSync(patientDir, { recursive: true });
    }
    
    cb(null, patientDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  },
});

const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  // Accept images, PDFs, and common document formats
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images, PDFs, and common document formats are allowed.'));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
  },
});

// Permission constants
const REQUIRED_PERMISSIONS = {
  LIST: ['patients:list'],
  VIEW: ['patients:view'],
  CREATE: ['patients:create'],
  UPDATE: ['patients:update'],
  DELETE: ['patients:delete'],
  MANAGE_MEDICAL_HISTORY: ['medical-records:create', 'medical-records:update'],
  VIEW_MEDICAL_HISTORY: ['medical-records:view'],
  MANAGE_VITAL_SIGNS: ['vital-signs:create', 'vital-signs:update'],
  VIEW_VITAL_SIGNS: ['vital-signs:view'],
  MANAGE_ALLERGIES: ['patients:update'],
  MANAGE_IMMUNIZATIONS: ['patients:update'],
  UPLOAD_FILES: ['patients:update'],
  VIEW_REPORTS: ['reports:view'],
  EXPORT_DATA: ['patients:export'],
};

// Validation schemas
const patientSchema = z.object({
  fileNumber: z.string().optional(),
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  dateOfBirth: z.string().refine((value) => !isNaN(Date.parse(value)), {
    message: 'Invalid date format',
  }),
  gender: z.enum(['male', 'female', 'other']),
  bloodType: z.enum(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'unknown']).optional(),
  nationalId: z.string().optional(),
  passportNumber: z.string().optional(),
  email: z.string().email('Invalid email format').optional(),
  phoneNumber: z.string().min(1, 'Phone number is required'),
  emergencyContact: z.string().optional(),
  address: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  country: z.string().optional(),
  postalCode: z.string().optional(),
  occupation: z.string().optional(),
  maritalStatus: z.enum(['single', 'married', 'divorced', 'widowed', 'other']).optional(),
  notes: z.string().optional(),
  insuranceProvider: z.string().optional(),
  insuranceNumber: z.string().optional(),
  insuranceExpiryDate: z.string().optional().refine((value) => !value || !isNaN(Date.parse(value)), {
    message: 'Invalid date format',
  }),
  status: z.enum(['active', 'inactive', 'deceased']).default('active'),
});

const updatePatientSchema = patientSchema.partial();

const vitalSignSchema = z.object({
  temperature: z.number().optional(),
  temperatureUnit: z.enum(['C', 'F']).default('C'),
  heartRate: z.number().int().optional(),
  bloodPressureSystolic: z.number().int().optional(),
  bloodPressureDiastolic: z.number().int().optional(),
  respiratoryRate: z.number().int().optional(),
  oxygenSaturation: z.number().int().optional(),
  height: z.number().optional(),
  heightUnit: z.enum(['cm', 'in']).default('cm'),
  weight: z.number().optional(),
  weightUnit: z.enum(['kg', 'lb']).default('kg'),
  bmi: z.number().optional(),
  pain: z.number().int().min(0).max(10).optional(),
  notes: z.string().optional(),
});

const allergySchema = z.object({
  allergen: z.string().min(1, 'Allergen is required'),
  reaction: z.string().min(1, 'Reaction is required'),
  severity: z.enum(['mild', 'moderate', 'severe']),
  diagnosedAt: z.string().optional().refine((value) => !value || !isNaN(Date.parse(value)), {
    message: 'Invalid date format',
  }),
  notes: z.string().optional(),
});

const immunizationSchema = z.object({
  vaccine: z.string().min(1, 'Vaccine is required'),
  doseNumber: z.number().int().min(1).default(1),
  administeredDate: z.string().refine((value) => !isNaN(Date.parse(value)), {
    message: 'Invalid date format',
  }),
  administeredBy: z.string().optional(),
  manufacturer: z.string().optional(),
  batchNumber: z.string().optional(),
  expirationDate: z.string().optional().refine((value) => !value || !isNaN(Date.parse(value)), {
    message: 'Invalid date format',
  }),
  site: z.string().optional(),
  route: z.string().optional(),
  notes: z.string().optional(),
});

const noteSchema = z.object({
  title: z.string().optional(),
  content: z.string().min(1, 'Content is required'),
  type: z.enum(['clinical', 'administrative', 'personal']),
  isPrivate: z.boolean().default(false),
});

const emergencyContactSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  relationship: z.string().min(1, 'Relationship is required'),
  phoneNumber: z.string().min(1, 'Phone number is required'),
  address: z.string().optional(),
  isEmergencyContact: z.boolean().default(true),
  notes: z.string().optional(),
});

const insuranceSchema = z.object({
  provider: z.string().min(1, 'Provider is required'),
  policyNumber: z.string().min(1, 'Policy number is required'),
  groupNumber: z.string().optional(),
  holderName: z.string().min(1, 'Holder name is required'),
  relationship: z.enum(['self', 'spouse', 'child', 'other']),
  expiryDate: z.string().refine((value) => !isNaN(Date.parse(value)), {
    message: 'Invalid date format',
  }),
  coverageDetails: z.string().optional(),
  notes: z.string().optional(),
});

const patientFilterSchema = z.object({
  search: z.string().optional(),
  status: z.enum(['active', 'inactive', 'deceased', 'all']).optional(),
  gender: z.enum(['male', 'female', 'other', 'all']).optional(),
  ageFrom: z.number().int().optional(),
  ageTo: z.number().int().optional(),
  bloodType: z.string().optional(),
  city: z.string().optional(),
  hasInsurance: z.boolean().optional(),
  lastVisitFrom: z.string().optional(),
  lastVisitTo: z.string().optional(),
  sortBy: z.enum(['firstName', 'lastName', 'dateOfBirth', 'registrationDate', 'lastVisitDate']).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().positive().optional(),
  limit: z.number().int().positive().optional(),
});

// Helper functions
const generateFileNumber = async (prisma: PrismaClient): Promise<string> => {
  const year = new Date().getFullYear().toString().substr(-2);
  const month = (new Date().getMonth() + 1).toString().padStart(2, '0');
  
  // Get the count of patients for this month
  const patientCount = await prisma.patient.count({
    where: {
      registrationDate: {
        gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
      },
    },
  });
  
  // Generate sequential number
  const sequentialNumber = (patientCount + 1).toString().padStart(4, '0');
  
  // Generate file number in format: P-YY-MM-XXXX
  return `P-${year}-${month}-${sequentialNumber}`;
};

const calculateBMI = (weight: number, height: number, weightUnit: string, heightUnit: string): number => {
  // Convert to kg and meters if needed
  const weightKg = weightUnit === 'lb' ? weight * 0.453592 : weight;
  const heightM = heightUnit === 'in' ? height * 0.0254 : height / 100;
  
  // Calculate BMI: weight (kg) / height^2 (m)
  return weightKg / (heightM * heightM);
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
  
  // Doctors have full access to their patients
  if (req.auth?.roles?.includes('DOCTOR')) {
    // For specific patient operations, we'll check if the patient is assigned to the doctor
    // This is handled in specific routes
    if (req.params.id && permissions.some(p => p.startsWith('patients:'))) {
      return true;
    }
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
 * @route GET /api/patients
 * @desc Get list of patients with filtering and pagination
 * @access Private (requires patients:list permission)
 */
router.get('/', requirePermission(REQUIRED_PERMISSIONS.LIST), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prisma = req.tenantPrisma || req.prisma;
    
    // Parse and validate query parameters
    const filters = patientFilterSchema.parse({
      search: req.query.search as string,
      status: req.query.status as string,
      gender: req.query.gender as string,
      ageFrom: req.query.ageFrom ? parseInt(req.query.ageFrom as string, 10) : undefined,
      ageTo: req.query.ageTo ? parseInt(req.query.ageTo as string, 10) : undefined,
      bloodType: req.query.bloodType as string,
      city: req.query.city as string,
      hasInsurance: req.query.hasInsurance ? req.query.hasInsurance === 'true' : undefined,
      lastVisitFrom: req.query.lastVisitFrom as string,
      lastVisitTo: req.query.lastVisitTo as string,
      sortBy: req.query.sortBy as string,
      sortOrder: req.query.sortOrder as string,
      page: req.query.page ? parseInt(req.query.page as string, 10) : 1,
      limit: req.query.limit ? parseInt(req.query.limit as string, 10) : 20,
    });
    
    const {
      search,
      status,
      gender,
      ageFrom,
      ageTo,
      bloodType,
      city,
      hasInsurance,
      lastVisitFrom,
      lastVisitTo,
      sortBy = 'lastName',
      sortOrder = 'asc',
      page = 1,
      limit = 20,
    } = filters;
    
    // Build where clause
    const where: any = {};
    
    // For doctors, only show their patients
    if (req.auth?.roles?.includes('DOCTOR') && !req.auth?.roles?.includes('TENANT_ADMIN')) {
      const doctorId = await prisma.doctor.findUnique({
        where: { userId: req.auth.sub },
        select: { id: true },
      });
      
      if (doctorId) {
        where.appointments = {
          some: {
            doctorId: doctorId.id,
          },
        };
      }
    }
    
    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { fileNumber: { contains: search, mode: 'insensitive' } },
        { nationalId: { contains: search, mode: 'insensitive' } },
        { phoneNumber: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
      ];
    }
    
    if (status && status !== 'all') {
      where.status = status;
    }
    
    if (gender && gender !== 'all') {
      where.gender = gender;
    }
    
    if (bloodType) {
      where.bloodType = bloodType;
    }
    
    if (city) {
      where.city = { contains: city, mode: 'insensitive' };
    }
    
    if (hasInsurance !== undefined) {
      if (hasInsurance) {
        where.insuranceProvider = { not: null };
        where.insuranceNumber = { not: null };
      } else {
        where.OR = [
          { insuranceProvider: null },
          { insuranceNumber: null },
        ];
      }
    }
    
    // Age filter
    if (ageFrom !== undefined || ageTo !== undefined) {
      const now = new Date();
      
      if (ageFrom !== undefined) {
        const oldestDate = new Date(now);
        oldestDate.setFullYear(oldestDate.getFullYear() - ageFrom);
        where.dateOfBirth = { ...(where.dateOfBirth || {}), lte: oldestDate };
      }
      
      if (ageTo !== undefined) {
        const youngestDate = new Date(now);
        youngestDate.setFullYear(youngestDate.getFullYear() - ageTo - 1);
        youngestDate.setDate(youngestDate.getDate() + 1);
        where.dateOfBirth = { ...(where.dateOfBirth || {}), gt: youngestDate };
      }
    }
    
    // Last visit filter
    if (lastVisitFrom || lastVisitTo) {
      where.lastVisitDate = {};
      
      if (lastVisitFrom) {
        where.lastVisitDate.gte = new Date(lastVisitFrom);
      }
      
      if (lastVisitTo) {
        const endDate = new Date(lastVisitTo);
        endDate.setHours(23, 59, 59, 999);
        where.lastVisitDate.lte = endDate;
      }
    }
    
    // Calculate pagination
    const skip = (page - 1) * limit;
    
    // Build order by
    const orderBy: any = {};
    orderBy[sortBy] = sortOrder;
    
    // Get patients with pagination
    const [patients, total] = await Promise.all([
      prisma.patient.findMany({
        where,
        select: {
          id: true,
          fileNumber: true,
          firstName: true,
          lastName: true,
          dateOfBirth: true,
          gender: true,
          bloodType: true,
          phoneNumber: true,
          email: true,
          city: true,
          country: true,
          registrationDate: true,
          lastVisitDate: true,
          insuranceProvider: true,
          status: true,
          _count: {
            select: {
              appointments: true,
              medicalRecords: true,
              prescriptions: true,
            },
          },
        },
        orderBy,
        skip,
        take: limit,
      }),
      prisma.patient.count({ where }),
    ]);
    
    // Calculate age for each patient
    const patientsWithAge = patients.map(patient => {
      const birthDate = new Date(patient.dateOfBirth);
      const today = new Date();
      let age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      
      if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        age--;
      }
      
      return {
        ...patient,
        age,
      };
    });
    
    // Return patients with pagination info
    return res.status(200).json({
      success: true,
      data: {
        patients: patientsWithAge,
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
 * @route GET /api/patients/:id
 * @desc Get patient by ID
 * @access Private (requires patients:view permission)
 */
router.get('/:id', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // For doctors, check if they have access to this patient
    if (req.auth?.roles?.includes('DOCTOR') && !req.auth?.roles?.includes('TENANT_ADMIN')) {
      const doctorId = await prisma.doctor.findUnique({
        where: { userId: req.auth.sub },
        select: { id: true },
      });
      
      if (doctorId) {
        const hasAccess = await prisma.appointment.findFirst({
          where: {
            patientId: id,
            doctorId: doctorId.id,
          },
        });
        
        if (!hasAccess) {
          return res.status(403).json({
            success: false,
            error: {
              code: 'FORBIDDEN',
              message: 'You do not have permission to view this patient',
            },
          });
        }
      }
    }
    
    // Get patient
    const patient = await prisma.patient.findUnique({
      where: { id },
      include: {
        appointments: {
          take: 5,
          orderBy: { startTime: 'desc' },
          include: {
            doctor: {
              include: {
                user: {
                  select: {
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            },
          },
        },
        medicalRecords: {
          take: 5,
          orderBy: { visitDate: 'desc' },
          include: {
            doctor: {
              include: {
                user: {
                  select: {
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            },
          },
        },
        prescriptions: {
          take: 5,
          orderBy: { prescriptionDate: 'desc' },
          include: {
            doctor: {
              include: {
                user: {
                  select: {
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            },
            medications: true,
          },
        },
        vitalSigns: {
          take: 10,
          orderBy: { recordedAt: 'desc' },
        },
        allergies: {
          orderBy: { allergen: 'asc' },
        },
        immunizations: {
          orderBy: { administeredDate: 'desc' },
        },
        labResults: {
          take: 5,
          orderBy: { testDate: 'desc' },
        },
        invoices: {
          take: 5,
          orderBy: { issueDate: 'desc' },
        },
        notes: {
          take: 10,
          orderBy: { createdAt: 'desc' },
          include: {
            createdBy: {
              select: {
                firstName: true,
                lastName: true,
              },
            },
          },
        },
        _count: {
          select: {
            appointments: true,
            medicalRecords: true,
            prescriptions: true,
            vitalSigns: true,
            allergies: true,
            immunizations: true,
            labResults: true,
            invoices: true,
            notes: true,
          },
        },
      },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Calculate age
    const birthDate = new Date(patient.dateOfBirth);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    
    // Get attachments
    const attachments = await prisma.attachment.findMany({
      where: {
        OR: [
          { medicalRecord: { patientId: id } },
          { labResult: { patientId: id } },
        ],
      },
      orderBy: { uploadedAt: 'desc' },
      take: 10,
    });
    
    // Create audit log for patient view
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'PATIENT_VIEWED',
      resourceType: 'Patient',
      resourceId: id,
      description: `Patient ${patient.fileNumber} viewed`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Return patient with additional data
    return res.status(200).json({
      success: true,
      data: {
        patient: {
          ...patient,
          age,
        },
        attachments,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/patients
 * @desc Create a new patient
 * @access Private (requires patients:create permission)
 */
router.post('/', requirePermission(REQUIRED_PERMISSIONS.CREATE), validateRequest(patientSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prisma = req.tenantPrisma || req.prisma;
    
    // Generate file number if not provided
    if (!req.body.fileNumber) {
      req.body.fileNumber = await generateFileNumber(prisma);
    } else {
      // Check if file number is already in use
      const existingPatient = await prisma.patient.findUnique({
        where: { fileNumber: req.body.fileNumber },
      });
      
      if (existingPatient) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'FILE_NUMBER_IN_USE',
            message: 'File number is already in use',
          },
        });
      }
    }
    
    // Check if national ID is already in use (if provided)
    if (req.body.nationalId) {
      const existingPatient = await prisma.patient.findFirst({
        where: { nationalId: req.body.nationalId },
      });
      
      if (existingPatient) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'NATIONAL_ID_IN_USE',
            message: 'National ID is already in use',
          },
        });
      }
    }
    
    // Parse dates
    const dateOfBirth = new Date(req.body.dateOfBirth);
    const insuranceExpiryDate = req.body.insuranceExpiryDate ? new Date(req.body.insuranceExpiryDate) : undefined;
    
    // Create patient
    const patient = await prisma.patient.create({
      data: {
        fileNumber: req.body.fileNumber,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        dateOfBirth,
        gender: req.body.gender,
        bloodType: req.body.bloodType,
        nationalId: req.body.nationalId,
        passportNumber: req.body.passportNumber,
        email: req.body.email,
        phoneNumber: req.body.phoneNumber,
        emergencyContact: req.body.emergencyContact,
        address: req.body.address,
        city: req.body.city,
        state: req.body.state,
        country: req.body.country,
        postalCode: req.body.postalCode,
        occupation: req.body.occupation,
        maritalStatus: req.body.maritalStatus,
        insuranceProvider: req.body.insuranceProvider,
        insuranceNumber: req.body.insuranceNumber,
        insuranceExpiryDate,
        notes: req.body.notes,
        status: req.body.status,
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'PATIENT_CREATED',
      resourceType: 'Patient',
      resourceId: patient.id,
      description: `Patient ${patient.fileNumber} created`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    return res.status(201).json({
      success: true,
      data: {
        patient,
        message: 'Patient created successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route PUT /api/patients/:id
 * @desc Update a patient
 * @access Private (requires patients:update permission)
 */
router.put('/:id', requirePermission(REQUIRED_PERMISSIONS.UPDATE), validateRequest(updatePatientSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const existingPatient = await prisma.patient.findUnique({
      where: { id },
    });
    
    if (!existingPatient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Check if file number is already in use (if changing)
    if (req.body.fileNumber && req.body.fileNumber !== existingPatient.fileNumber) {
      const fileNumberExists = await prisma.patient.findUnique({
        where: { fileNumber: req.body.fileNumber },
      });
      
      if (fileNumberExists) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'FILE_NUMBER_IN_USE',
            message: 'File number is already in use',
          },
        });
      }
    }
    
    // Check if national ID is already in use (if changing)
    if (req.body.nationalId && req.body.nationalId !== existingPatient.nationalId) {
      const nationalIdExists = await prisma.patient.findFirst({
        where: {
          nationalId: req.body.nationalId,
          id: { not: id },
        },
      });
      
      if (nationalIdExists) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'NATIONAL_ID_IN_USE',
            message: 'National ID is already in use',
          },
        });
      }
    }
    
    // Prepare update data
    const updateData: any = { ...req.body };
    
    // Parse dates if provided
    if (updateData.dateOfBirth) {
      updateData.dateOfBirth = new Date(updateData.dateOfBirth);
    }
    
    if (updateData.insuranceExpiryDate) {
      updateData.insuranceExpiryDate = new Date(updateData.insuranceExpiryDate);
    }
    
    // Update patient
    const updatedPatient = await prisma.patient.update({
      where: { id },
      data: updateData,
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'PATIENT_UPDATED',
      resourceType: 'Patient',
      resourceId: id,
      description: `Patient ${updatedPatient.fileNumber} updated`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        changes: req.body,
      },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        patient: updatedPatient,
        message: 'Patient updated successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/patients/:id
 * @desc Delete a patient
 * @access Private (requires patients:delete permission)
 */
router.delete('/:id', requirePermission(REQUIRED_PERMISSIONS.DELETE), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const existingPatient = await prisma.patient.findUnique({
      where: { id },
      select: {
        id: true,
        fileNumber: true,
        firstName: true,
        lastName: true,
        _count: {
          select: {
            appointments: true,
            medicalRecords: true,
            prescriptions: true,
            invoices: true,
          },
        },
      },
    });
    
    if (!existingPatient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Check if patient has related records
    const hasRelatedRecords = 
      existingPatient._count.appointments > 0 ||
      existingPatient._count.medicalRecords > 0 ||
      existingPatient._count.prescriptions > 0 ||
      existingPatient._count.invoices > 0;
    
    if (hasRelatedRecords) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'PATIENT_HAS_RELATED_RECORDS',
          message: 'Patient has related records and cannot be deleted',
          details: {
            appointments: existingPatient._count.appointments,
            medicalRecords: existingPatient._count.medicalRecords,
            prescriptions: existingPatient._count.prescriptions,
            invoices: existingPatient._count.invoices,
          },
        },
      });
    }
    
    // Create audit log before deletion
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'PATIENT_DELETED',
      resourceType: 'Patient',
      resourceId: id,
      description: `Patient ${existingPatient.fileNumber} (${existingPatient.firstName} ${existingPatient.lastName}) deleted`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Delete patient
    await prisma.patient.delete({
      where: { id },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'Patient deleted successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/patients/:id/vital-signs
 * @desc Add vital signs for a patient
 * @access Private (requires vital-signs:create permission)
 */
router.post('/:id/vital-signs', requirePermission(REQUIRED_PERMISSIONS.MANAGE_VITAL_SIGNS), validateRequest(vitalSignSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true, fileNumber: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Calculate BMI if height and weight are provided
    let bmi = req.body.bmi;
    if (!bmi && req.body.height && req.body.weight) {
      bmi = calculateBMI(
        req.body.weight,
        req.body.height,
        req.body.weightUnit || 'kg',
        req.body.heightUnit || 'cm'
      );
    }
    
    // Create vital signs record
    const vitalSigns = await prisma.vitalSign.create({
      data: {
        patientId: id,
        temperature: req.body.temperature,
        temperatureUnit: req.body.temperatureUnit,
        heartRate: req.body.heartRate,
        bloodPressureSystolic: req.body.bloodPressureSystolic,
        bloodPressureDiastolic: req.body.bloodPressureDiastolic,
        respiratoryRate: req.body.respiratoryRate,
        oxygenSaturation: req.body.oxygenSaturation,
        height: req.body.height,
        heightUnit: req.body.heightUnit,
        weight: req.body.weight,
        weightUnit: req.body.weightUnit,
        bmi,
        pain: req.body.pain,
        notes: req.body.notes,
      },
    });
    
    // Update patient's last visit date
    await prisma.patient.update({
      where: { id },
      data: {
        lastVisitDate: new Date(),
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'VITAL_SIGNS_RECORDED',
      resourceType: 'VitalSign',
      resourceId: vitalSigns.id,
      description: `Vital signs recorded for patient ${patient.fileNumber}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    return res.status(201).json({
      success: true,
      data: {
        vitalSigns,
        message: 'Vital signs recorded successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/patients/:id/vital-signs
 * @desc Get vital signs for a patient
 * @access Private (requires vital-signs:view permission)
 */
router.get('/:id/vital-signs', requirePermission(REQUIRED_PERMISSIONS.VIEW_VITAL_SIGNS), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Parse query parameters
    const limit = parseInt(req.query.limit as string || '20', 10);
    const page = parseInt(req.query.page as string || '1', 10);
    const skip = (page - 1) * limit;
    
    // Get vital signs with pagination
    const [vitalSigns, total] = await Promise.all([
      prisma.vitalSign.findMany({
        where: { patientId: id },
        orderBy: { recordedAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.vitalSign.count({
        where: { patientId: id },
      }),
    ]);
    
    return res.status(200).json({
      success: true,
      data: {
        vitalSigns,
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
 * @route POST /api/patients/:id/allergies
 * @desc Add allergy for a patient
 * @access Private (requires patients:update permission)
 */
router.post('/:id/allergies', requirePermission(REQUIRED_PERMISSIONS.MANAGE_ALLERGIES), validateRequest(allergySchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true, fileNumber: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Check if allergy already exists
    const existingAllergy = await prisma.allergy.findFirst({
      where: {
        patientId: id,
        allergen: req.body.allergen,
      },
    });
    
    if (existingAllergy) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'ALLERGY_ALREADY_EXISTS',
          message: 'This allergy is already recorded for the patient',
        },
      });
    }
    
    // Parse diagnosed date if provided
    const diagnosedAt = req.body.diagnosedAt ? new Date(req.body.diagnosedAt) : undefined;
    
    // Create allergy record
    const allergy = await prisma.allergy.create({
      data: {
        patientId: id,
        allergen: req.body.allergen,
        reaction: req.body.reaction,
        severity: req.body.severity,
        diagnosedAt,
        notes: req.body.notes,
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'ALLERGY_RECORDED',
      resourceType: 'Allergy',
      resourceId: allergy.id,
      description: `Allergy to ${allergy.allergen} recorded for patient ${patient.fileNumber}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    return res.status(201).json({
      success: true,
      data: {
        allergy,
        message: 'Allergy recorded successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/patients/:id/allergies
 * @desc Get allergies for a patient
 * @access Private (requires patients:view permission)
 */
router.get('/:id/allergies', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Get allergies
    const allergies = await prisma.allergy.findMany({
      where: { patientId: id },
      orderBy: [
        { severity: 'desc' },
        { allergen: 'asc' },
      ],
    });
    
    return res.status(200).json({
      success: true,
      data: {
        allergies,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/patients/:patientId/allergies/:id
 * @desc Delete an allergy record
 * @access Private (requires patients:update permission)
 */
router.delete('/:patientId/allergies/:id', requirePermission(REQUIRED_PERMISSIONS.MANAGE_ALLERGIES), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { patientId, id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if allergy exists
    const allergy = await prisma.allergy.findFirst({
      where: {
        id,
        patientId,
      },
    });
    
    if (!allergy) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'ALLERGY_NOT_FOUND',
          message: 'Allergy not found',
        },
      });
    }
    
    // Create audit log before deletion
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'ALLERGY_DELETED',
      resourceType: 'Allergy',
      resourceId: id,
      description: `Allergy to ${allergy.allergen} deleted for patient`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Delete allergy
    await prisma.allergy.delete({
      where: { id },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'Allergy deleted successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/patients/:id/immunizations
 * @desc Add immunization for a patient
 * @access Private (requires patients:update permission)
 */
router.post('/:id/immunizations', requirePermission(REQUIRED_PERMISSIONS.MANAGE_IMMUNIZATIONS), validateRequest(immunizationSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true, fileNumber: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Parse dates
    const administeredDate = new Date(req.body.administeredDate);
    const expirationDate = req.body.expirationDate ? new Date(req.body.expirationDate) : undefined;
    
    // Create immunization record
    const immunization = await prisma.immunization.create({
      data: {
        patientId: id,
        vaccine: req.body.vaccine,
        doseNumber: req.body.doseNumber,
        administeredDate,
        administeredBy: req.body.administeredBy,
        manufacturer: req.body.manufacturer,
        batchNumber: req.body.batchNumber,
        expirationDate,
        site: req.body.site,
        route: req.body.route,
        notes: req.body.notes,
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'IMMUNIZATION_RECORDED',
      resourceType: 'Immunization',
      resourceId: immunization.id,
      description: `Immunization (${immunization.vaccine}) recorded for patient ${patient.fileNumber}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    return res.status(201).json({
      success: true,
      data: {
        immunization,
        message: 'Immunization recorded successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/patients/:id/immunizations
 * @desc Get immunizations for a patient
 * @access Private (requires patients:view permission)
 */
router.get('/:id/immunizations', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Get immunizations
    const immunizations = await prisma.immunization.findMany({
      where: { patientId: id },
      orderBy: [
        { vaccine: 'asc' },
        { administeredDate: 'desc' },
      ],
    });
    
    return res.status(200).json({
      success: true,
      data: {
        immunizations,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/patients/:patientId/immunizations/:id
 * @desc Delete an immunization record
 * @access Private (requires patients:update permission)
 */
router.delete('/:patientId/immunizations/:id', requirePermission(REQUIRED_PERMISSIONS.MANAGE_IMMUNIZATIONS), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { patientId, id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if immunization exists
    const immunization = await prisma.immunization.findFirst({
      where: {
        id,
        patientId,
      },
    });
    
    if (!immunization) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'IMMUNIZATION_NOT_FOUND',
          message: 'Immunization not found',
        },
      });
    }
    
    // Create audit log before deletion
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'IMMUNIZATION_DELETED',
      resourceType: 'Immunization',
      resourceId: id,
      description: `Immunization (${immunization.vaccine}) deleted for patient`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Delete immunization
    await prisma.immunization.delete({
      where: { id },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'Immunization deleted successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/patients/:id/notes
 * @desc Add a note for a patient
 * @access Private (requires patients:update permission)
 */
router.post('/:id/notes', requirePermission(REQUIRED_PERMISSIONS.UPDATE), validateRequest(noteSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true, fileNumber: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Create note
    const note = await prisma.note.create({
      data: {
        patientId: id,
        title: req.body.title,
        content: req.body.content,
        type: req.body.type,
        isPrivate: req.body.isPrivate,
        createdById: req.auth?.sub || '',
      },
      include: {
        createdBy: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'NOTE_CREATED',
      resourceType: 'Note',
      resourceId: note.id,
      description: `Note created for patient ${patient.fileNumber}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    return res.status(201).json({
      success: true,
      data: {
        note,
        message: 'Note created successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/patients/:id/notes
 * @desc Get notes for a patient
 * @access Private (requires patients:view permission)
 */
router.get('/:id/notes', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Parse query parameters
    const limit = parseInt(req.query.limit as string || '20', 10);
    const page = parseInt(req.query.page as string || '1', 10);
    const skip = (page - 1) * limit;
    const type = req.query.type as string;
    
    // Build where clause
    const where: any = { patientId: id };
    
    if (type) {
      where.type = type;
    }
    
    // For non-admin users, don't show private notes unless they created them
    if (!req.auth?.roles?.includes('TENANT_ADMIN') && !req.auth?.roles?.includes('SYSTEM_ADMIN')) {
      where.OR = [
        { isPrivate: false },
        { isPrivate: true, createdById: req.auth?.sub },
      ];
    }
    
    // Get notes with pagination
    const [notes, total] = await Promise.all([
      prisma.note.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          createdBy: {
            select: {
              firstName: true,
              lastName: true,
            },
          },
        },
      }),
      prisma.note.count({ where }),
    ]);
    
    return res.status(200).json({
      success: true,
      data: {
        notes,
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
 * @route DELETE /api/patients/:patientId/notes/:id
 * @desc Delete a note
 * @access Private (requires patients:update permission)
 */
router.delete('/:patientId/notes/:id', requirePermission(REQUIRED_PERMISSIONS.UPDATE), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { patientId, id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if note exists
    const note = await prisma.note.findFirst({
      where: {
        id,
        patientId,
      },
    });
    
    if (!note) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOTE_NOT_FOUND',
          message: 'Note not found',
        },
      });
    }
    
    // Only allow deletion if user is admin or the creator of the note
    if (
      !req.auth?.roles?.includes('TENANT_ADMIN') &&
      !req.auth?.roles?.includes('SYSTEM_ADMIN') &&
      note.createdById !== req.auth?.sub
    ) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'You do not have permission to delete this note',
        },
      });
    }
    
    // Create audit log before deletion
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'NOTE_DELETED',
      resourceType: 'Note',
      resourceId: id,
      description: `Note deleted for patient`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Delete note
    await prisma.note.delete({
      where: { id },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'Note deleted successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route POST /api/patients/:id/upload
 * @desc Upload files for a patient
 * @access Private (requires patients:update permission)
 */
router.post('/:id/upload', requirePermission(REQUIRED_PERMISSIONS.UPLOAD_FILES), upload.array('files', 5), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    const files = req.files as Express.Multer.File[];
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true, fileNumber: true },
    });
    
    if (!patient) {
      // Remove uploaded files if patient doesn't exist
      files.forEach(file => {
        fs.unlinkSync(file.path);
      });
      
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Get or create medical record for attachments
    const recordType = req.body.recordType || 'medical-record';
    const recordId = req.body.recordId;
    
    let medicalRecordId: string | null = null;
    let labResultId: string | null = null;
    
    if (recordType === 'medical-record') {
      if (recordId) {
        // Check if medical record exists and belongs to this patient
        const medicalRecord = await prisma.medicalRecord.findFirst({
          where: {
            id: recordId,
            patientId: id,
          },
        });
        
        if (!medicalRecord) {
          // Remove uploaded files if record doesn't exist
          files.forEach(file => {
            fs.unlinkSync(file.path);
          });
          
          return res.status(404).json({
            success: false,
            error: {
              code: 'MEDICAL_RECORD_NOT_FOUND',
              message: 'Medical record not found',
            },
          });
        }
        
        medicalRecordId = recordId;
      } else {
        // Create a new medical record for these attachments
        const doctorId = await prisma.doctor.findFirst({
          where: {
            userId: req.auth?.sub,
          },
          select: { id: true },
        });
        
        if (!doctorId) {
          // Remove uploaded files if doctor doesn't exist
          files.forEach(file => {
            fs.unlinkSync(file.path);
          });
          
          return res.status(400).json({
            success: false,
            error: {
              code: 'DOCTOR_REQUIRED',
              message: 'A doctor is required to create a medical record',
            },
          });
        }
        
        const newMedicalRecord = await prisma.medicalRecord.create({
          data: {
            patientId: id,
            doctorId: doctorId.id,
            chiefComplaint: req.body.description || 'File upload',
            diagnosis: [],
            notes: req.body.notes,
          },
        });
        
        medicalRecordId = newMedicalRecord.id;
      }
    } else if (recordType === 'lab-result') {
      if (recordId) {
        // Check if lab result exists and belongs to this patient
        const labResult = await prisma.labResult.findFirst({
          where: {
            id: recordId,
            patientId: id,
          },
        });
        
        if (!labResult) {
          // Remove uploaded files if record doesn't exist
          files.forEach(file => {
            fs.unlinkSync(file.path);
          });
          
          return res.status(404).json({
            success: false,
            error: {
              code: 'LAB_RESULT_NOT_FOUND',
              message: 'Lab result not found',
            },
          });
        }
        
        labResultId = recordId;
      } else {
        // Create a new lab result for these attachments
        const newLabResult = await prisma.labResult.create({
          data: {
            patientId: id,
            testName: req.body.testName || 'File upload',
            testDate: new Date(),
            status: 'pending',
            notes: req.body.notes,
          },
        });
        
        labResultId = newLabResult.id;
      }
    }
    
    // Create attachment records
    const attachments = [];
    
    for (const file of files) {
      const attachment = await prisma.attachment.create({
        data: {
          fileName: file.originalname,
          fileType: path.extname(file.originalname).substring(1),
          fileSize: file.size,
          filePath: file.path,
          contentType: file.mimetype,
          description: req.body.description,
          uploadedById: req.auth?.sub,
          medicalRecordId,
          labResultId,
        },
      });
      
      attachments.push(attachment);
    }
    
    // Update patient's last visit date
    await prisma.patient.update({
      where: { id },
      data: {
        lastVisitDate: new Date(),
      },
    });
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'FILES_UPLOADED',
      resourceType: recordType === 'medical-record' ? 'MedicalRecord' : 'LabResult',
      resourceId: recordType === 'medical-record' ? medicalRecordId || undefined : labResultId || undefined,
      description: `${files.length} files uploaded for patient ${patient.fileNumber}`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: {
        fileCount: files.length,
        fileNames: files.map(f => f.originalname),
      },
    });
    
    return res.status(201).json({
      success: true,
      data: {
        attachments,
        message: `${files.length} files uploaded successfully`,
      },
    });
  } catch (error) {
    // Handle multer errors
    if (error instanceof multer.MulterError) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'FILE_UPLOAD_ERROR',
          message: error.message,
        },
      });
    }
    
    next(error);
  }
});

/**
 * @route GET /api/patients/:id/attachments
 * @desc Get attachments for a patient
 * @access Private (requires patients:view permission)
 */
router.get('/:id/attachments', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Parse query parameters
    const limit = parseInt(req.query.limit as string || '20', 10);
    const page = parseInt(req.query.page as string || '1', 10);
    const skip = (page - 1) * limit;
    const fileType = req.query.fileType as string;
    
    // Build where clause
    let where: any = {
      OR: [
        { medicalRecord: { patientId: id } },
        { labResult: { patientId: id } },
      ],
    };
    
    if (fileType) {
      where = {
        ...where,
        fileType: { contains: fileType, mode: 'insensitive' },
      };
    }
    
    // Get attachments with pagination
    const [attachments, total] = await Promise.all([
      prisma.attachment.findMany({
        where,
        orderBy: { uploadedAt: 'desc' },
        skip,
        take: limit,
        include: {
          medicalRecord: {
            select: {
              id: true,
              visitDate: true,
              diagnosis: true,
            },
          },
          labResult: {
            select: {
              id: true,
              testName: true,
              testDate: true,
              status: true,
            },
          },
        },
      }),
      prisma.attachment.count({ where }),
    ]);
    
    return res.status(200).json({
      success: true,
      data: {
        attachments,
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
 * @route GET /api/patients/:id/attachments/:attachmentId
 * @desc Download an attachment
 * @access Private (requires patients:view permission)
 */
router.get('/:id/attachments/:attachmentId', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id, attachmentId } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Get attachment
    const attachment = await prisma.attachment.findFirst({
      where: {
        id: attachmentId,
        OR: [
          { medicalRecord: { patientId: id } },
          { labResult: { patientId: id } },
        ],
      },
    });
    
    if (!attachment) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'ATTACHMENT_NOT_FOUND',
          message: 'Attachment not found',
        },
      });
    }
    
    // Check if file exists
    if (!fs.existsSync(attachment.filePath)) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'FILE_NOT_FOUND',
          message: 'File not found on server',
        },
      });
    }
    
    // Create audit log
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'FILE_DOWNLOADED',
      resourceType: 'Attachment',
      resourceId: attachmentId,
      description: `File ${attachment.fileName} downloaded for patient`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Set content disposition and type
    res.setHeader('Content-Disposition', `attachment; filename="${attachment.fileName}"`);
    res.setHeader('Content-Type', attachment.contentType);
    
    // Stream the file
    const fileStream = fs.createReadStream(attachment.filePath);
    fileStream.pipe(res);
  } catch (error) {
    next(error);
  }
});

/**
 * @route DELETE /api/patients/:id/attachments/:attachmentId
 * @desc Delete an attachment
 * @access Private (requires patients:update permission)
 */
router.delete('/:id/attachments/:attachmentId', requirePermission(REQUIRED_PERMISSIONS.UPLOAD_FILES), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id, attachmentId } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if attachment exists and belongs to the patient
    const attachment = await prisma.attachment.findFirst({
      where: {
        id: attachmentId,
        OR: [
          { medicalRecord: { patientId: id } },
          { labResult: { patientId: id } },
        ],
      },
    });
    
    if (!attachment) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'ATTACHMENT_NOT_FOUND',
          message: 'Attachment not found',
        },
      });
    }
    
    // Create audit log before deletion
    await createAuditLog(prisma, {
      userId: req.auth?.sub || '',
      tenantId: req.auth?.tenantId,
      action: 'ATTACHMENT_DELETED',
      resourceType: 'Attachment',
      resourceId: attachmentId,
      description: `Attachment ${attachment.fileName} deleted`,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
    
    // Delete file from disk if it exists
    if (fs.existsSync(attachment.filePath)) {
      fs.unlinkSync(attachment.filePath);
    }
    
    // Delete attachment record
    await prisma.attachment.delete({
      where: { id: attachmentId },
    });
    
    return res.status(200).json({
      success: true,
      data: {
        message: 'Attachment deleted successfully',
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @route GET /api/patients/:id/timeline
 * @desc Get patient timeline
 * @access Private (requires patients:view permission)
 */
router.get('/:id/timeline', requirePermission(REQUIRED_PERMISSIONS.VIEW), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    const prisma = req.tenantPrisma || req.prisma;
    
    // Check if patient exists
    const patient = await prisma.patient.findUnique({
      where: { id },
      select: { id: true },
    });
    
    if (!patient) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'PATIENT_NOT_FOUND',
          message: 'Patient not found',
        },
      });
    }
    
    // Parse query parameters
    const limit = parseInt(req.query.limit as string || '50', 10);
    const page = parseInt(req.query.page as string || '1', 10);
    const skip = (page - 1) * limit;
    
    // Get all timeline events
    const [
      appointments,
      medicalRecords,
      prescriptions,
      labResults,
      vitalSigns,
      immunizations,
      invoices,
      payments,
      notes,
    ] = await Promise.all([
      prisma.appointment.findMany({
        where: { patientId: id },
        select: {
          id: true,
          startTime: true,
          endTime: true,
          status: true,
          type: true,
          title: true,
          doctor: {
            select: {
              user: {
                select: {
                  firstName: true,
                  lastName: true,
                },
              },
            },
          },
          createdAt: true,
        },
        orderBy: { startTime: 'desc' },
        take: 20,
      }),
      prisma.medicalRecord.findMany({
        where: { patientId: id },
        select: {
          id: true,
          visitDate: true,
          chiefComplaint: true,
          diagnosis: true,
          doctor: {
            select: {
              user: {
                select: {
                  firstName: true,
                  lastName: true,