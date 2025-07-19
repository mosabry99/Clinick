/**
 * Core type definitions for Clinick Medical Clinic Management System
 * 
 * This file contains all the core TypeScript type definitions used throughout the application.
 * Types are organized by domain and functionality.
 */

// =============================================================================
// Common/Utility Types
// =============================================================================

/**
 * Base entity interface with common properties for all database entities
 */
export interface BaseEntity {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Standard API response format
 */
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    totalPages?: number;
  };
}

/**
 * Pagination parameters for list requests
 */
export interface PaginationParams {
  page: number;
  limit: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Filter parameters for list requests
 */
export interface FilterParams {
  search?: string;
  startDate?: Date | string;
  endDate?: Date | string;
  status?: string;
  [key: string]: any;
}

/**
 * Contact information
 */
export interface ContactInfo {
  email: string;
  phone: string;
  alternatePhone?: string;
  address?: Address;
}

/**
 * Physical address
 */
export interface Address {
  street: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  coordinates?: {
    latitude: number;
    longitude: number;
  };
}

/**
 * Audit log entry
 */
export interface AuditLogEntry extends BaseEntity {
  userId: string;
  action: string;
  entityType: string;
  entityId: string;
  details: any;
  ipAddress: string;
  userAgent: string;
}

// =============================================================================
// Authentication & Authorization Types
// =============================================================================

/**
 * Available user roles in the system
 */
export enum UserRole {
  SUPER_ADMIN = 'SUPER_ADMIN',
  TENANT_ADMIN = 'TENANT_ADMIN',
  DOCTOR = 'DOCTOR',
  NURSE = 'NURSE',
  RECEPTIONIST = 'RECEPTIONIST',
  PHARMACIST = 'PHARMACIST',
  LAB_TECHNICIAN = 'LAB_TECHNICIAN',
  ACCOUNTANT = 'ACCOUNTANT',
  PATIENT = 'PATIENT',
}

/**
 * Permission definition
 */
export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'manage';
}

/**
 * Role definition with associated permissions
 */
export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: Permission[];
  isDefault?: boolean;
  isSystem?: boolean;
}

/**
 * JWT token payload structure
 */
export interface JwtPayload {
  sub: string; // User ID
  email: string;
  roles: UserRole[];
  permissions: string[];
  tenantId: string;
  exp: number; // Expiration timestamp
  iat: number; // Issued at timestamp
  licenseId?: string;
}

/**
 * Authentication credentials for login
 */
export interface AuthCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

/**
 * Authentication response after successful login
 */
export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: UserBasic;
  expiresAt: number;
}

/**
 * License information
 */
export interface License {
  id: string;
  key: string;
  type: 'trial' | 'basic' | 'professional' | 'enterprise';
  status: 'active' | 'expired' | 'suspended' | 'cancelled';
  features: string[];
  maxUsers: number;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  tenantId: string;
  paymentId?: string;
}

// =============================================================================
// User Types
// =============================================================================

/**
 * Basic user information
 */
export interface UserBasic {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  displayName: string;
  avatar?: string;
  roles: UserRole[];
  isActive: boolean;
  tenantId: string;
  lastLoginAt?: Date;
}

/**
 * Complete user profile
 */
export interface User extends UserBasic, BaseEntity {
  phone?: string;
  dateOfBirth?: Date;
  gender?: 'male' | 'female' | 'other' | 'prefer_not_to_say';
  address?: Address;
  language: 'en' | 'ar';
  timezone: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  twoFactorEnabled: boolean;
  permissions: Permission[];
  metadata?: Record<string, any>;
}

/**
 * Staff member (extends User)
 */
export interface StaffMember extends User {
  staffId: string;
  department?: string;
  position: string;
  specialization?: string;
  qualification?: string;
  joinDate: Date;
  emergencyContact?: ContactInfo;
  schedule?: WorkSchedule;
  isAvailableForAppointments?: boolean;
}

/**
 * Doctor profile (extends StaffMember)
 */
export interface Doctor extends StaffMember {
  specialization: string;
  qualifications: string[];
  licenseNumber: string;
  licenseExpiryDate: Date;
  yearsOfExperience: number;
  consultationFee: number;
  followUpFee: number;
  biography?: string;
  languages: string[];
  averageRating?: number;
  totalReviews?: number;
}

/**
 * Patient profile
 */
export interface Patient extends User {
  patientId: string;
  bloodGroup?: 'A+' | 'A-' | 'B+' | 'B-' | 'AB+' | 'AB-' | 'O+' | 'O-';
  height?: number; // in cm
  weight?: number; // in kg
  allergies?: string[];
  chronicConditions?: string[];
  emergencyContact?: ContactInfo;
  insuranceInfo?: InsuranceInfo;
  primaryDoctorId?: string;
  registrationDate: Date;
  lastVisitDate?: Date;
  isArchived: boolean;
}

/**
 * Insurance information
 */
export interface InsuranceInfo {
  provider: string;
  policyNumber: string;
  groupNumber?: string;
  holderName: string;
  relationship?: 'self' | 'spouse' | 'child' | 'other';
  expiryDate: Date;
  coverageDetails?: string;
  verificationStatus?: 'verified' | 'pending' | 'failed';
}

/**
 * Work schedule
 */
export interface WorkSchedule {
  monday?: DaySchedule;
  tuesday?: DaySchedule;
  wednesday?: DaySchedule;
  thursday?: DaySchedule;
  friday?: DaySchedule;
  saturday?: DaySchedule;
  sunday?: DaySchedule;
  exceptions?: ScheduleException[];
}

/**
 * Schedule for a specific day
 */
export interface DaySchedule {
  isWorkingDay: boolean;
  shifts: TimeSlot[];
}

/**
 * Time slot
 */
export interface TimeSlot {
  start: string; // HH:MM format (24-hour)
  end: string; // HH:MM format (24-hour)
}

/**
 * Exception to regular schedule (holidays, leave, etc.)
 */
export interface ScheduleException {
  date: Date;
  reason: string;
  isFullDay: boolean;
  timeSlots?: TimeSlot[]; // If not full day
}

// =============================================================================
// Appointment Types
// =============================================================================

/**
 * Appointment status
 */
export enum AppointmentStatus {
  SCHEDULED = 'scheduled',
  CONFIRMED = 'confirmed',
  CHECKED_IN = 'checked_in',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
  NO_SHOW = 'no_show',
  RESCHEDULED = 'rescheduled',
}

/**
 * Appointment type
 */
export enum AppointmentType {
  NEW_VISIT = 'new_visit',
  FOLLOW_UP = 'follow_up',
  CONSULTATION = 'consultation',
  PROCEDURE = 'procedure',
  CHECKUP = 'checkup',
  EMERGENCY = 'emergency',
  VACCINATION = 'vaccination',
  LAB_WORK = 'lab_work',
}

/**
 * Appointment information
 */
export interface Appointment extends BaseEntity {
  patientId: string;
  doctorId: string;
  scheduledAt: Date;
  endAt: Date;
  duration: number; // in minutes
  status: AppointmentStatus;
  type: AppointmentType;
  title: string;
  notes?: string;
  reason?: string;
  visitType: 'in_person' | 'telemedicine';
  reminderSent: boolean;
  cancellationReason?: string;
  cancelledBy?: string;
  rescheduledFrom?: string;
  checkInTime?: Date;
  checkOutTime?: Date;
  patient?: Patient;
  doctor?: Doctor;
  createdBy: string;
  tenantId: string;
}

/**
 * Appointment reminder
 */
export interface AppointmentReminder extends BaseEntity {
  appointmentId: string;
  patientId: string;
  reminderType: 'email' | 'sms' | 'push';
  scheduledFor: Date;
  sentAt?: Date;
  status: 'pending' | 'sent' | 'failed';
  failureReason?: string;
  tenantId: string;
}

// =============================================================================
// Medical Record Types
// =============================================================================

/**
 * Medical record entry
 */
export interface MedicalRecord extends BaseEntity {
  patientId: string;
  recordType: 'visit' | 'lab_result' | 'prescription' | 'procedure' | 'note' | 'document';
  title: string;
  description: string;
  appointmentId?: string;
  doctorId: string;
  attachments?: Attachment[];
  isConfidential: boolean;
  tags?: string[];
  tenantId: string;
}

/**
 * Visit/Encounter record
 */
export interface VisitRecord extends MedicalRecord {
  recordType: 'visit';
  chiefComplaint: string;
  vitalSigns: VitalSigns;
  symptoms: string[];
  diagnosis: Diagnosis[];
  treatment: string;
  followUpInstructions?: string;
  followUpDate?: Date;
  referrals?: Referral[];
}

/**
 * Vital signs
 */
export interface VitalSigns {
  temperature?: number; // in Celsius
  bloodPressureSystolic?: number; // in mmHg
  bloodPressureDiastolic?: number; // in mmHg
  heartRate?: number; // in BPM
  respiratoryRate?: number; // breaths per minute
  oxygenSaturation?: number; // percentage
  height?: number; // in cm
  weight?: number; // in kg
  bmi?: number; // calculated
  painLevel?: number; // 0-10 scale
  glucoseLevel?: number; // mg/dL
  recordedAt: Date;
}

/**
 * Diagnosis information
 */
export interface Diagnosis {
  code: string; // ICD-10 code
  name: string;
  description?: string;
  type: 'primary' | 'secondary' | 'differential';
  notes?: string;
}

/**
 * Referral to specialist
 */
export interface Referral {
  specialistType: string;
  reason: string;
  urgency: 'routine' | 'urgent' | 'emergency';
  notes?: string;
  status: 'pending' | 'completed' | 'cancelled';
}

/**
 * Prescription record
 */
export interface Prescription extends MedicalRecord {
  recordType: 'prescription';
  medications: Medication[];
  instructions: string;
  issuedDate: Date;
  expiryDate?: Date;
  status: 'draft' | 'active' | 'completed' | 'cancelled';
  refillable: boolean;
  refillCount?: number;
  refillsRemaining?: number;
  pharmacyNotes?: string;
}

/**
 * Medication information
 */
export interface Medication {
  name: string;
  dosage: string;
  frequency: string;
  route: 'oral' | 'topical' | 'intravenous' | 'intramuscular' | 'subcutaneous' | 'inhalation' | 'other';
  duration: string;
  quantity: number;
  instructions?: string;
  reason?: string;
  isControlled: boolean;
  inventoryItemId?: string;
}

/**
 * Lab result record
 */
export interface LabResult extends MedicalRecord {
  recordType: 'lab_result';
  testType: string;
  testDate: Date;
  results: LabTestResult[];
  labName?: string;
  labReferenceNumber?: string;
  orderedBy: string;
  reviewedBy?: string;
  reviewedAt?: Date;
  status: 'pending' | 'completed' | 'cancelled';
  notes?: string;
}

/**
 * Individual lab test result
 */
export interface LabTestResult {
  name: string;
  value: string | number;
  unit?: string;
  referenceRange?: string;
  isAbnormal: boolean;
  notes?: string;
}

/**
 * Document attachment
 */
export interface Attachment {
  id: string;
  fileName: string;
  fileType: string;
  fileSize: number; // in bytes
  url: string;
  thumbnailUrl?: string;
  uploadedAt: Date;
  uploadedBy: string;
  description?: string;
  isPublic: boolean;
  tenantId: string;
}

// =============================================================================
// Inventory Types
// =============================================================================

/**
 * Inventory item
 */
export interface InventoryItem extends BaseEntity {
  name: string;
  description?: string;
  category: 'medication' | 'supply' | 'equipment' | 'other';
  sku: string;
  barcode?: string;
  quantity: number;
  unit: string;
  unitPrice: number;
  reorderLevel: number;
  location?: string;
  supplier?: string;
  expiryDate?: Date;
  batchNumber?: string;
  isActive: boolean;
  tenantId: string;
}

/**
 * Inventory transaction
 */
export interface InventoryTransaction extends BaseEntity {
  itemId: string;
  transactionType: 'purchase' | 'sale' | 'adjustment' | 'return' | 'transfer';
  quantity: number;
  unitPrice: number;
  totalPrice: number;
  referenceNumber?: string;
  notes?: string;
  performedBy: string;
  tenantId: string;
}

// =============================================================================
// Billing & Payment Types
// =============================================================================

/**
 * Invoice status
 */
export enum InvoiceStatus {
  DRAFT = 'draft',
  PENDING = 'pending',
  PAID = 'paid',
  PARTIALLY_PAID = 'partially_paid',
  OVERDUE = 'overdue',
  CANCELLED = 'cancelled',
  REFUNDED = 'refunded',
}

/**
 * Invoice
 */
export interface Invoice extends BaseEntity {
  invoiceNumber: string;
  patientId: string;
  appointmentId?: string;
  issueDate: Date;
  dueDate: Date;
  status: InvoiceStatus;
  subtotal: number;
  taxAmount: number;
  discountAmount: number;
  totalAmount: number;
  paidAmount: number;
  balanceDue: number;
  items: InvoiceItem[];
  payments: Payment[];
  notes?: string;
  termsAndConditions?: string;
  createdBy: string;
  tenantId: string;
}

/**
 * Invoice line item
 */
export interface InvoiceItem {
  id: string;
  description: string;
  quantity: number;
  unitPrice: number;
  taxRate: number;
  taxAmount: number;
  discountRate?: number;
  discountAmount?: number;
  totalAmount: number;
  itemType: 'service' | 'product' | 'fee';
  itemId?: string; // Reference to service or product
}

/**
 * Payment method
 */
export enum PaymentMethod {
  CASH = 'cash',
  CREDIT_CARD = 'credit_card',
  DEBIT_CARD = 'debit_card',
  BANK_TRANSFER = 'bank_transfer',
  CHEQUE = 'cheque',
  INSURANCE = 'insurance',
  MOBILE_PAYMENT = 'mobile_payment',
  ONLINE_PAYMENT = 'online_payment',
  OTHER = 'other',
}

/**
 * Payment record
 */
export interface Payment extends BaseEntity {
  invoiceId: string;
  amount: number;
  paymentMethod: PaymentMethod;
  paymentDate: Date;
  transactionId?: string;
  status: 'pending' | 'completed' | 'failed' | 'refunded';
  notes?: string;
  receivedBy: string;
  tenantId: string;
}

/**
 * Insurance claim
 */
export interface InsuranceClaim extends BaseEntity {
  invoiceId: string;
  patientId: string;
  insuranceProvider: string;
  policyNumber: string;
  claimNumber?: string;
  claimDate: Date;
  claimAmount: number;
  approvedAmount?: number;
  status: 'draft' | 'submitted' | 'in_process' | 'approved' | 'partially_approved' | 'denied' | 'closed';
  submissionDate?: Date;
  responseDate?: Date;
  denialReason?: string;
  notes?: string;
  attachments?: Attachment[];
  tenantId: string;
}

// =============================================================================
// Tenant & Subscription Types
// =============================================================================

/**
 * Tenant information
 */
export interface Tenant extends BaseEntity {
  name: string;
  displayName: string;
  slug: string;
  description?: string;
  logo?: string;
  contactEmail: string;
  contactPhone?: string;
  address?: Address;
  website?: string;
  status: 'active' | 'inactive' | 'suspended' | 'pending';
  subscriptionId?: string;
  licenseId?: string;
  settings: TenantSettings;
  theme?: TenantTheme;
  metadata?: Record<string, any>;
}

/**
 * Tenant settings
 */
export interface TenantSettings {
  defaultLanguage: 'en' | 'ar';
  timezone: string;
  dateFormat: string;
  timeFormat: '12h' | '24h';
  currency: string;
  appointmentDuration: number; // in minutes
  workingHours: WorkSchedule;
  emailNotifications: boolean;
  smsNotifications: boolean;
  allowPatientRegistration: boolean;
  allowPatientAppointments: boolean;
  requireAppointmentApproval: boolean;
  reminderSettings: {
    sendEmailReminders: boolean;
    sendSmsReminders: boolean;
    reminderHours: number[]; // Hours before appointment
  };
  securitySettings: {
    passwordPolicy: {
      minLength: number;
      requireUppercase: boolean;
      requireLowercase: boolean;
      requireNumbers: boolean;
      requireSpecialChars: boolean;
    };
    sessionTimeout: number; // in minutes
    allowMultipleSessions: boolean;
    twoFactorAuthRequired: boolean;
  };
}

/**
 * Tenant theme settings
 */
export interface TenantTheme {
  primaryColor: string;
  secondaryColor: string;
  accentColor: string;
  logoUrl?: string;
  faviconUrl?: string;
  customCss?: string;
  darkMode: boolean;
  rtl: boolean;
}

/**
 * Subscription plan
 */
export interface SubscriptionPlan extends BaseEntity {
  name: string;
  description: string;
  features: string[];
  price: number;
  billingCycle: 'monthly' | 'quarterly' | 'biannually' | 'annually';
  trialDays: number;
  maxUsers: number;
  maxPatients: number;
  maxStorage: number; // in GB
  isActive: boolean;
  isPublic: boolean;
  sortOrder: number;
}

/**
 * Subscription
 */
export interface Subscription extends BaseEntity {
  tenantId: string;
  planId: string;
  status: 'trial' | 'active' | 'past_due' | 'cancelled' | 'expired';
  startDate: Date;
  endDate: Date;
  trialEndsAt?: Date;
  cancelledAt?: Date;
  currentPeriodStart: Date;
  currentPeriodEnd: Date;
  paymentMethod?: PaymentMethod;
  paymentGateway?: string;
  gatewaySubscriptionId?: string;
  gatewayCustomerId?: string;
  autoRenew: boolean;
  cancelAtPeriodEnd: boolean;
  plan?: SubscriptionPlan;
}

/**
 * Payment gateway configuration
 */
export interface PaymentGateway {
  id: string;
  name: string;
  code: 'creem' | 'paymob' | 'stripe' | 'paypal' | 'manual';
  isActive: boolean;
  isDefault: boolean;
  config: Record<string, any>;
  supportedCurrencies: string[];
  supportedPaymentMethods: PaymentMethod[];
}

// =============================================================================
// Backup & Restore Types
// =============================================================================

/**
 * Backup metadata
 */
export interface BackupMetadata {
  id: string;
  tenantId: string;
  createdAt: Date;
  createdBy: string;
  fileName: string;
  fileSize: number;
  checksum: string;
  version: string;
  description?: string;
  backupType: 'full' | 'data_only' | 'settings_only';
  encryptionMethod: 'aes-256' | 'none';
  compressionMethod: 'gzip' | 'none';
}

/**
 * Restore options
 */
export interface RestoreOptions {
  backupId?: string;
  file?: File;
  password?: string;
  restoreType: 'full' | 'data_only' | 'settings_only';
  overwriteExisting: boolean;
  restartAfterRestore: boolean;
}

// =============================================================================
// Notification Types
// =============================================================================

/**
 * Notification type
 */
export enum NotificationType {
  APPOINTMENT_REMINDER = 'appointment_reminder',
  APPOINTMENT_CONFIRMATION = 'appointment_confirmation',
  APPOINTMENT_CANCELLATION = 'appointment_cancellation',
  APPOINTMENT_RESCHEDULED = 'appointment_rescheduled',
  NEW_MESSAGE = 'new_message',
  PRESCRIPTION_READY = 'prescription_ready',
  LAB_RESULTS_READY = 'lab_results_ready',
  PAYMENT_RECEIVED = 'payment_received',
  PAYMENT_DUE = 'payment_due',
  PAYMENT_OVERDUE = 'payment_overdue',
  SYSTEM_ALERT = 'system_alert',
  LICENSE_EXPIRING = 'license_expiring',
  LICENSE_EXPIRED = 'license_expired',
}

/**
 * Notification
 */
export interface Notification extends BaseEntity {
  userId: string;
  type: NotificationType;
  title: string;
  message: string;
  isRead: boolean;
  readAt?: Date;
  data?: Record<string, any>;
  link?: string;
  priority: 'low' | 'normal' | 'high' | 'urgent';
  expiresAt?: Date;
  tenantId: string;
}

/**
 * Notification preferences
 */
export interface NotificationPreferences {
  userId: string;
  channels: {
    email: boolean;
    sms: boolean;
    push: boolean;
    inApp: boolean;
  };
  types: Record<NotificationType, {
    enabled: boolean;
    channels: string[];
  }>;
  quietHours: {
    enabled: boolean;
    start: string; // HH:MM format
    end: string; // HH:MM format
    timezone: string;
  };
}

// =============================================================================
// Report Types
// =============================================================================

/**
 * Report type
 */
export enum ReportType {
  APPOINTMENTS = 'appointments',
  PATIENTS = 'patients',
  REVENUE = 'revenue',
  INVENTORY = 'inventory',
  DOCTORS_PERFORMANCE = 'doctors_performance',
  INSURANCE_CLAIMS = 'insurance_claims',
  CUSTOM = 'custom',
}

/**
 * Report parameters
 */
export interface ReportParams {
  type: ReportType;
  startDate: Date;
  endDate: Date;
  groupBy?: 'day' | 'week' | 'month' | 'quarter' | 'year';
  filters?: Record<string, any>;
  includeCharts?: boolean;
  format?: 'pdf' | 'excel' | 'csv' | 'json';
  tenantId: string;
}

/**
 * Report data
 */
export interface ReportData {
  type: ReportType;
  title: string;
  description: string;
  generatedAt: Date;
  generatedBy: string;
  parameters: ReportParams;
  summary: Record<string, any>;
  data: any[];
  charts?: any[];
  tenantId: string;
}
