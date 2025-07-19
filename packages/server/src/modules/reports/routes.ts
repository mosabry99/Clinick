/**
 * Reports and Analytics Routes
 * 
 * This module handles all reporting and analytics operations including:
 * - Financial reports (revenue, expenses, profitability)
 * - Patient analytics and demographics
 * - Appointment and scheduling analytics
 * - Medical statistics and outcomes
 * - Doctor performance metrics
 * - Clinic utilization reports
 * - Revenue cycle management reports
 * - Patient satisfaction surveys
 * - Clinical quality indicators
 * - Custom report builder
 * - Dashboard widgets and KPIs
 * - Export capabilities (PDF, Excel, CSV)
 * - Scheduled report generation
 * - Interactive charts and visualizations
 */

import { Router, Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import PDFDocument from 'pdfkit';
import ExcelJS from 'exceljs';
import { createObjectCsvWriter } from 'csv-writer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { DateTime } from 'luxon';
import nodemailer from 'nodemailer';
import cron from 'node-cron';
import Chart from 'chart.js/auto';
import { ChartJSNodeCanvas } from 'chartjs-node-canvas';
import archiver from 'archiver';
import { parse as jsonParse } from 'json2csv';
import { JSDOM } from 'jsdom';
import crypto from 'crypto';

// Create router
const router = Router();

// Environment variables
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const EMAIL_FROM = process.env.EMAIL_FROM || 'noreply@clinick.app';
const REPORTS_DIR = process.env.REPORTS_DIR || './data/reports';
const CHARTS_DIR = process.env.CHARTS_DIR || './data/charts';
const SCHEDULED_REPORTS_ENABLED = process.env.SCHEDULED_REPORTS_ENABLED === 'true';

// Get the directory name for reports storage
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPORTS_PATH = path.join(__dirname, '../../../../', REPORTS_DIR);
const CHARTS_PATH = path.join(__dirname, '../../../../', CHARTS_DIR);

// Create storage directories if they don't exist
if (!fs.existsSync(REPORTS_PATH)) {
  fs.mkdirSync(REPORTS_PATH, { recursive: true });
}

if (!fs.existsSync(CHARTS_PATH)) {
  fs.mkdirSync(CHARTS_PATH, { recursive: true });
}

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: parseInt(process.env.SMTP_PORT || '2525', 10),
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
  },
  secure: process.env.SMTP_SECURE === 'true',
});

// Permission constants
const REQUIRED_PERMISSIONS = {
  VIEW_FINANCIAL_REPORTS: ['reports:view-financial'],
  VIEW_PATIENT_ANALYTICS: ['reports:view-patient-analytics'],
  VIEW_APPOINTMENT_ANALYTICS: ['reports:view-appointment-analytics'],
  VIEW_MEDICAL_STATISTICS: ['reports:view-medical-statistics'],
  VIEW_DOCTOR_PERFORMANCE: ['reports:view-doctor-performance'],
  VIEW_CLINIC_UTILIZATION: ['reports:view-clinic-utilization'],
  VIEW_REVENUE_CYCLE: ['reports:view-revenue-cycle'],
  VIEW_SATISFACTION_SURVEYS: ['reports:view-satisfaction-surveys'],
  VIEW_CLINICAL_QUALITY: ['reports:view-clinical-quality'],
  MANAGE_CUSTOM_REPORTS: ['reports:manage-custom'],
  VIEW_DASHBOARD: ['reports:view-dashboard'],
  EXPORT_REPORTS: ['reports:export'],
  SCHEDULE_REPORTS: ['reports:schedule'],
  MANAGE_SCHEDULED_REPORTS: ['reports:manage-scheduled'],
  ADMIN_REPORTS: ['reports:admin'],
};

// Validation schemas
const dateRangeSchema = z.object({
  startDate: z.string().refine((value) => !isNaN(Date.parse(value)), {
    message: 'Invalid start date format',
  }),
  endDate: z.string().refine((value) => !isNaN(Date.parse(value)), {
    message: 'Invalid end date format',
  }),
});

const financialReportSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'revenue', 
    'expenses', 
    'profitability', 
    'revenue_by_service', 
    'revenue_by_doctor',
    'revenue_by_location',
    'outstanding_invoices',
    'payment_methods',
    'insurance_claims',
    'refunds',
    'tax'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  serviceId: z.string().uuid('Invalid service ID').optional(),
  insuranceProviderId: z.string().uuid('Invalid insurance provider ID').optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const patientAnalyticsSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'demographics', 
    'new_patients', 
    'patient_retention', 
    'patient_source',
    'patient_conditions',
    'patient_age_distribution',
    'patient_gender_distribution',
    'patient_geographic_distribution',
    'patient_insurance_distribution',
    'patient_visit_frequency'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  ageRange: z.string().optional(), // e.g., "0-18,19-35,36-50,51-65,65+"
  gender: z.string().optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const appointmentAnalyticsSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'appointment_volume', 
    'appointment_status', 
    'no_shows', 
    'cancellations',
    'reschedules',
    'appointment_duration',
    'wait_time',
    'booking_channel',
    'appointment_by_service',
    'appointment_by_doctor',
    'appointment_by_location',
    'appointment_by_day_of_week',
    'appointment_by_hour'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  serviceId: z.string().uuid('Invalid service ID').optional(),
  status: z.string().optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const medicalStatisticsSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'diagnoses', 
    'procedures', 
    'medications', 
    'lab_results',
    'vital_signs',
    'treatment_outcomes',
    'condition_prevalence',
    'referrals',
    'readmissions',
    'allergies'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  diagnosisCode: z.string().optional(),
  procedureCode: z.string().optional(),
  medicationId: z.string().optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
  anonymize: z.boolean().default(false),
});

const doctorPerformanceSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'patient_volume', 
    'revenue_generated', 
    'appointment_efficiency', 
    'patient_satisfaction',
    'treatment_outcomes',
    'documentation_compliance',
    'referral_patterns',
    'procedure_volume',
    'average_visit_duration',
    'follow_up_rate'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  specialtyId: z.string().uuid('Invalid specialty ID').optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const clinicUtilizationSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'room_utilization', 
    'equipment_utilization', 
    'staff_utilization', 
    'capacity_analysis',
    'peak_hours',
    'resource_allocation',
    'idle_time',
    'overbooking_rate',
    'utilization_by_service',
    'utilization_by_doctor'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  roomId: z.string().uuid('Invalid room ID').optional(),
  equipmentId: z.string().uuid('Invalid equipment ID').optional(),
  staffId: z.string().uuid('Invalid staff ID').optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const revenueCycleSchema = dateRangeSchema.extend({
  reportType: z.enum([
    'accounts_receivable', 
    'days_in_ar', 
    'collection_rate', 
    'denial_rate',
    'claim_aging',
    'payment_velocity',
    'write_offs',
    'adjustments',
    'payer_mix',
    'revenue_leakage'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  insuranceProviderId: z.string().uuid('Invalid insurance provider ID').optional(),
  claimStatus: z.string().optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const satisfactionSurveySchema = dateRangeSchema.extend({
  reportType: z.enum([
    'overall_satisfaction', 
    'nps_score', 
    'satisfaction_by_category', 
    'satisfaction_by_doctor',
    'satisfaction_by_location',
    'satisfaction_by_service',
    'satisfaction_trends',
    'survey_response_rate',
    'sentiment_analysis',
    'improvement_areas'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  serviceId: z.string().uuid('Invalid service ID').optional(),
  surveyType: z.string().optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
});

const clinicalQualitySchema = dateRangeSchema.extend({
  reportType: z.enum([
    'preventive_care', 
    'chronic_disease_management', 
    'medication_adherence', 
    'care_gaps',
    'clinical_outcomes',
    'readmission_rates',
    'infection_rates',
    'adverse_events',
    'quality_measures',
    'guideline_adherence'
  ]),
  groupBy: z.enum(['day', 'week', 'month', 'quarter', 'year']).optional(),
  locationId: z.string().uuid('Invalid location ID').optional(),
  doctorId: z.string().uuid('Invalid doctor ID').optional(),
  conditionId: z.string().uuid('Invalid condition ID').optional(),
  measureId: z.string().uuid('Invalid measure ID').optional(),
  format: z.enum(['json', 'csv', 'pdf', 'excel']).default('json'),
  includeCharts: z.boolean().default(true),
  anonymize: z.boolean().default(false),
});

const customReportSchema = z.object({
  name: z.string().min(1, 'Report name is required'),
  description: z.string().optional(),
  reportType: z.string().min(1, 'Report type is required'),
  dataSource: z.enum([
    'appointments', 
    'patients', 
    'invoices', 
    'payments',
    'medical_records',
    'lab_results',
    'diagnostics',
    'treatments',
    'surveys',
    'users',
    'inventory',
    'multiple'
  ]),
  filters: z.array(z.object({
    field: z.string().min(1, 'Filter field is required'),
    operator: z.enum(['equals', 'not_equals', 'greater_than', 'less_than', 'contains', 'not_contains', 'in', 'not_in', 'between', 'is_null', 'is_not_null']),
    value: z.any().optional(),
  })).optional(),
  columns: z.array(z.object({
    field: z.string().min(1, 'Column field is required'),
    title: z.string().min(1, 'Column title is required'),
    dataType: z.enum(['string', 'number', 'date', 'boolean', 'object']),
    format: z.string().optional(),
    width: z.number().optional(),
    sortable: z.boolean().optional(),
    visible: z.boolean().optional(),
  })),
  sortBy: z.array(z.object({
    field: z.string().min(1, 'Sort field is required'),
    direction: z.enum(['asc', 'desc']),
  })).optional(),
  groupBy: z.array(z.string()).optional(),
  aggregations: z.array(z.object({
    field: z.string().min(1, 'Aggregation field is required'),
    function: z.enum(['sum', 'avg', 'min', 'max', 'count', 'count_distinct']),
    title: z.string().min(1, 'Aggregation title is required'),
  })).optional(),
  charts: z.array(z.object({
    type: z.enum(['bar', 'line', 'pie', 'doughnut', 'radar', 'scatter', 'bubble', 'area', 'stacked_bar']),
    title: z.string().min(1, 'Chart title is required'),
    xAxis: z.string().optional(),
    yAxis: z.string().optional(),
    series: z.array(z.object({
      field: z.string().min(1, 'Series field is required'),
      label: z.string().min(1, 'Series label is required'),
      color: z.string().optional(),
    })).optional(),
    options: z.record(z.any()).optional(),
  })).optional(),
  isPublic: z.boolean().default(false),
  schedule: z.object({
    enabled: z.boolean().default(false),
    frequency: z.enum(['daily', 'weekly', 'monthly', 'quarterly']).optional(),
    dayOfWeek: z.number().int().min(0).max(6).optional(), // 0 = Sunday, 6 = Saturday
    dayOfMonth: z.number().int().min(1).max(31).optional(),
    time: z.string().optional(), // HH:MM format
    recipients: z.array(z.string().email('Invalid email format')).optional(),
    format: z.enum(['pdf', 'excel', 'csv']).optional(),
  }).optional(),
  tenantId: z.string().uuid('Invalid tenant ID').optional(),
});

const updateCustomReportSchema = customReportSchema.partial().extend({
  name: z.string().min(1, 'Report name is required').optional(),
});

const dashboardWidgetSchema = z.object({
  name: z.string().min(1, 'Widget name is required'),
  type: z.enum([
    'number', 
    'chart', 
    'table', 
    'list',
    'gauge',
    'status',
    'trend',
    'comparison',
    'map',
    'calendar',
    'custom'
  ]),
  dataSource: z.string().min(1, 'Data source is required'),
  refresh: z.enum(['manual', 'realtime', '1min', '5min', '15min', '30min', '1hour', '4hour', '12hour', 'daily']).default('manual'),
  size: z.enum(['small', 'medium', 'large', 'full']).default('medium'),
  position: z.number().int().nonnegative().optional(),
  config: z.record(z.any()),
  filters: z.array(z.object({
    field: z.string().min(1, 'Filter field is required'),
    operator: z.enum(['equals', 'not_equals', 'greater_than', 'less_than', 'contains', 'not_contains', 'in', 'not_in', 'between', 'is_null', 'is_not_null']),
    value: z.any().optional(),
  })).optional(),
  visualization: z.object({
    type: z.enum(['bar', 'line', 'pie', 'doughnut', 'radar', 'scatter', 'bubble', 'area', 'stacked_bar', 'table', 'kpi', 'gauge', 'map']).optional(),
    options: z.record(z.any()).optional(),
  }).optional(),
  isPublic: z.boolean().default(false),
  dashboardId: z.string().uuid('Invalid dashboard ID'),
});

const updateDashboardWidgetSchema = dashboardWidgetSchema.partial().extend({
  name: z.string().min(1, 'Widget name is required').optional(),
});

const dashboardSchema = z.object({
  name: z.string().min(1, 'Dashboard name is required'),
  description: z.string().optional(),
  isDefault: z.boolean().default(false),
  isPublic: z.boolean().default(false),
  layout: z.array(z.object({
    id: z.string().uuid('Invalid widget ID'),
    x: z.number().int().nonnegative(),
    y: z.number().int().nonnegative(),
    w: z.number().int().positive(),
    h: z.number().int().positive(),
  })).optional(),
  filters: z.array(z.object({
    field: z.string().min(1, 'Filter field is required'),
    operator: z.enum(['equals', 'not_equals', 'greater_than', 'less_than', 'contains', 'not_contains', 'in', 'not_in', 'between', 'is_null', 'is_not_null']),
    value: z.any().optional(),
    label: z.string().optional(),
  })).optional(),
  dateRange: z.object({
    start: z.string().optional(),
    end: z.string().optional(),
    preset: z.enum(['today', 'yesterday', 'this_week', 'last_week', 'this_month', 'last_month', 'this_quarter', 'last_quarter', 'this_year', 'last_year', 'custom']).optional(),
  }).optional(),
  refreshRate: z.enum(['manual', 'realtime', '1min', '5min', '15min', '30min', '1hour', '4hour', '12hour', 'daily']).default('manual'),
  tenantId: z.string().uuid('Invalid tenant ID').optional(),
});

const updateDashboardSchema = dashboardSchema.partial().extend({
  name: z.string().min(1, 'Dashboard name is required').optional(),
});

const scheduledReportSchema = z.object({
  name: z.string().min(1, 'Report name is required'),
  description: z.string().optional(),
  reportType: z.string().min(1, 'Report type is required'),
  reportId: z.string().uuid('Invalid report ID').optional(),
  parameters: z.record(z.any()),
  schedule: z.object({
    frequency: z.enum(['daily', 'weekly', 'monthly', 'quarterly']),
    dayOfWeek: z.number().int().min(0).max(6).optional(), // 0 = Sunday, 6 = Saturday
    dayOfMonth: z.number().int().min(1).max(31).optional(),
    time: z.string(), // HH:MM format
    timezone: z.string().default('UTC'),
  }),
  format: z.enum(['pdf', 'excel', 'csv', 'json']).default('pdf'),
  delivery: z.object({
    method: z.enum(['email', 'storage', 'both']),
    recipients: z.array(z.string().email('Invalid email format')).optional(),
    subject: z.string().optional(),
    message: z.string().optional(),
    storageLocation: z.string().optional(),
  }),
  isActive: z.boolean().default(true),
  lastRun: z.string().optional(),
  nextRun: z.string().optional(),
  tenantId: z.string().uuid('Invalid tenant ID').optional(),
});

const updateScheduledReportSchema = scheduledReportSchema.partial().extend({
  name: z.string().min(1, 'Report name is required').optional(),
});

// Helper functions
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

const sendEmail = async (options: {
  to: string | string[];
  subject: string;
  text?: string;
  html: string;
  attachments?: any[];
}): Promise<void> => {
  try {
    await transporter.sendMail({
      from: EMAIL_FROM,
      ...options,
    });
  } catch (error) {
    console.error('Error sending email:', error);
  }
};

const generateReportFilename = (reportType: string, format: string): string => {
  const timestamp = DateTime.now().toFormat('yyyyMMdd_HHmmss');
  return `${reportType}_${timestamp}.${format}`;
};

const formatDateRange = (startDate: string, endDate: string, groupBy: string = 'day'): { start: Date, end: Date, intervals: any[] } => {
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  // Ensure end date is at the end of the day
  end.setHours(23, 59, 59, 999);
  
  const intervals: any[] = [];
  let current = new Date(start);
  
  while (current <= end) {
    let label = '';
    let nextDate = new Date(current);
    
    switch (groupBy) {
      case 'day':
        label = DateTime.fromJSDate(current).toFormat('yyyy-MM-dd');
        nextDate.setDate(current.getDate() + 1);
        break;
      case 'week':
        const weekStart = DateTime.fromJSDate(current).startOf('week');
        const weekEnd = DateTime.fromJSDate(current).endOf('week');
        label = `${weekStart.toFormat('yyyy-MM-dd')} to ${weekEnd.toFormat('yyyy-MM-dd')}`;
        nextDate.setDate(current.getDate() + 7);
        break;
      case 'month':
        label = DateTime.fromJSDate(current).toFormat('yyyy-MM');
        nextDate = DateTime.fromJSDate(current).plus({ months: 1 }).toJSDate();
        break;
      case 'quarter':
        const quarter = Math.floor(current.getMonth() / 3) + 1;
        label = `${current.getFullYear()}-Q${quarter}`;
        nextDate = DateTime.fromJSDate(current).plus({ months: 3 }).toJSDate();
        break;
      case 'year':
        label = current.getFullYear().toString();
        nextDate = new Date(current);
        nextDate.setFullYear(current.getFullYear() + 1);
        break;
    }
    
    intervals.push({
      start: new Date(current),
      end: new Date(nextDate),
      label,
    });
    
    current = nextDate;
  }
  
  return { start, end, intervals };
};

const generatePdf = async (title: string, data: any, options: any = {}): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      const filename = generateReportFilename(title.replace(/\s+/g, '_').toLowerCase(), 'pdf');
      const filePath = path.join(REPORTS_PATH, filename);
      
      // Create a new PDF document
      const doc = new PDFDocument({ margin: 50 });
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);
      
      // Add title
      doc.fontSize(24).text(title, { align: 'center' });
      doc.moveDown();
      
      // Add date range if provided
      if (options.startDate && options.endDate) {
        const startDate = DateTime.fromISO(options.startDate).toFormat('MMM dd, yyyy');
        const endDate = DateTime.fromISO(options.endDate).toFormat('MMM dd, yyyy');
        doc.fontSize(12).text(`Period: ${startDate} to ${endDate}`, { align: 'center' });
        doc.moveDown();
      }
      
      // Add filters if provided
      if (options.filters && Object.keys(options.filters).length > 0) {
        doc.fontSize(12).text('Filters:', { underline: true });
        Object.entries(options.filters).forEach(([key, value]) => {
          if (value) {
            doc.text(`${key}: ${value}`);
          }
        });
        doc.moveDown();
      }
      
      // Add charts if provided
      if (options.charts && options.charts.length > 0) {
        for (const chartInfo of options.charts) {
          if (chartInfo.path && fs.existsSync(chartInfo.path)) {
            doc.image(chartInfo.path, {
              fit: [500, 300],
              align: 'center',
            });
            doc.moveDown();
            
            if (chartInfo.title) {
              doc.fontSize(12).text(chartInfo.title, { align: 'center' });
              doc.moveDown();
            }
          }
        }
      }
      
      // Add tables if provided
      if (options.tables && options.tables.length > 0) {
        for (const tableInfo of options.tables) {
          if (tableInfo.title) {
            doc.fontSize(14).text(tableInfo.title, { underline: true });
            doc.moveDown(0.5);
          }
          
          if (tableInfo.data && tableInfo.data.length > 0) {
            const table = tableInfo.data;
            const headers = Object.keys(table[0]);
            
            // Calculate column widths
            const columnWidth = 500 / headers.length;
            
            // Draw headers
            let xPos = 50;
            headers.forEach(header => {
              doc.fontSize(10).text(header, xPos, doc.y, { width: columnWidth });
              xPos += columnWidth;
            });
            
            doc.moveDown(0.5);
            doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
            doc.moveDown(0.5);
            
            // Draw rows
            table.forEach(row => {
              if (doc.y > 700) {
                doc.addPage();
              }
              
              xPos = 50;
              headers.forEach(header => {
                doc.fontSize(10).text(row[header]?.toString() || '', xPos, doc.y, { width: columnWidth });
                xPos += columnWidth;
              });
              
              doc.moveDown();
            });
            
            doc.moveDown();
          }
        }
      }
      
      // Add summary if provided
      if (options.summary) {
        doc.fontSize(14).text('Summary', { underline: true });
        doc.moveDown(0.5);
        
        Object.entries(options.summary).forEach(([key, value]) => {
          doc.fontSize(10).text(`${key}: ${value}`);
        });
        
        doc.moveDown();
      }
      
      // Add footer
      const pageCount = doc.bufferedPageRange().count;
      for (let i = 0; i < pageCount; i++) {
        doc.switchToPage(i);
        
        // Footer text
        doc.fontSize(8)
          .text(
            `Generated on ${DateTime.now().toFormat('yyyy-MM-dd HH:mm:ss')}`,
            50,
            doc.page.height - 50,
            { align: 'center', width: doc.page.width - 100 }
          );
        
        // Page numbers
        doc.text(
          `Page ${i + 1} of ${pageCount}`,
          50,
          doc.page.height - 35,
          { align: 'center', width: doc.page.width - 100 }
        );
      }
      
      // Finalize the PDF
      doc.end();
      
      stream.on('finish', () => {
        resolve(filePath);
      });
      
      stream.on('error', (err) => {
        reject(err);
      });
    } catch (error) {
      reject(error);
    }
  });
};

const generateExcel = async (title: string, data: any, options: any = {}): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      const filename = generateReportFilename(title.replace(/\s+/g, '_').toLowerCase(), 'xlsx');
      const filePath = path.join(REPORTS_PATH, filename);
      
      // Create a new workbook
      const workbook = new ExcelJS.Workbook();
      workbook.creator = 'Clinick App';
      workbook.created = new Date();
      
      // Add main worksheet
      const worksheet = workbook.addWorksheet('Report');
      
      // Add title
      worksheet.mergeCells('A1:H1');
      const titleCell = worksheet.getCell('A1');
      titleCell.value = title;
      titleCell.font = { size: 16, bold: true };
      titleCell.alignment = { horizontal: 'center' };
      
      // Add date range if provided
      if (options.startDate && options.endDate) {
        const startDate = DateTime.fromISO(options.startDate).toFormat('MMM dd, yyyy');
        const endDate = DateTime.fromISO(options.endDate).toFormat('MMM dd, yyyy');
        
        worksheet.mergeCells('A2:H2');
        const dateCell = worksheet.getCell('A2');
        dateCell.value = `Period: ${startDate} to ${endDate}`;
        dateCell.font = { size: 12 };
        dateCell.alignment = { horizontal: 'center' };
      }
      
      // Add filters if provided
      let rowIndex = 4;
      if (options.filters && Object.keys(options.filters).length > 0) {
        worksheet.getCell(`A${rowIndex}`).value = 'Filters:';
        worksheet.getCell(`A${rowIndex}`).font = { bold: true };
        rowIndex++;
        
        Object.entries(options.filters).forEach(([key, value]) => {
          if (value) {
            worksheet.getCell(`A${rowIndex}`).value = key;
            worksheet.getCell(`B${rowIndex}`).value = value;
            rowIndex++;
          }
        });
        
        rowIndex += 1;
      }
      
      // Add tables if provided
      if (options.tables && options.tables.length > 0) {
        for (const tableInfo of options.tables) {
          if (tableInfo.title) {
            worksheet.getCell(`A${rowIndex}`).value = tableInfo.title;
            worksheet.getCell(`A${rowIndex}`).font = { size: 14, bold: true };
            rowIndex += 2;
          }
          
          if (tableInfo.data && tableInfo.data.length > 0) {
            const table = tableInfo.data;
            const headers = Object.keys(table[0]);
            
            // Add headers
            headers.forEach((header, index) => {
              const cell = worksheet.getCell(rowIndex, index + 1);
              cell.value = header;
              cell.font = { bold: true };
              cell.border = {
                top: { style: 'thin' },
                left: { style: 'thin' },
                bottom: { style: 'thin' },
                right: { style: 'thin' }
              };
            });
            
            rowIndex++;
            
            // Add data rows
            table.forEach(row => {
              headers.forEach((header, index) => {
                const cell = worksheet.getCell(rowIndex, index + 1);
                cell.value = row[header];
                cell.border = {
                  top: { style: 'thin' },
                  left: { style: 'thin' },
                  bottom: { style: 'thin' },
                  right: { style: 'thin' }
                };
              });
              
              rowIndex++;
            });
            
            rowIndex += 2;
          }
        }
      }
      
      // Add summary if provided
      if (options.summary) {
        worksheet.getCell(`A${rowIndex}`).value = 'Summary';
        worksheet.getCell(`A${rowIndex}`).font = { size: 14, bold: true };
        rowIndex++;
        
        Object.entries(options.summary).forEach(([key, value]) => {
          worksheet.getCell(`A${rowIndex}`).value = key;
          worksheet.getCell(`B${rowIndex}`).value = value;
          rowIndex++;
        });
      }
      
      // If there are charts, create a separate worksheet for each chart
      if (options.charts && options.charts.length > 0) {
        // Excel doesn't support embedding images directly, so we'll just create data tables
        // for the chart data if available
        options.charts.forEach((chartInfo: any, index: number) => {
          if (chartInfo.data) {
            const chartSheet = workbook.addWorksheet(`Chart ${index + 1}`);
            
            // Add chart title
            chartSheet.mergeCells('A1:D1');
            const chartTitleCell = chartSheet.getCell('A1');
            chartTitleCell.value = chartInfo.title || `Chart ${index + 1}`;
            chartTitleCell.font = { size: 14, bold: true };
            chartTitleCell.alignment = { horizontal: 'center' };
            
            // Add chart data
            const chartData = chartInfo.data;
            if (Array.isArray(chartData) && chartData.length > 0) {
              const headers = Object.keys(chartData[0]);
              
              // Add headers
              headers.forEach((header, headerIndex) => {
                const cell = chartSheet.getCell(3, headerIndex + 1);
                cell.value = header;
                cell.font = { bold: true };
              });
              
              // Add data rows
              chartData.forEach((dataRow, rowIndex) => {
                headers.forEach((header, headerIndex) => {
                  chartSheet.getCell(rowIndex + 4, headerIndex + 1).value = dataRow[header];
                });
              });
            }
          }
        });
      }
      
      // Add footer
      const footerRow = rowIndex + 2;
      worksheet.mergeCells(`A${footerRow}:H${footerRow}`);
      const footerCell = worksheet.getCell(`A${footerRow}`);
      footerCell.value = `Generated on ${DateTime.now().toFormat('yyyy-MM-dd HH:mm:ss')}`;
      footerCell.font = { size: 8 };
      footerCell.alignment = { horizontal: 'center' };
      
      // Save the workbook
      workbook.xlsx.writeFile(filePath)
        .then(() => {
          resolve(filePath);
        })
        .catch(err => {
          reject(err);
        });
    } catch (error) {
      reject(error);
    }
  });
};

const generateCsv = async (title: string, data: any): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      const filename = generateReportFilename(title.replace(/\s+/g, '_').toLowerCase(), 'csv');
      const filePath = path.join(REPORTS_PATH, filename);
      
      // If data is an array of objects, convert to CSV
      if (Array.isArray(data)) {
        const csvData = jsonParse({ data });
        fs.writeFileSync(filePath, csvData);
        resolve(filePath);
      } 
      // If data has tables, write each table to a separate CSV
      else if (data.tables && data.tables.length > 0) {
        const mainTable = data.tables[0];
        if (mainTable.data && mainTable.data.length > 0) {
          const csvData = jsonParse({ data: mainTable.data });
          fs.writeFileSync(filePath, csvData);
          
          // If there are multiple tables, create a zip file
          if (data.tables.length > 1) {
            const zipFilename = generateReportFilename(title.replace(/\s+/g, '_').toLowerCase(), 'zip');
            const zipFilePath = path.join(REPORTS_PATH, zipFilename);
            
            const output = fs.createWriteStream(zipFilePath);
            const archive = archiver('zip', { zlib: { level: 9 } });
            
            output.on('close', () => {
              // Delete individual CSV files
              fs.unlinkSync(filePath);
              resolve(zipFilePath);
            });
            
            archive.on('error', (err) => {
              reject(err);
            });
            
            archive.pipe(output);
            
            // Add the main table
            archive.file(filePath, { name: path.basename(filePath) });
            
            // Add additional tables
            for (let i = 1; i < data.tables.length; i++) {
              const table = data.tables[i];
              if (table.data && table.data.length > 0) {
                const tableFilename = generateReportFilename(`${title}_${i + 1}`.replace(/\s+/g, '_').toLowerCase(), 'csv');
                const tableFilePath = path.join(REPORTS_PATH, tableFilename);
                
                const tableCsvData = jsonParse({ data: table.data });
                fs.writeFileSync(tableFilePath, tableCsvData);
                
                archive.file(tableFilePath, { name: path.basename(tableFilePath) });
              }
            }
            
            archive.finalize();
          } else {
            resolve(filePath);
          }
        } else {
          reject(new Error('No data available for CSV export'));
        }
      } else {
        reject(new Error('Invalid data format for CSV export'));
      }
    } catch (error) {
      reject(error);
    }
  });
};

const generateChart = async (
  type: string,
  data: any[],
  options: {
    title?: string;
    xAxis?: string;
    yAxis?: string;
    width?: number;
    height?: number;
    backgroundColor?: string;
    colors?: string[];
    legend?: boolean;
  } = {}
): Promise<string> => {
  try {
    const width = options.width || 800;
    const height = options.height || 400;
    const backgroundColor = options.backgroundColor || 'white';
    
    const chartJSNodeCanvas = new ChartJSNodeCanvas({ width, height, backgroundColour: backgroundColor });
    
    // Prepare chart configuration
    const config: any = {
      type: type,
      data: {
        labels: data.map(item => item.label || item.name || item.category || item.x),
        datasets: [],
      },
      options: {
        responsive: true,
        plugins: {
          title: {
            display: !!options.title,
            text: options.title || '',
          },
          legend: {
            display: options.legend !== false,
            position: 'top',
          },
        },
      },
    };
    
    // Configure axes if provided
    if (options.xAxis || options.yAxis) {
      config.options.scales = {
        x: {
          title: {
            display: !!options.xAxis,
            text: options.xAxis || '',
          },
        },
        y: {
          title: {
            display: !!options.yAxis,
            text: options.yAxis || '',
          },
          beginAtZero: true,
        },
      };
    }
    
    // Handle different chart types
    if (type === 'pie' || type === 'doughnut') {
      config.data.datasets.push({
        data: data.map(item => item.value || item.count || item.y),
        backgroundColor: options.colors || [
          '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40',
          '#8AC54B', '#5D6D7E', '#EC7063', '#3498DB', '#F1C40F', '#2ECC71',
        ],
      });
    } else if (type === 'bar' || type === 'line') {
      // Check if data has multiple series
      const hasMultipleSeries = data.length > 0 && data[0].series;
      
      if (hasMultipleSeries) {
        // Extract unique series names
        const allSeries = data.flatMap(item => item.series || []);
        const seriesNames = [...new Set(allSeries.map(s => s.name))];
        
        seriesNames.forEach((seriesName, index) => {
          const seriesData = data.map(item => {
            const series = (item.series || []).find(s => s.name === seriesName);
            return series ? series.value : null;
          });
          
          config.data.datasets.push({
            label: seriesName,
            data: seriesData,
            backgroundColor: options.colors ? options.colors[index % options.colors.length] : getDefaultColor(index),
            borderColor: type === 'line' ? (options.colors ? options.colors[index % options.colors.length] : getDefaultColor(index)) : undefined,
            fill: type === 'line' ? false : undefined,
          });
        });
      } else {
        config.data.datasets.push({
          label: options.yAxis || 'Value',
          data: data.map(item => item.value || item.count || item.y),
          backgroundColor: options.colors ? options.colors[0] : '#36A2EB',
          borderColor: type === 'line' ? (options.colors ? options.colors[0] : '#36A2EB') : undefined,
          fill: type === 'line' ? false : undefined,
        });
      }
    }
    
    // Generate chart image
    const image = await chartJSNodeCanvas.renderToBuffer(config);
    
    // Save image to file
    const filename = `chart_${Date.now()}_${Math.round(Math.random() * 1E6)}.png`;
    const filePath = path.join(CHARTS_PATH, filename);
    
    fs.writeFileSync(filePath, image);
    
    return filePath;
  } catch (error) {
    console.error('Error generating chart:', error);
    throw error;
  }
};

const getDefaultColor = (index: number): string => {
  const colors = [
    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40',
    '#8AC54B', '#5D6D7E', '#EC7063', '#3498DB', '#F1C40F', '#2ECC71',
  ];
  
  return colors[index % colors.length];
};

const executeCustomReport = async (prisma: PrismaClient, report: any, params: any = {}): Promise<any> => {
  try {
    // Parse report definition
    const { dataSource, filters = [], columns, sortBy = [], groupBy = [], aggregations = [] } = report;
    
    // Apply parameters to filters
    const appliedFilters = filters.map((filter: any) => {
      if (filter.parameterized && params[filter.field]) {
        return { ...filter, value: params[filter.field] };
      }
      return filter;
    });
    
    // Build query based on data source
    let query: any = {};
    let include: any = {};
    let orderBy: any = [];
    
    // Build where clause from filters
    if (appliedFilters.length > 0) {
      query.where = buildWhereClause(appliedFilters);
    }
    
    // Build select clause from columns
    const select: any = {};
    columns.forEach((column: any) => {
      // Handle nested fields (e.g., patient.firstName)
      if (column.field.includes('.')) {
        const [relation, field] = column.field.split('.');
        if (!include[relation]) {
          include[relation] = { select: {} };
        }
        include[relation].select[field] = true;
      } else {
        select[column.field] = true;
      }
    });
    
    // Add include to query if needed
    if (Object.keys(include).length > 0) {
      query.include = include;
    }
    
    // Add orderBy from sortBy
    if (sortBy.length > 0) {
      sortBy.forEach((sort: any) => {
        orderBy.push({ [sort.field]: sort.direction });
      });
      query.orderBy = orderBy;
    }
    
    // Execute query based on data source
    let results: any[] = [];
    
    switch (dataSource) {
      case 'appointments':
        results = await prisma.appointment.findMany(query);
        break;
      case 'patients':
        results = await prisma.patient.findMany(query);
        break;
      case 'invoices':
        results = await prisma.invoice.findMany(query);
        break;
      case 'payments':
        results = await prisma.payment.findMany(query);
        break;
      case 'medical_records':
        results = await prisma.medicalRecord.findMany(query);
        break;
      case 'lab_results':
        results = await prisma.labResult.findMany(query);
        break;
      case 'diagnostics':
        results = await prisma.diagnosticReport.findMany(query);
        break;
      case 'treatments':
        results = await prisma.treatmentPlan.findMany(query);
        break;
      case 'surveys':
        results = await prisma.satisfactionSurvey.findMany(query);
        break;
      case 'users':
        results = await prisma.user.findMany(query);
        break;
      case 'inventory':
        results = await prisma.inventoryItem.findMany(query);
        break;
      case 'multiple':
        // Handle multiple data sources (more complex queries)
        results = await executeMultiSourceQuery(prisma, report, params);
        break;
      default:
        throw new Error(`Unsupported data source: ${dataSource}`);
    }
    
    // Process results
    let processedResults = results;
    
    // Apply grouping if specified
    if (groupBy.length > 0) {
      processedResults = applyGrouping(results, groupBy, aggregations);
    }
    // Apply aggregations without grouping if needed
    else if (aggregations.length > 0) {
      processedResults = applyAggregations(results, aggregations);
    }
    
    // Format results based on column definitions
    processedResults = formatResults(processedResults, columns);
    
    return processedResults;
  } catch (error) {
    console.error('Error executing custom report:', error);
    throw error;
  }
};

const buildWhereClause = (filters: any[]): any => {
  if (filters.length === 0) return {};
  
  const whereClause: any = {};
  const orConditions: any[] = [];
  
  filters.forEach(filter => {
    if (filter.logic === 'or') {
      // Handle OR conditions
      const orCondition = buildFilterCondition(filter);
      if (orCondition) {
        orConditions.push(orCondition);
      }
    } else {
      // Handle AND conditions (default)
      const condition = buildFilterCondition(filter);
      if (condition) {
        Object.assign(whereClause, condition);
      }
    }
  });
  
  // Add OR conditions if any
  if (orConditions.length > 0) {
    whereClause.OR = orConditions;
  }
  
  return whereClause;
};

const buildFilterCondition = (filter: any): any => {
  const { field, operator, value } = filter;
  
  if (!field || !operator) return null;
  
  const condition: any = {};
  
  switch (operator) {
    case 'equals':
      condition[field] = value;
      break;
    case 'not_equals':
      condition[field] = { not: value };
      break;
    case 'greater_than':
      condition[field] = { gt: value };
      break;
    case 'less_than':
      condition[field] = { lt: value };
      break;
    case 'contains':
      condition[field] = { contains: value, mode: 'insensitive' };
      break;
    case 'not_contains':
      condition[field] = { not: { contains: value, mode: 'insensitive' } };
      break;
    case 'in':
      condition[field] = { in: Array.isArray(value) ? value : [value] };
      break;
    case 'not_in':
      condition[field] = { notIn: Array.isArray(value) ? value : [value] };
      break;
    case 'between':
      if (Array.isArray(value) && value.length === 2) {
        condition[field] = { gte: value[0], lte: value[1] };
      }
      break;
    case 'is_null':
      condition[field] = null;
      break;
    case 'is_not_null':
      condition[field] = { not: null };
      break;
    default:
      return null;
  }
  
  return condition;
};

const executeMultiSourceQuery = async (prisma: PrismaClient, report: any, params: any): Promise<any[]> => {
  // This is a placeholder for more complex multi-source queries
  // In a real implementation, this would handle JOINs across multiple tables
  
  // For now, we'll just return an empty array
  return [];
};

const applyGrouping = (data: any[], groupBy: string[], aggregations: any[]): any[] => {
  // Group data by the specified fields
  const groupedData: any = {};
  
  data.forEach(item => {
    // Create a key based on groupBy fields
    const groupKey = groupBy.map(field => getNestedValue(item, field)).join('|');
    
    if (!groupedData[groupKey]) {
      groupedData[groupKey] = {
        // Include groupBy fields in the result
        ...groupBy.reduce((acc, field) => {
          const value = getNestedValue(item, field);
          const fieldName = field.includes('.') ? field.split('.').pop() : field;
          return { ...acc, [fieldName as string]: value };
        }, {}),
        items: [],
      };
    }
    
    groupedData[groupKey].items.push(item);
  });
  
  // Apply aggregations to each group
  return Object.values(groupedData).map((group: any) => {
    const result = { ...group };
    delete result.items;
    
    aggregations.forEach(agg => {
      result[agg.title] = calculateAggregation(group.items, agg.field, agg.function);
    });
    
    return result;
  });
};

const applyAggregations = (data: any[], aggregations: any[]): any[] => {
  // Apply aggregations without grouping (returns a single row)
  const result: any = {};
  
  aggregations.forEach(agg => {
    result[agg.title] = calculateAggregation(data, agg.field, agg.function);
  });
  
  return [result];
};

const calculateAggregation = (data: any[], field: string, func: string): any => {
  // Extract values, handling nested fields
  const values = data.map(item => getNestedValue(item, field)).filter(val => val !== null && val !== undefined);
  
  switch (func) {
    case 'sum':
      return values.reduce((sum, val) => sum + (Number(val) || 0), 0);
    case 'avg':
      return values.length > 0 ? values.reduce((sum, val) => sum + (Number(val) || 0), 0) / values.length : 0;
    case 'min':
      return values.length > 0 ? Math.min(...values.map(v => Number(v) || 0)) : 0;
    case 'max':
      return values.length > 0 ? Math.max(...values.map(v => Number(v) || 0)) : 0;
    case 'count':
      return values.length;
    case 'count_distinct':
      return new Set(values).size;
    default:
      return null;
  }
};

const getNestedValue = (obj: any, path: string): any => {
  // Handle nested fields (e.g., patient.firstName)
  const parts = path.split('.');
  let value = obj;
  
  for (const part of parts) {
    if (value === null || value === undefined) return null;
    value = value[part];
  }
  
  return value;
};

const formatResults = (results: any[], columns: any[]): any[] => {
  // Format results based on column definitions
  return results.map(item => {
    const formattedItem: any = {};
    
    columns.forEach(column => {
      const fieldName = column.field.includes('.') ? column.field.split('.').pop() : column.field;
      let value = column.field.includes('.') ? getNestedValue(item, column.field) : item[column.field];
      
      // Apply formatting based on data type
      if (value !== null && value !== undefined) {
        switch (column.dataType) {
          case 'date':
            if (column.format) {
              value = DateTime.fromJSDate(new Date(value)).toFormat(column.format);
            } else {
              value = new Date(value).toISOString().split('T')[0];
            }
            break;
          case 'number':
            if (column.format === 'currency') {
              value = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(value);
            } else if (column.format === 'percent') {
              value = new Intl.NumberFormat('en-US', { style: 'percent', minimumFractionDigits: 2 }).format(value / 100);
            } else if (column.format) {
              value = new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value);
            }
            break;
          case 'boolean':
            value = value ? 'Yes' : 'No';
            break;
        }
      }
      
      formattedItem[column.title || fieldName] = value;
    });
    
    return formattedItem;
  });
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
 * @route GET /api/reports/financial
 * @desc Get financial reports
 * @access Private (requires reports:view-financial permission)
 */
router.get('/financial', requirePermission(REQUIRED_PERMISSIONS.VIEW_FINANCIAL_REPORTS), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prisma = req.tenantPrisma || req.prisma;
    
    // Parse and validate query parameters
    const params = financialReportSchema.parse({
      reportType: req.query.reportType as string || 'revenue',
      startDate: req.query.startDate as string,
      endDate: req.query.endDate as string,
      groupBy: req.query.groupBy as string || 'month',
      locationId: req.query.locationId as string,
      doctorId: req.query.doctorId as string,
      serviceId: req.query.serviceId as string,
      insuranceProviderId: req.query.insuranceProviderId as string,
      format: req.query.format as string || 'json',
      includeCharts: req.query.includeCharts === 'true',
    });
    
    // Format date range
    const { start, end, intervals } = formatDateRange(params.startDate, params.endDate, params.groupBy);
    
    // Prepare response data
    let reportData: any = {
      title: `Financial Report - ${params.reportType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`,
      startDate: params.startDate,
      endDate: params.endDate,
      groupBy: params.groupBy,
      filters: {
        locationId: params.locationId,
        doctorId: params.doctorId,
        serviceId: params.serviceId,
        insuranceProviderId: params.insuranceProviderId,
      },
      data: [],
      summary: {},
    };
    
    // Build where clause for queries
    const dateField = params.reportType.includes('invoice') || params.reportType.includes('revenue') ? 'issueDate' : 'paymentDate';
    const whereClause: any = {
      [dateField]: {
        gte: start,
        lte: end,
      },
    };
    
    if (params.locationId) {
      whereClause.clinicLocationId = params.locationId;
    }
    
    if (params.doctorId) {
      whereClause.doctorId = params.doctorId;
    }
    
    // Generate report based on report type
    switch (params.reportType) {
      case 'revenue':
        // Get invoices grouped by date
        const invoicesByDate = await Promise.all(intervals.map(async interval => {
          const invoices = await prisma.invoice.findMany({
            where: {
              ...whereClause,
              issueDate: {
                gte: interval.start,
                lt: interval.end,
              },
              status: { in: ['paid', 'partially_paid'] },
            },
            select: {
              id: true,
              total: true,
              status: true,
            },
          });
          
          // Get payments for these invoices
          const payments = await prisma.payment.findMany({
            where: {
              invoiceId: { in: invoices.map(inv => inv.id) },
              status: 'completed',
            },
            select: {
              amount: true,
            },
          });
          
          const totalRevenue = payments.reduce((sum, payment) => sum + Number(payment.amount), 0);
          
          return {
            period: interval.label,
            revenue: totalRevenue,
            invoiceCount: invoices.length,
          };
        }));
        
        reportData.data = invoicesByDate;
        reportData.summary = {
          totalRevenue: invoicesByDate.reduce((sum, item) => sum + item.revenue, 0),
          totalInvoices: invoicesByDate.reduce((sum, item) => sum + item.invoiceCount, 0),
          averageRevenue: invoicesByDate.length > 0 
            ? invoicesByDate.reduce((sum, item) => sum + item.revenue, 0) / invoicesByDate.length 
            : 0,
        };
        
        // Generate chart if requested
        if (params.includeCharts) {
          const chartPath = await generateChart('bar', invoicesByDate.map(item => ({
            label: item.period,
            value: item.revenue,
          })), {
            title: 'Revenue by Period',
            xAxis: 'Period',
            yAxis: 'Revenue (USD)',
          });
          
          reportData.charts = [{
            title: 'Revenue by Period',
            path: chartPath,
            type: 'bar',
            data: invoicesByDate,
          }];
        }
        
        // Prepare tables for export formats
        reportData.tables = [{
          title: 'Revenue by Period',
          data: invoicesByDate,
        }];
        break;
      
      case 'expenses':
        // Get expenses grouped by date
        const expensesByDate = await Promise.all(intervals.map(async interval => {
          const expenses = await prisma.expense.findMany({
            where: {
              date: {
                gte: interval.start,
                lt: interval.end,
              },
              ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
            },
            select: {
              amount: true,
              category: true,
            },
          });
          
          const totalExpenses = expenses.reduce((sum, expense) => sum + Number(expense.amount), 0);
          
          return {
            period: interval.label,
            expenses: totalExpenses,
            expenseCount: expenses.length,
          };
        }));
        
        reportData.data = expensesByDate;
        reportData.summary = {
          totalExpenses: expensesByDate.reduce((sum, item) => sum + item.expenses, 0),
          totalExpenseItems: expensesByDate.reduce((sum, item) => sum + item.expenseCount, 0),
          averageExpenses: expensesByDate.length > 0 
            ? expensesByDate.reduce((sum, item) => sum + item.expenses, 0) / expensesByDate.length 
            : 0,
        };
        
        // Generate chart if requested
        if (params.includeCharts) {
          const chartPath = await generateChart('bar', expensesByDate.map(item => ({
            label: item.period,
            value: item.expenses,
          })), {
            title: 'Expenses by Period',
            xAxis: 'Period',
            yAxis: 'Expenses (USD)',
          });
          
          reportData.charts = [{
            title: 'Expenses by Period',
            path: chartPath,
            type: 'bar',
            data: expensesByDate,
          }];
        }
        
        // Prepare tables for export formats
        reportData.tables = [{
          title: 'Expenses by Period',
          data: expensesByDate,
        }];
        break;
      
      case 'profitability':
        // Get both revenue and expenses for profitability
        const profitabilityByDate = await Promise.all(intervals.map(async interval => {
          // Get revenue
          const invoices = await prisma.invoice.findMany({
            where: {
              issueDate: {
                gte: interval.start,
                lt: interval.end,
              },
              status: { in: ['paid', 'partially_paid'] },
              ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
              ...(params.doctorId ? { doctorId: params.doctorId } : {}),
            },
            select: {
              id: true,
            },
          });
          
          const payments = await prisma.payment.findMany({
            where: {
              invoiceId: { in: invoices.map(inv => inv.id) },
              status: 'completed',
            },
            select: {
              amount: true,
            },
          });
          
          const revenue = payments.reduce((sum, payment) => sum + Number(payment.amount), 0);
          
          // Get expenses
          const expenses = await prisma.expense.findMany({
            where: {
              date: {
                gte: interval.start,
                lt: interval.end,
              },
              ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
            },
            select: {
              amount: true,
            },
          });
          
          const expenseTotal = expenses.reduce((sum, expense) => sum + Number(expense.amount), 0);
          
          // Calculate profit
          const profit = revenue - expenseTotal;
          const profitMargin = revenue > 0 ? (profit / revenue) * 100 : 0;
          
          return {
            period: interval.label,
            revenue,
            expenses: expenseTotal,
            profit,
            profitMargin: parseFloat(profitMargin.toFixed(2)),
          };
        }));
        
        reportData.data = profitabilityByDate;
        
        const totalRevenue = profitabilityByDate.reduce((sum, item) => sum + item.revenue, 0);
        const totalExpenses = profitabilityByDate.reduce((sum, item) => sum + item.expenses, 0);
        const totalProfit = totalRevenue - totalExpenses;
        const overallProfitMargin = totalRevenue > 0 ? (totalProfit / totalRevenue) * 100 : 0;
        
        reportData.summary = {
          totalRevenue,
          totalExpenses,
          totalProfit,
          overallProfitMargin: parseFloat(overallProfitMargin.toFixed(2)),
        };
        
        // Generate charts if requested
        if (params.includeCharts) {
          // Profit by period chart
          const profitChartPath = await generateChart('bar', profitabilityByDate.map(item => ({
            label: item.period,
            value: item.profit,
          })), {
            title: 'Profit by Period',
            xAxis: 'Period',
            yAxis: 'Profit (USD)',
          });
          
          // Revenue vs Expenses chart
          const comparisonData = profitabilityByDate.map(item => ({
            label: item.period,
            series: [
              { name: 'Revenue', value: item.revenue },
              { name: 'Expenses', value: item.expenses },
            ],
          }));
          
          const comparisonChartPath = await generateChart('bar', comparisonData, {
            title: 'Revenue vs Expenses',
            xAxis: 'Period',
            yAxis: 'Amount (USD)',
          });
          
          reportData.charts = [
            {
              title: 'Profit by Period',
              path: profitChartPath,
              type: 'bar',
              data: profitabilityByDate.map(item => ({
                period: item.period,
                profit: item.profit,
              })),
            },
            {
              title: 'Revenue vs Expenses',
              path: comparisonChartPath,
              type: 'bar',
              data: comparisonData,
            },
          ];
        }
        
        // Prepare tables for export formats
        reportData.tables = [{
          title: 'Profitability by Period',
          data: profitabilityByDate,
        }];
        break;
      
      case 'revenue_by_service':
        // Get revenue grouped by service
        const services = await prisma.service.findMany({
          select: {
            id: true,
            name: true,
          },
        });
        
        const revenueByService = await Promise.all(services.map(async service => {
          const invoiceItems = await prisma.invoiceItem.findMany({
            where: {
              serviceId: service.id,
              invoice: {
                issueDate: {
                  gte: start,
                  lte: end,
                },
                status: { in: ['paid', 'partially_paid'] },
                ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
                ...(params.doctorId ? { doctorId: params.doctorId } : {}),
              },
            },
            select: {
              total: true,
              quantity: true,
            },
          });
          
          const totalRevenue = invoiceItems.reduce((sum, item) => sum + Number(item.total), 0);
          const totalQuantity = invoiceItems.reduce((sum, item) => sum + Number(item.quantity), 0);
          
          return {
            serviceId: service.id,
            serviceName: service.name,
            revenue: totalRevenue,
            quantity: totalQuantity,
            averagePerService: totalQuantity > 0 ? totalRevenue / totalQuantity : 0,
          };
        }));
        
        // Filter out services with no revenue
        const filteredRevenueByService = revenueByService.filter(item => item.revenue > 0);
        
        // Sort by revenue in descending order
        filteredRevenueByService.sort((a, b) => b.revenue - a.revenue);
        
        reportData.data = filteredRevenueByService;
        reportData.summary = {
          totalRevenue: filteredRevenueByService.reduce((sum, item) => sum + item.revenue, 0),
          totalServices: filteredRevenueByService.length,
          totalQuantity: filteredRevenueByService.reduce((sum, item) => sum + item.quantity, 0),
        };
        
        // Generate chart if requested
        if (params.includeCharts) {
          const chartPath = await generateChart('pie', filteredRevenueByService.map(item => ({
            label: item.serviceName,
            value: item.revenue,
          })), {
            title: 'Revenue by Service',
          });
          
          reportData.charts = [{
            title: 'Revenue by Service',
            path: chartPath,
            type: 'pie',
            data: filteredRevenueByService,
          }];
        }
        
        // Prepare tables for export formats
        reportData.tables = [{
          title: 'Revenue by Service',
          data: filteredRevenueByService,
        }];
        break;
      
      case 'revenue_by_doctor':
        // Get revenue grouped by doctor
        const doctors = await prisma.user.findMany({
          where: {
            roles: {
              hasSome: ['DOCTOR'],
            },
            ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
          },
          select: {
            id: true,
            firstName: true,
            lastName: true,
            specialization: true,
          },
        });
        
        const revenueByDoctor = await Promise.all(doctors.map(async doctor => {
          const invoices = await prisma.invoice.findMany({
            where: {
              doctorId: doctor.id,
              issueDate: {
                gte: start,
                lte: end,
              },
              status: { in: ['paid', 'partially_paid'] },
              ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
            },
            select: {
              id: true,
            },
          });
          
          const payments = await prisma.payment.findMany({
            where: {
              invoiceId: { in: invoices.map(inv => inv.id) },
              status: 'completed',
            },
            select: {
              amount: true,
            },
          });
          
          const totalRevenue = payments.reduce((sum, payment) => sum + Number(payment.amount), 0);
          
          // Get appointment count for the doctor
          const appointmentCount = await prisma.appointment.count({
            where: {
              doctorId: doctor.id,
              startTime: {
                gte: start,
                lte: end,
              },
              status: 'completed',
              ...(params.locationId ? { clinicLocationId: params.locationId } : {}),
            },
          });
          
          return {
            doctorId: doctor.id,
            doctorName: `${doctor.firstName} ${doctor.lastName}`,
            specialization: doctor.specialization,
            revenue: totalRevenue,
            appointmentCount,
            averagePerAppointment: appointmentCount > 0 ? totalRevenue / appointmentCount : 0,
          };
        }));
        
        // Filter out doctors with no revenue
        const filteredRevenueByDoctor = revenueByDoctor.filter(item => item.revenue > 0);
        
        // Sort by revenue in descending order
        filteredRevenueByDoctor.sort((a, b) => b.revenue - a.revenue);
        
        reportData.data = filteredRevenueByDoctor;
        reportData.summary = {
          totalRevenue: filteredRevenueByDoctor.reduce((sum, item) => sum + item.revenue, 0),
          totalDoctors: filteredRevenueByDoctor.length,
          totalAppointments: filteredRevenueByDoctor.reduce((sum, item) => sum + item.appointmentCount, 0),
        };
        
        // Generate chart if requested
        if (params.includeCharts) {
          const chartPath =