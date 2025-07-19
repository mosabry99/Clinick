/**
 * License Management System
 * 
 * This module provides comprehensive license management functionality including:
 * - JWT-based license validation
 * - Secure license storage in IndexedDB with encryption
 * - License expiration and grace period handling
 * - Subscription status and feature management
 * - License enforcement hooks and utilities
 * - Payment gateway integration
 * - Backup encryption with tenant-specific keys
 * - Admin manual activation
 * - Audit logging for all license operations
 */

import { useEffect, useState, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import jwt_decode from 'jwt-decode';
import CryptoJS from 'crypto-js';
import Dexie from 'dexie';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { License, JwtPayload, ApiResponse } from '../types';

// =============================================================================
// Database Configuration
// =============================================================================

/**
 * License database schema using Dexie
 */
class LicenseDatabase extends Dexie {
  licenses!: Dexie.Table<EncryptedLicense, string>;
  licenseAuditLogs!: Dexie.Table<LicenseAuditLog, string>;

  constructor() {
    super('ClinicLicenseDB');
    this.version(1).stores({
      licenses: 'id, tenantId, status, expiresAt',
      licenseAuditLogs: '++id, timestamp, action, licenseId, userId, details'
    });
  }
}

const db = new LicenseDatabase();

// =============================================================================
// Types
// =============================================================================

/**
 * License status types
 */
export enum LicenseStatus {
  ACTIVE = 'active',
  TRIAL = 'trial',
  GRACE_PERIOD = 'grace_period',
  EXPIRED = 'expired',
  SUSPENDED = 'suspended',
  REVOKED = 'revoked',
  PENDING_ACTIVATION = 'pending_activation'
}

/**
 * License plan types
 */
export enum LicensePlan {
  FREE = 'free',
  BASIC = 'basic',
  PROFESSIONAL = 'professional',
  ENTERPRISE = 'enterprise'
}

/**
 * License features
 */
export enum LicenseFeature {
  APPOINTMENTS = 'appointments',
  PATIENTS = 'patients',
  BILLING = 'billing',
  INVENTORY = 'inventory',
  REPORTING = 'reporting',
  MULTI_DOCTOR = 'multi_doctor',
  TELEMEDICINE = 'telemedicine',
  API_ACCESS = 'api_access',
  CUSTOM_BRANDING = 'custom_branding',
  BACKUP_RESTORE = 'backup_restore',
  ADVANCED_SECURITY = 'advanced_security',
  THIRD_PARTY_INTEGRATIONS = 'third_party_integrations'
}

/**
 * License mode
 */
export enum LicenseMode {
  FULL = 'full',
  READ_ONLY = 'read_only',
  RESTRICTED = 'restricted',
  BACKUP_ONLY = 'backup_only'
}

/**
 * License source
 */
export enum LicenseSource {
  ONLINE_PURCHASE = 'online_purchase',
  MANUAL_ACTIVATION = 'manual_activation',
  IMPORTED = 'imported',
  TRIAL = 'trial'
}

/**
 * Payment gateway types
 */
export enum PaymentGateway {
  CREEM = 'creem',
  PAYMOB = 'paymob',
  MANUAL = 'manual'
}

/**
 * License activation request
 */
export interface LicenseActivationRequest {
  activationCode?: string;
  email: string;
  tenantId: string;
  planId: string;
  gateway?: PaymentGateway;
  gatewayTransactionId?: string;
  manualActivationCode?: string;
}

/**
 * License activation response
 */
export interface LicenseActivationResponse {
  success: boolean;
  license?: License;
  token?: string;
  error?: string;
  redirectUrl?: string;
}

/**
 * Encrypted license for storage
 */
interface EncryptedLicense {
  id: string;
  tenantId: string;
  encryptedData: string;
  iv: string;
  status: LicenseStatus;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * License audit log entry
 */
interface LicenseAuditLog {
  id?: string;
  timestamp: Date;
  action: string;
  licenseId: string;
  userId?: string;
  details: any;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * License verification result
 */
export interface LicenseVerificationResult {
  isValid: boolean;
  license?: License;
  mode: LicenseMode;
  error?: string;
  gracePeriodRemaining?: number; // in days
}

/**
 * License backup encryption key
 */
export interface LicenseBackupKey {
  tenantId: string;
  key: string;
  iv: string;
  algorithm: string;
  createdAt: Date;
}

// =============================================================================
// Constants
// =============================================================================

/**
 * License configuration constants
 */
export const LICENSE_CONFIG = {
  GRACE_PERIOD_DAYS: 7,
  TOKEN_REFRESH_INTERVAL: 12 * 60 * 60 * 1000, // 12 hours
  ACTIVATION_ENDPOINT: '/api/licenses/activate',
  VERIFICATION_ENDPOINT: '/api/licenses/verify',
  RENEWAL_ENDPOINT: '/api/licenses/renew',
  LOCAL_STORAGE_KEY: 'clinick_license_token',
  ENCRYPTION_SECRET_KEY: 'CLINICK_LICENSE_ENCRYPTION_KEY',
  JWT_SECRET: process.env.REACT_APP_LICENSE_JWT_SECRET || 'clinick_license_secret',
  PUBLIC_ROUTES: [
    '/activate',
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/verify-email',
    '/terms',
    '/privacy',
    '/help'
  ],
  PAYMENT_GATEWAYS: {
    [PaymentGateway.CREEM]: {
      name: 'Creem.io',
      checkoutUrl: 'https://checkout.creem.io',
      webhookEndpoint: '/api/webhooks/creem'
    },
    [PaymentGateway.PAYMOB]: {
      name: 'Paymob',
      checkoutUrl: 'https://accept.paymob.com/api/acceptance',
      webhookEndpoint: '/api/webhooks/paymob'
    }
  },
  PLAN_FEATURES: {
    [LicensePlan.FREE]: [
      LicenseFeature.APPOINTMENTS,
      LicenseFeature.PATIENTS
    ],
    [LicensePlan.BASIC]: [
      LicenseFeature.APPOINTMENTS,
      LicenseFeature.PATIENTS,
      LicenseFeature.BILLING,
      LicenseFeature.INVENTORY
    ],
    [LicensePlan.PROFESSIONAL]: [
      LicenseFeature.APPOINTMENTS,
      LicenseFeature.PATIENTS,
      LicenseFeature.BILLING,
      LicenseFeature.INVENTORY,
      LicenseFeature.REPORTING,
      LicenseFeature.MULTI_DOCTOR,
      LicenseFeature.BACKUP_RESTORE
    ],
    [LicensePlan.ENTERPRISE]: [
      LicenseFeature.APPOINTMENTS,
      LicenseFeature.PATIENTS,
      LicenseFeature.BILLING,
      LicenseFeature.INVENTORY,
      LicenseFeature.REPORTING,
      LicenseFeature.MULTI_DOCTOR,
      LicenseFeature.TELEMEDICINE,
      LicenseFeature.API_ACCESS,
      LicenseFeature.CUSTOM_BRANDING,
      LicenseFeature.BACKUP_RESTORE,
      LicenseFeature.ADVANCED_SECURITY,
      LicenseFeature.THIRD_PARTY_INTEGRATIONS
    ]
  }
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Generates a secure encryption key for license data
 */
const generateEncryptionKey = (): string => {
  return CryptoJS.lib.WordArray.random(32).toString();
};

/**
 * Encrypts license data for secure storage
 * 
 * @param license License data to encrypt
 * @param secretKey Secret key for encryption
 * @returns Encrypted license data and initialization vector
 */
const encryptLicense = (license: License, secretKey: string): { encryptedData: string, iv: string } => {
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(
    JSON.stringify(license),
    secretKey,
    { iv: iv }
  );

  return {
    encryptedData: encrypted.toString(),
    iv: iv.toString()
  };
};

/**
 * Decrypts license data from secure storage
 * 
 * @param encryptedData Encrypted license data
 * @param iv Initialization vector
 * @param secretKey Secret key for decryption
 * @returns Decrypted license data or null if decryption fails
 */
const decryptLicense = (encryptedData: string, iv: string, secretKey: string): License | null => {
  try {
    const decrypted = CryptoJS.AES.decrypt(
      encryptedData,
      secretKey,
      { iv: CryptoJS.enc.Hex.parse(iv) }
    );
    
    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    if (!decryptedText) {
      return null;
    }
    
    return JSON.parse(decryptedText);
  } catch (error) {
    console.error('License decryption failed:', error);
    return null;
  }
};

/**
 * Verifies a JWT token and extracts the payload
 * 
 * @param token JWT token to verify
 * @returns Decoded JWT payload or null if invalid
 */
const verifyJwtToken = (token: string): JwtPayload | null => {
  try {
    // In a production environment, this would be validated on the server
    // For client-side, we just decode and check expiration
    const decoded = jwt_decode<JwtPayload>(token);
    
    // Check if token is expired
    const currentTime = Math.floor(Date.now() / 1000);
    if (decoded.exp < currentTime) {
      return null;
    }
    
    return decoded;
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
};

/**
 * Calculates the remaining grace period in days
 * 
 * @param expiryDate License expiry date
 * @returns Number of days remaining in grace period, or 0 if expired
 */
const calculateGracePeriod = (expiryDate: Date): number => {
  const now = new Date();
  const expiry = new Date(expiryDate);
  const gracePeriodEnd = new Date(expiry);
  gracePeriodEnd.setDate(gracePeriodEnd.getDate() + LICENSE_CONFIG.GRACE_PERIOD_DAYS);
  
  if (now > gracePeriodEnd) {
    return 0;
  }
  
  const diffTime = gracePeriodEnd.getTime() - now.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
};

/**
 * Determines the license mode based on its status and expiry
 * 
 * @param license License to check
 * @returns The appropriate license mode
 */
const determineLicenseMode = (license: License): LicenseMode => {
  const now = new Date();
  const expiryDate = new Date(license.expiresAt);
  
  if (license.status === LicenseStatus.ACTIVE && now < expiryDate) {
    return LicenseMode.FULL;
  }
  
  if (license.status === LicenseStatus.TRIAL && now < expiryDate) {
    return LicenseMode.FULL;
  }
  
  if (license.status === LicenseStatus.SUSPENDED) {
    return LicenseMode.RESTRICTED;
  }
  
  // Check if in grace period
  const gracePeriodEnd = new Date(expiryDate);
  gracePeriodEnd.setDate(gracePeriodEnd.getDate() + LICENSE_CONFIG.GRACE_PERIOD_DAYS);
  
  if (now < gracePeriodEnd) {
    return LicenseMode.READ_ONLY;
  }
  
  // License is expired beyond grace period
  return LicenseMode.BACKUP_ONLY;
};

/**
 * Generates a backup encryption key based on tenant ID and license key
 * 
 * @param tenantId Tenant ID
 * @param licenseKey License key
 * @returns Backup encryption key object
 */
export const generateBackupEncryptionKey = (tenantId: string, licenseKey: string): LicenseBackupKey => {
  const iv = CryptoJS.lib.WordArray.random(16);
  const salt = CryptoJS.lib.WordArray.random(16);
  
  // Generate a deterministic key based on tenant ID and license key
  const key = CryptoJS.PBKDF2(
    `${tenantId}:${licenseKey}`,
    salt,
    { keySize: 256/32, iterations: 1000 }
  ).toString();
  
  return {
    tenantId,
    key,
    iv: iv.toString(),
    algorithm: 'aes-256-cbc',
    createdAt: new Date()
  };
};

// =============================================================================
// License Service
// =============================================================================

/**
 * License Service for managing license operations
 */
export class LicenseService {
  private static instance: LicenseService;
  private currentLicense: License | null = null;
  private encryptionKey: string;
  private tokenRefreshInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.encryptionKey = localStorage.getItem(LICENSE_CONFIG.ENCRYPTION_SECRET_KEY) || generateEncryptionKey();
    
    // Store the encryption key if it was just generated
    if (!localStorage.getItem(LICENSE_CONFIG.ENCRYPTION_SECRET_KEY)) {
      localStorage.setItem(LICENSE_CONFIG.ENCRYPTION_SECRET_KEY, this.encryptionKey);
    }
  }

  /**
   * Gets the singleton instance of the LicenseService
   */
  public static getInstance(): LicenseService {
    if (!LicenseService.instance) {
      LicenseService.instance = new LicenseService();
    }
    return LicenseService.instance;
  }

  /**
   * Initializes the license service and loads the current license
   */
  public async initialize(): Promise<void> {
    // Load license from storage
    await this.loadCurrentLicense();
    
    // Start token refresh interval
    this.startTokenRefreshInterval();
  }

  /**
   * Loads the current license from storage
   */
  private async loadCurrentLicense(): Promise<void> {
    try {
      // First try to load from localStorage token
      const token = localStorage.getItem(LICENSE_CONFIG.LOCAL_STORAGE_KEY);
      if (token) {
        const payload = verifyJwtToken(token);
        if (payload && payload.licenseId) {
          // Load the full license from IndexedDB
          const encryptedLicense = await db.licenses.get(payload.licenseId);
          if (encryptedLicense) {
            const license = decryptLicense(
              encryptedLicense.encryptedData,
              encryptedLicense.iv,
              this.encryptionKey
            );
            if (license) {
              this.currentLicense = license;
              return;
            }
          }
        }
      }
      
      // If no valid token or license found, try to find the most recent active license
      const encryptedLicenses = await db.licenses
        .where('status')
        .equals(LicenseStatus.ACTIVE)
        .or('status')
        .equals(LicenseStatus.TRIAL)
        .or('status')
        .equals(LicenseStatus.GRACE_PERIOD)
        .toArray();
      
      if (encryptedLicenses.length > 0) {
        // Sort by expiry date, most recent first
        encryptedLicenses.sort((a, b) => 
          new Date(b.expiresAt).getTime() - new Date(a.expiresAt).getTime()
        );
        
        const license = decryptLicense(
          encryptedLicenses[0].encryptedData,
          encryptedLicenses[0].iv,
          this.encryptionKey
        );
        
        if (license) {
          this.currentLicense = license;
          // Generate a new token and store it
          await this.refreshLicenseToken(license);
        }
      }
    } catch (error) {
      console.error('Failed to load license:', error);
      this.currentLicense = null;
    }
  }

  /**
   * Starts the token refresh interval
   */
  private startTokenRefreshInterval(): void {
    if (this.tokenRefreshInterval) {
      clearInterval(this.tokenRefreshInterval);
    }
    
    this.tokenRefreshInterval = setInterval(async () => {
      if (this.currentLicense) {
        await this.refreshLicenseToken(this.currentLicense);
      }
    }, LICENSE_CONFIG.TOKEN_REFRESH_INTERVAL);
  }

  /**
   * Refreshes the license token
   * 
   * @param license License to refresh token for
   */
  private async refreshLicenseToken(license: License): Promise<void> {
    try {
      const response = await axios.post<ApiResponse<{ token: string }>>(
        LICENSE_CONFIG.VERIFICATION_ENDPOINT,
        { licenseId: license.id, licenseKey: license.key }
      );
      
      if (response.data.success && response.data.data?.token) {
        localStorage.setItem(LICENSE_CONFIG.LOCAL_STORAGE_KEY, response.data.data.token);
        
        // Log the token refresh
        await this.logLicenseActivity('token_refresh', license.id, {
          message: 'License token refreshed successfully'
        });
      }
    } catch (error) {
      console.error('Failed to refresh license token:', error);
      
      // Log the failure
      await this.logLicenseActivity('token_refresh_failed', license.id, {
        message: 'Failed to refresh license token',
        error
      });
    }
  }

  /**
   * Activates a license using an activation code or payment information
   * 
   * @param activationRequest License activation request
   * @returns License activation response
   */
  public async activateLicense(activationRequest: LicenseActivationRequest): Promise<LicenseActivationResponse> {
    try {
      // Log the activation attempt
      await this.logLicenseActivity('activation_attempt', 'new', {
        email: activationRequest.email,
        tenantId: activationRequest.tenantId,
        planId: activationRequest.planId,
        gateway: activationRequest.gateway
      });
      
      // Send activation request to the server
      const response = await axios.post<ApiResponse<{
        license: License;
        token: string;
        redirectUrl?: string;
      }>>(LICENSE_CONFIG.ACTIVATION_ENDPOINT, activationRequest);
      
      if (!response.data.success) {
        return {
          success: false,
          error: response.data.error?.message || 'License activation failed'
        };
      }
      
      const { license, token, redirectUrl } = response.data.data!;
      
      // If we have a redirect URL (for payment), return it
      if (redirectUrl) {
        return {
          success: true,
          redirectUrl
        };
      }
      
      // Store the license and token
      await this.storeLicense(license, token);
      
      // Log the successful activation
      await this.logLicenseActivity('activation_success', license.id, {
        message: 'License activated successfully',
        licenseType: license.type,
        expiresAt: license.expiresAt
      });
      
      return {
        success: true,
        license,
        token
      };
    } catch (error) {
      console.error('License activation failed:', error);
      
      // Log the failure
      await this.logLicenseActivity('activation_failed', 'new', {
        message: 'License activation failed',
        error,
        request: activationRequest
      });
      
      return {
        success: false,
        error: 'License activation failed. Please try again or contact support.'
      };
    }
  }

  /**
   * Manually activates a license (admin function)
   * 
   * @param email User email
   * @param tenantId Tenant ID
   * @param planId Plan ID
   * @param expiryDate Expiry date
   * @param adminId Admin user ID
   * @returns License activation response
   */
  public async manuallyActivateLicense(
    email: string,
    tenantId: string,
    planId: string,
    expiryDate: Date,
    adminId: string
  ): Promise<LicenseActivationResponse> {
    try {
      // Log the manual activation attempt
      await this.logLicenseActivity('manual_activation_attempt', 'new', {
        email,
        tenantId,
        planId,
        expiryDate,
        adminId
      });
      
      // Send manual activation request to the server
      const response = await axios.post<ApiResponse<{
        license: License;
        token: string;
      }>>('/api/admin/licenses/manual-activation', {
        email,
        tenantId,
        planId,
        expiryDate,
        adminId
      });
      
      if (!response.data.success) {
        return {
          success: false,
          error: response.data.error?.message || 'Manual license activation failed'
        };
      }
      
      const { license, token } = response.data.data!;
      
      // Store the license and token
      await this.storeLicense(license, token);
      
      // Log the successful manual activation
      await this.logLicenseActivity('manual_activation_success', license.id, {
        message: 'License manually activated successfully',
        licenseType: license.type,
        expiresAt: license.expiresAt,
        adminId
      });
      
      return {
        success: true,
        license,
        token
      };
    } catch (error) {
      console.error('Manual license activation failed:', error);
      
      // Log the failure
      await this.logLicenseActivity('manual_activation_failed', 'new', {
        message: 'Manual license activation failed',
        error,
        email,
        tenantId,
        planId,
        adminId
      });
      
      return {
        success: false,
        error: 'Manual license activation failed. Please try again.'
      };
    }
  }

  /**
   * Stores a license in the database
   * 
   * @param license License to store
   * @param token JWT token for the license
   */
  private async storeLicense(license: License, token: string): Promise<void> {
    try {
      // Encrypt the license data
      const { encryptedData, iv } = encryptLicense(license, this.encryptionKey);
      
      // Store in IndexedDB
      await db.licenses.put({
        id: license.id,
        tenantId: license.tenantId,
        encryptedData,
        iv,
        status: license.status as LicenseStatus,
        expiresAt: new Date(license.expiresAt),
        createdAt: new Date(license.createdAt),
        updatedAt: new Date(license.updatedAt)
      });
      
      // Store the token in localStorage
      localStorage.setItem(LICENSE_CONFIG.LOCAL_STORAGE_KEY, token);
      
      // Update the current license
      this.currentLicense = license;
      
      // Restart token refresh interval
      this.startTokenRefreshInterval();
    } catch (error) {
      console.error('Failed to store license:', error);
      throw error;
    }
  }

  /**
   * Verifies the current license
   * 
   * @returns License verification result
   */
  public async verifyLicense(): Promise<LicenseVerificationResult> {
    try {
      // Check if we have a current license
      if (!this.currentLicense) {
        return {
          isValid: false,
          mode: LicenseMode.RESTRICTED,
          error: 'No license found'
        };
      }
      
      // Check license expiration
      const now = new Date();
      const expiryDate = new Date(this.currentLicense.expiresAt);
      const gracePeriodRemaining = calculateGracePeriod(expiryDate);
      
      // Determine license mode
      const mode = determineLicenseMode(this.currentLicense);
      
      // If the license is in grace period, update its status
      if (now > expiryDate && gracePeriodRemaining > 0 && 
          this.currentLicense.status !== LicenseStatus.GRACE_PERIOD) {
        this.currentLicense.status = LicenseStatus.GRACE_PERIOD;
        
        // Update the license in the database
        const { encryptedData, iv } = encryptLicense(this.currentLicense, this.encryptionKey);
        await db.licenses.update(this.currentLicense.id, {
          status: LicenseStatus.GRACE_PERIOD,
          encryptedData,
          iv,
          updatedAt: new Date()
        });
        
        // Log the grace period status
        await this.logLicenseActivity('entered_grace_period', this.currentLicense.id, {
          message: 'License entered grace period',
          gracePeriodRemaining,
          expiryDate
        });
      }
      
      // If the license is expired beyond grace period, update its status
      if (gracePeriodRemaining === 0 && 
          this.currentLicense.status !== LicenseStatus.EXPIRED) {
        this.currentLicense.status = LicenseStatus.EXPIRED;
        
        // Update the license in the database
        const { encryptedData, iv } = encryptLicense(this.currentLicense, this.encryptionKey);
        await db.licenses.update(this.currentLicense.id, {
          status: LicenseStatus.EXPIRED,
          encryptedData,
          iv,
          updatedAt: new Date()
        });
        
        // Log the expiration
        await this.logLicenseActivity('license_expired', this.currentLicense.id, {
          message: 'License expired',
          expiryDate
        });
      }
      
      // For active or grace period licenses, verify with the server
      if (this.currentLicense.status === LicenseStatus.ACTIVE || 
          this.currentLicense.status === LicenseStatus.TRIAL ||
          this.currentLicense.status === LicenseStatus.GRACE_PERIOD) {
        try {
          const response = await axios.post<ApiResponse<{
            isValid: boolean;
            license?: License;
          }>>(LICENSE_CONFIG.VERIFICATION_ENDPOINT, {
            licenseId: this.currentLicense.id,
            licenseKey: this.currentLicense.key
          });
          
          if (response.data.success && response.data.data?.isValid && response.data.data.license) {
            // Update the license if necessary
            if (JSON.stringify(this.currentLicense) !== JSON.stringify(response.data.data.license)) {
              await this.storeLicense(
                response.data.data.license,
                localStorage.getItem(LICENSE_CONFIG.LOCAL_STORAGE_KEY) || ''
              );
            }
            
            return {
              isValid: true,
              license: response.data.data.license,
              mode,
              gracePeriodRemaining
            };
          }
        } catch (error) {
          console.error('Online license verification failed:', error);
          // Continue with offline verification
        }
      }
      
      // Return the result based on the current license state
      return {
        isValid: mode !== LicenseMode.RESTRICTED && mode !== LicenseMode.BACKUP_ONLY,
        license: this.currentLicense,
        mode,
        gracePeriodRemaining
      };
    } catch (error) {
      console.error('License verification failed:', error);
      
      // Log the verification failure
      if (this.currentLicense) {
        await this.logLicenseActivity('verification_failed', this.currentLicense.id, {
          message: 'License verification failed',
          error
        });
      }
      
      return {
        isValid: false,
        mode: LicenseMode.RESTRICTED,
        error: 'License verification failed'
      };
    }
  }

  /**
   * Checks if a feature is available in the current license
   * 
   * @param feature Feature to check
   * @returns True if the feature is available
   */
  public async isFeatureAvailable(feature: LicenseFeature): Promise<boolean> {
    try {
      const verification = await this.verifyLicense();
      
      // If license is not valid, feature is not available
      if (!verification.isValid || !verification.license) {
        return false;
      }
      
      // Check if the feature is included in the license
      return verification.license.features.includes(feature);
    } catch (error) {
      console.error('Feature check failed:', error);
      return false;
    }
  }

  /**
   * Gets the current license
   * 
   * @returns Current license or null if not available
   */
  public async getCurrentLicense(): Promise<License | null> {
    if (!this.currentLicense) {
      await this.loadCurrentLicense();
    }
    return this.currentLicense;
  }

  /**
   * Renews the current license
   * 
   * @param gateway Payment gateway to use
   * @returns URL to redirect for payment or success status
   */
  public async renewLicense(gateway: PaymentGateway): Promise<{ success: boolean; redirectUrl?: string; error?: string }> {
    try {
      if (!this.currentLicense) {
        return {
          success: false,
          error: 'No license found to renew'
        };
      }
      
      // Log the renewal attempt
      await this.logLicenseActivity('renewal_attempt', this.currentLicense.id, {
        message: 'License renewal attempted',
        gateway
      });
      
      // Send renewal request to the server
      const response = await axios.post<ApiResponse<{
        redirectUrl: string;
      }>>(LICENSE_CONFIG.RENEWAL_ENDPOINT, {
        licenseId: this.currentLicense.id,
        gateway
      });
      
      if (!response.data.success) {
        return {
          success: false,
          error: response.data.error?.message || 'License renewal failed'
        };
      }
      
      // Log the successful renewal request
      await this.logLicenseActivity('renewal_initiated', this.currentLicense.id, {
        message: 'License renewal initiated',
        gateway,
        redirectUrl: response.data.data?.redirectUrl
      });
      
      return {
        success: true,
        redirectUrl: response.data.data?.redirectUrl
      };
    } catch (error) {
      console.error('License renewal failed:', error);
      
      // Log the failure
      if (this.currentLicense) {
        await this.logLicenseActivity('renewal_failed', this.currentLicense.id, {
          message: 'License renewal failed',
          error,
          gateway
        });
      }
      
      return {
        success: false,
        error: 'License renewal failed. Please try again or contact support.'
      };
    }
  }

  /**
   * Generates a backup encryption key for the current license
   * 
   * @returns Backup encryption key
   */
  public async getBackupEncryptionKey(): Promise<LicenseBackupKey | null> {
    try {
      const license = await this.getCurrentLicense();
      if (!license) {
        return null;
      }
      
      return generateBackupEncryptionKey(license.tenantId, license.key);
    } catch (error) {
      console.error('Failed to generate backup encryption key:', error);
      return null;
    }
  }

  /**
   * Logs a license activity for audit purposes
   * 
   * @param action Action performed
   * @param licenseId License ID
   * @param details Additional details
   */
  public async logLicenseActivity(action: string, licenseId: string, details: any): Promise<void> {
    try {
      const logEntry: LicenseAuditLog = {
        id: uuidv4(),
        timestamp: new Date(),
        action,
        licenseId,
        userId: this.getCurrentUserId(),
        details,
        ipAddress: await this.getIpAddress(),
        userAgent: navigator.userAgent
      };
      
      await db.licenseAuditLogs.add(logEntry);
    } catch (error) {
      console.error('Failed to log license activity:', error);
    }
  }

  /**
   * Gets the current user ID from the JWT token
   * 
   * @returns Current user ID or undefined
   */
  private getCurrentUserId(): string | undefined {
    const token = localStorage.getItem(LICENSE_CONFIG.LOCAL_STORAGE_KEY);
    if (!token) {
      return undefined;
    }
    
    const payload = verifyJwtToken(token);
    return payload?.sub;
  }

  /**
   * Gets the client IP address
   * 
   * @returns IP address or undefined
   */
  private async getIpAddress(): Promise<string | undefined> {
    try {
      const response = await axios.get<{ ip: string }>('https://api.ipify.org?format=json');
      return response.data.ip;
    } catch (error) {
      console.error('Failed to get IP address:', error);
      return undefined;
    }
  }

  /**
   * Clears the current license
   */
  public async clearLicense(): Promise<void> {
    try {
      if (this.currentLicense) {
        // Log the license clear
        await this.logLicenseActivity('license_cleared', this.currentLicense.id, {
          message: 'License cleared'
        });
      }
      
      // Clear the token
      localStorage.removeItem(LICENSE_CONFIG.LOCAL_STORAGE_KEY);
      
      // Clear the current license
      this.currentLicense = null;
      
      // Stop the token refresh interval
      if (this.tokenRefreshInterval) {
        clearInterval(this.tokenRefreshInterval);
        this.tokenRefreshInterval = null;
      }
    } catch (error) {
      console.error('Failed to clear license:', error);
    }
  }
}

// =============================================================================
// React Hooks
// =============================================================================

/**
 * Hook for license verification and enforcement
 * 
 * @returns License verification result and utility functions
 */
export const useLicense = () => {
  const [verificationResult, setVerificationResult] = useState<LicenseVerificationResult>({
    isValid: false,
    mode: LicenseMode.RESTRICTED,
    error: 'License not verified yet'
  });
  const [isLoading, setIsLoading] = useState(true);
  const licenseService = LicenseService.getInstance();
  const navigate = useNavigate();
  const location = useLocation();

  const verifyLicense = useCallback(async () => {
    setIsLoading(true);
    try {
      const result = await licenseService.verifyLicense();
      setVerificationResult(result);
      return result;
    } catch (error) {
      console.error('License verification failed:', error);
      setVerificationResult({
        isValid: false,
        mode: LicenseMode.RESTRICTED,
        error: 'License verification failed'
      });
      return null;
    } finally {
      setIsLoading(false);
    }
  }, [licenseService]);

  const activateLicense = useCallback(async (request: LicenseActivationRequest) => {
    return await licenseService.activateLicense(request);
  }, [licenseService]);

  const renewLicense = useCallback(async (gateway: PaymentGateway) => {
    return await licenseService.renewLicense(gateway);
  }, [licenseService]);

  const checkFeature = useCallback(async (feature: LicenseFeature) => {
    return await licenseService.isFeatureAvailable(feature);
  }, [licenseService]);

  const getLicense = useCallback(async () => {
    return await licenseService.getCurrentLicense();
  }, [licenseService]);

  const getBackupKey = useCallback(async () => {
    return await licenseService.getBackupEncryptionKey();
  }, [licenseService]);

  const clearLicense = useCallback(async () => {
    await licenseService.clearLicense();
    navigate('/activate');
  }, [licenseService, navigate]);

  // Effect to verify license on mount and when location changes
  useEffect(() => {
    const checkLicense = async () => {
      const result = await verifyLicense();
      
      // If license is not valid and we're not on a public route, redirect to activation
      if (result && !result.isValid && 
          !LICENSE_CONFIG.PUBLIC_ROUTES.some(route => location.pathname.startsWith(route))) {
        navigate('/activate');
      }
    };
    
    checkLicense();
  }, [location.pathname, navigate, verifyLicense]);

  return {
    verificationResult,
    isLoading,
    verifyLicense,
    activateLicense,
    renewLicense,
    checkFeature,
    getLicense,
    getBackupKey,
    clearLicense
  };
};

/**
 * Hook for feature-based access control
 * 
 * @param requiredFeature Feature required to access the component
 * @param fallback Component to render if feature is not available
 * @returns Whether the feature is available and loading state
 */
export const useFeature = (requiredFeature: LicenseFeature, fallback?: React.ReactNode) => {
  const [isAvailable, setIsAvailable] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const { checkFeature } = useLicense();

  useEffect(() => {
    const checkFeatureAvailability = async () => {
      setIsLoading(true);
      try {
        const available = await checkFeature(requiredFeature);
        setIsAvailable(available);
      } catch (error) {
        console.error(`Failed to check feature ${requiredFeature}:`, error);
        setIsAvailable(false);
      } finally {
        setIsLoading(false);
      }
    };
    
    checkFeatureAvailability();
  }, [checkFeature, requiredFeature]);

  return { isAvailable, isLoading, fallback };
};

/**
 * HOC for feature-based access control
 * 
 * @param WrappedComponent Component to wrap
 * @param requiredFeature Feature required to access the component
 * @param FallbackComponent Component to render if feature is not available
 * @returns Wrapped component with feature check
 */
export function withFeatureAccess<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  requiredFeature: LicenseFeature,
  FallbackComponent?: React.ComponentType<any>
) {
  return function WithFeatureAccess(props: P) {
    const { isAvailable, isLoading } = useFeature(requiredFeature);
    
    if (isLoading) {
      return <div>Loading...</div>;
    }
    
    if (!isAvailable) {
      return FallbackComponent ? <FallbackComponent /> : (
        <div className="p-4 bg-danger-50 text-danger-700 rounded-md">
          <h3 className="font-semibold">Feature Not Available</h3>
          <p>This feature requires a higher license tier. Please upgrade your subscription to access it.</p>
        </div>
      );
    }
    
    return <WrappedComponent {...props} />;
  };
}

/**
 * Component for conditional rendering based on feature availability
 */
export const FeatureGuard: React.FC<{
  feature: LicenseFeature;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}> = ({ feature, children, fallback }) => {
  const { isAvailable, isLoading } = useFeature(feature);
  
  if (isLoading) {
    return <div>Loading...</div>;
  }
  
  if (!isAvailable) {
    return fallback ? <>{fallback}</> : null;
  }
  
  return <>{children}</>;
};

/**
 * Hook for license mode-based access control
 * 
 * @param requiredMode Minimum license mode required
 * @returns Whether the current license mode meets the requirement
 */
export const useLicenseMode = (requiredMode: LicenseMode) => {
  const { verificationResult, isLoading } = useLicense();
  
  const hasAccess = useMemo(() => {
    const modeHierarchy = [
      LicenseMode.RESTRICTED,
      LicenseMode.BACKUP_ONLY,
      LicenseMode.READ_ONLY,
      LicenseMode.FULL
    ];
    
    const currentModeIndex = modeHierarchy.indexOf(verificationResult.mode);
    const requiredModeIndex = modeHierarchy.indexOf(requiredMode);
    
    return currentModeIndex >= requiredModeIndex;
  }, [verificationResult.mode, requiredMode]);
  
  return { hasAccess, currentMode: verificationResult.mode, isLoading };
};

/**
 * Component for conditional rendering based on license mode
 */
export const LicenseModeGuard: React.FC<{
  requiredMode: LicenseMode;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}> = ({ requiredMode, children, fallback }) => {
  const { hasAccess, isLoading } = useLicenseMode(requiredMode);
  
  if (isLoading) {
    return <div>Loading...</div>;
  }
  
  if (!hasAccess) {
    return fallback ? <>{fallback}</> : null;
  }
  
  return <>{children}</>;
};

// =============================================================================
// Payment Gateway Integration
// =============================================================================

/**
 * Creates a payment checkout session with the specified gateway
 * 
 * @param gateway Payment gateway to use
 * @param planId Plan ID to purchase
 * @param email Customer email
 * @param tenantId Tenant ID
 * @returns Checkout URL or error
 */
export const createCheckoutSession = async (
  gateway: PaymentGateway,
  planId: string,
  email: string,
  tenantId: string
): Promise<{ success: boolean; checkoutUrl?: string; error?: string }> => {
  try {
    const response = await axios.post<ApiResponse<{
      checkoutUrl: string;
      sessionId: string;
    }>>('/api/payments/create-checkout', {
      gateway,
      planId,
      email,
      tenantId
    });
    
    if (!response.data.success) {
      return {
        success: false,
        error: response.data.error?.message || 'Failed to create checkout session'
      };
    }
    
    return {
      success: true,
      checkoutUrl: response.data.data?.checkoutUrl
    };
  } catch (error) {
    console.error('Failed to create checkout session:', error);
    return {
      success: false,
      error: 'Failed to create checkout session. Please try again.'
    };
  }
};

/**
 * Handles the payment webhook callback
 * 
 * @param gateway Payment gateway
 * @param data Webhook data
 * @returns Success status
 */
export const handlePaymentWebhook = async (
  gateway: PaymentGateway,
  data: any
): Promise<{ success: boolean; error?: string }> => {
  try {
    const response = await axios.post<ApiResponse<{
      license?: License;
      token?: string;
    }>>(`/api/webhooks/${gateway}`, data);
    
    if (!response.data.success) {
      return {
        success: false,
        error: response.data.error?.message || 'Failed to process payment webhook'
      };
    }
    
    // If we received a license and token, store them
    if (response.data.data?.license && response.data.data.token) {
      await LicenseService.getInstance().storeLicense(
        response.data.data.license,
        response.data.data.token
      );
    }
    
    return { success: true };
  } catch (error) {
    console.error('Failed to handle payment webhook:', error);
    return {
      success: false,
      error: 'Failed to process payment webhook. Please try again.'
    };
  }
};

// Initialize the license service
LicenseService.getInstance().initialize().catch(error => {
  console.error('Failed to initialize license service:', error);
});

export default LicenseService;
