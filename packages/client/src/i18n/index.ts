/**
 * Internationalization (i18n) Configuration
 * 
 * This module sets up i18next with React integration, providing:
 * - Language detection from browser/localStorage
 * - Lazy loading of translation files
 * - RTL/LTR direction switching
 * - Arabic and English language support
 * - Medical terminology translation handling
 * - Number and date formatting
 * - Fallback language handling
 * - Translation key validation
 * - Dynamic language switching
 */

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import Backend from 'i18next-http-backend';
import { format as formatDate, formatDistance, formatRelative } from 'date-fns';
import { enUS, arSA } from 'date-fns/locale';
import { useState, useEffect, createContext, useContext, useMemo } from 'react';

// =============================================================================
// Types
// =============================================================================

/**
 * Supported languages
 */
export enum Language {
  ENGLISH = 'en',
  ARABIC = 'ar'
}

/**
 * Language direction
 */
export enum Direction {
  LTR = 'ltr',
  RTL = 'rtl'
}

/**
 * Language metadata
 */
export interface LanguageInfo {
  code: Language;
  name: string;
  nativeName: string;
  direction: Direction;
  dateLocale: Locale;
  flagIcon: string;
}

/**
 * i18n context type
 */
export interface I18nContextType {
  currentLanguage: Language;
  direction: Direction;
  changeLanguage: (lang: Language) => Promise<void>;
  languages: Record<Language, LanguageInfo>;
  formatDate: (date: Date | string | number, format?: string) => string;
  formatRelativeTime: (date: Date | string | number) => string;
  formatDistance: (date: Date | string | number, baseDate: Date | string | number) => string;
  formatNumber: (num: number, options?: Intl.NumberFormatOptions) => string;
  formatCurrency: (amount: number, currency?: string) => string;
}

// =============================================================================
// Constants
// =============================================================================

/**
 * Language information for supported languages
 */
export const LANGUAGES: Record<Language, LanguageInfo> = {
  [Language.ENGLISH]: {
    code: Language.ENGLISH,
    name: 'English',
    nativeName: 'English',
    direction: Direction.LTR,
    dateLocale: enUS,
    flagIcon: '/icons/flags/us.svg'
  },
  [Language.ARABIC]: {
    code: Language.ARABIC,
    name: 'Arabic',
    nativeName: 'العربية',
    direction: Direction.RTL,
    dateLocale: arSA,
    flagIcon: '/icons/flags/sa.svg'
  }
};

/**
 * Default language
 */
export const DEFAULT_LANGUAGE = Language.ENGLISH;

/**
 * Default number format options
 */
export const DEFAULT_NUMBER_FORMAT: Intl.NumberFormatOptions = {
  style: 'decimal',
  minimumFractionDigits: 0,
  maximumFractionDigits: 2
};

/**
 * Default currency format options
 */
export const DEFAULT_CURRENCY_FORMAT: Intl.NumberFormatOptions = {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 2,
  maximumFractionDigits: 2
};

/**
 * Default date format
 */
export const DEFAULT_DATE_FORMAT = 'PPP';

/**
 * Namespace for medical terminology
 */
export const MEDICAL_NAMESPACE = 'medical';

/**
 * Available namespaces
 */
export const NAMESPACES = ['common', 'auth', 'patients', 'appointments', 'billing', 'inventory', MEDICAL_NAMESPACE];

// =============================================================================
// i18next Configuration
// =============================================================================

/**
 * Initialize i18next with all required configurations
 */
i18n
  // Load translations from server
  .use(Backend)
  // Detect user language
  .use(LanguageDetector)
  // Pass i18n instance to react-i18next
  .use(initReactI18next)
  // Initialize i18next
  .init({
    // Default language
    fallbackLng: DEFAULT_LANGUAGE,
    // Debug mode in development
    debug: process.env.NODE_ENV === 'development',
    // Default namespace
    defaultNS: 'common',
    // All namespaces to load
    ns: NAMESPACES,
    // Fallback namespaces
    fallbackNS: 'common',
    // Lazy load translations
    partialBundledLanguages: true,
    // Backend configuration
    backend: {
      // Path to load translations from
      loadPath: '/locales/{{lng}}/{{ns}}.json',
      // Allow cross-domain requests
      crossDomain: true,
      // Request timeout
      requestOptions: {
        timeout: 5000
      }
    },
    // Language detection options
    detection: {
      // Order of detection
      order: ['localStorage', 'cookie', 'navigator', 'htmlTag'],
      // Cache language in localStorage
      caches: ['localStorage'],
      // localStorage key
      lookupLocalStorage: 'clinick_language',
      // Cookie options
      lookupCookie: 'clinick_language',
      cookieExpirationDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
      // HTML attribute
      lookupFromPathIndex: 0
    },
    // Interpolation options
    interpolation: {
      // React already safes from XSS
      escapeValue: false,
      // Format function for dates, numbers, etc.
      format: (value, format, lng) => {
        if (value instanceof Date) {
          // Format date based on language
          const locale = lng === Language.ARABIC ? arSA : enUS;
          return formatDate(value, format || DEFAULT_DATE_FORMAT, { locale });
        }
        
        // Format numbers
        if (typeof value === 'number') {
          // Currency format
          if (format?.startsWith('currency:')) {
            const currency = format.split(':')[1] || 'USD';
            return new Intl.NumberFormat(lng, {
              ...DEFAULT_CURRENCY_FORMAT,
              currency
            }).format(value);
          }
          
          // Regular number format
          return new Intl.NumberFormat(lng, DEFAULT_NUMBER_FORMAT).format(value);
        }
        
        return value;
      }
    },
    // React options
    react: {
      // Wait for translations to be loaded
      useSuspense: true,
      // Bind events to document
      bindI18n: 'languageChanged loaded',
      // Bind store events
      bindStore: 'added removed',
      // Use translation function
      transEmptyNodeValue: '',
      // Default translation value when key is missing
      defaultTransParent: 'div',
      // Transform keys
      transSupportBasicHtmlNodes: true,
      transKeepBasicHtmlNodesFor: ['br', 'strong', 'i', 'em', 'b', 'p', 'span']
    },
    // Load missing translations in development
    saveMissing: process.env.NODE_ENV === 'development',
    // Missing translation handling
    missingKeyHandler: (lng, ns, key, fallbackValue) => {
      if (process.env.NODE_ENV === 'development') {
        console.warn(`Missing translation key: ${key} in namespace: ${ns} for language: ${lng}`);
      }
    },
    // Additional options
    returnNull: false,
    returnEmptyString: false,
    returnObjects: true,
    joinArrays: '\n',
    // Pluralization rules for Arabic
    pluralRules: {
      ar: {
        numbers: [0, 1, 2, 3, 11, 100],
        plurals: (n: number) => {
          if (n === 0) return 0;
          if (n === 1) return 1;
          if (n === 2) return 2;
          if (n % 100 >= 3 && n % 100 <= 10) return 3;
          if (n % 100 >= 11) return 4;
          return 5;
        }
      }
    }
  });

// =============================================================================
// React Context for i18n
// =============================================================================

/**
 * Create i18n context
 */
export const I18nContext = createContext<I18nContextType>({
  currentLanguage: DEFAULT_LANGUAGE,
  direction: LANGUAGES[DEFAULT_LANGUAGE].direction,
  changeLanguage: async () => {},
  languages: LANGUAGES,
  formatDate: () => '',
  formatRelativeTime: () => '',
  formatDistance: () => '',
  formatNumber: () => '',
  formatCurrency: () => ''
});

/**
 * i18n provider component
 */
export const I18nProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Current language state
  const [currentLanguage, setCurrentLanguage] = useState<Language>(
    (i18n.language as Language) || DEFAULT_LANGUAGE
  );
  
  // Current direction based on language
  const direction = useMemo(
    () => LANGUAGES[currentLanguage]?.direction || Direction.LTR,
    [currentLanguage]
  );
  
  // Update document direction when language changes
  useEffect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = currentLanguage;
    
    // Add RTL/LTR class to body for styling
    if (direction === Direction.RTL) {
      document.body.classList.add('rtl');
      document.body.classList.remove('ltr');
    } else {
      document.body.classList.add('ltr');
      document.body.classList.remove('rtl');
    }
    
    // Load appropriate font styles
    const fontLink = document.getElementById('language-font') as HTMLLinkElement || document.createElement('link');
    fontLink.id = 'language-font';
    fontLink.rel = 'stylesheet';
    
    if (currentLanguage === Language.ARABIC) {
      fontLink.href = 'https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@300;400;500;600;700&display=swap';
    } else {
      fontLink.href = 'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap';
    }
    
    if (!document.getElementById('language-font')) {
      document.head.appendChild(fontLink);
    }
  }, [direction, currentLanguage]);
  
  // Listen for language changes from i18next
  useEffect(() => {
    const handleLanguageChanged = (lng: string) => {
      setCurrentLanguage(lng as Language);
    };
    
    i18n.on('languageChanged', handleLanguageChanged);
    
    return () => {
      i18n.off('languageChanged', handleLanguageChanged);
    };
  }, []);
  
  // Change language function
  const changeLanguage = async (lang: Language) => {
    if (Object.values(Language).includes(lang)) {
      await i18n.changeLanguage(lang);
      setCurrentLanguage(lang);
      localStorage.setItem('clinick_language', lang);
    }
  };
  
  // Date formatting function
  const formatDateFn = (date: Date | string | number, format?: string) => {
    const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;
    const locale = LANGUAGES[currentLanguage].dateLocale;
    return formatDate(dateObj, format || DEFAULT_DATE_FORMAT, { locale });
  };
  
  // Relative time formatting function
  const formatRelativeTimeFn = (date: Date | string | number) => {
    const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;
    const locale = LANGUAGES[currentLanguage].dateLocale;
    return formatRelative(dateObj, new Date(), { locale });
  };
  
  // Distance formatting function
  const formatDistanceFn = (date: Date | string | number, baseDate: Date | string | number) => {
    const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;
    const baseDateObj = typeof baseDate === 'string' || typeof baseDate === 'number' ? new Date(baseDate) : baseDate;
    const locale = LANGUAGES[currentLanguage].dateLocale;
    return formatDistance(dateObj, baseDateObj, { locale, addSuffix: true });
  };
  
  // Number formatting function
  const formatNumberFn = (num: number, options?: Intl.NumberFormatOptions) => {
    return new Intl.NumberFormat(currentLanguage, {
      ...DEFAULT_NUMBER_FORMAT,
      ...options
    }).format(num);
  };
  
  // Currency formatting function
  const formatCurrencyFn = (amount: number, currency = 'USD') => {
    return new Intl.NumberFormat(currentLanguage, {
      ...DEFAULT_CURRENCY_FORMAT,
      currency
    }).format(amount);
  };
  
  // Context value
  const contextValue: I18nContextType = {
    currentLanguage,
    direction,
    changeLanguage,
    languages: LANGUAGES,
    formatDate: formatDateFn,
    formatRelativeTime: formatRelativeTimeFn,
    formatDistance: formatDistanceFn,
    formatNumber: formatNumberFn,
    formatCurrency: formatCurrencyFn
  };
  
  return (
    <I18nContext.Provider value={contextValue}>
      {children}
    </I18nContext.Provider>
  );
};

// =============================================================================
// React Hooks
// =============================================================================

/**
 * Hook to access i18n context
 */
export const useI18n = () => useContext(I18nContext);

/**
 * Hook for medical terminology translations
 */
export const useMedicalTerminology = () => {
  const { t } = useTranslation(MEDICAL_NAMESPACE);
  
  return {
    /**
     * Translate a medical term
     */
    translateMedicalTerm: (term: string, options?: any) => t(term, options),
    
    /**
     * Translate a diagnosis code (ICD-10)
     */
    translateDiagnosisCode: (code: string, options?: any) => t(`diagnosis.${code}`, options),
    
    /**
     * Translate a medication name
     */
    translateMedication: (medication: string, options?: any) => t(`medication.${medication}`, options),
    
    /**
     * Translate a procedure code
     */
    translateProcedure: (procedure: string, options?: any) => t(`procedure.${procedure}`, options),
    
    /**
     * Translate a lab test name
     */
    translateLabTest: (test: string, options?: any) => t(`labTest.${test}`, options),
    
    /**
     * Get all available medical specialties
     */
    getSpecialties: () => t('specialties', { returnObjects: true }) as string[]
  };
};

/**
 * Re-export useTranslation from react-i18next
 */
export { useTranslation } from 'react-i18next';

/**
 * Export i18n instance
 */
export default i18n;
