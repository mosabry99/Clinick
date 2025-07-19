/**
 * Main Application Component
 * 
 * This is the root component of the Clinick Medical Clinic Management System.
 * It sets up all the necessary providers and context for the application:
 * - React Router for navigation
 * - License verification and management
 * - Internationalization (i18n) with Arabic/English support
 * - Error boundaries for graceful error handling
 * - PWA service worker registration
 * - React Query for API data fetching and caching
 * - Authentication routing and protection
 * - Theme context for light/dark mode and RTL/LTR support
 */

import React, { useState, useEffect, createContext, useContext, Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import { ErrorBoundary } from 'react-error-boundary';
import { registerSW } from 'virtual:pwa-register';
import { I18nProvider, useI18n, Language, Direction } from './i18n';
import { useLicense, LicenseMode, LicenseService, LicenseStatus } from './core/auth/license';
import LoadingScreen from './ui/components/LoadingScreen';
import ErrorFallback from './ui/components/ErrorFallback';
import MainLayout from './ui/layouts/MainLayout';
import AuthLayout from './ui/layouts/AuthLayout';
import ActivationLayout from './ui/layouts/ActivationLayout';
import PageNotFound from './ui/pages/PageNotFound';
import PWAUpdateNotification from './ui/components/PWAUpdateNotification';
import { Toaster } from './ui/components/Toaster';

// Lazy-loaded pages for code splitting
const Dashboard = lazy(() => import('./modules/dashboard/pages/Dashboard'));
const Appointments = lazy(() => import('./modules/appointments/pages/Appointments'));
const Patients = lazy(() => import('./modules/patients/pages/Patients'));
const Billing = lazy(() => import('./modules/billing/pages/Billing'));
const Inventory = lazy(() => import('./modules/inventory/pages/Inventory'));
const Reports = lazy(() => import('./modules/reports/pages/Reports'));
const Settings = lazy(() => import('./modules/settings/pages/Settings'));
const Profile = lazy(() => import('./modules/profile/pages/Profile'));
const Login = lazy(() => import('./modules/auth/pages/Login'));
const Register = lazy(() => import('./modules/auth/pages/Register'));
const ForgotPassword = lazy(() => import('./modules/auth/pages/ForgotPassword'));
const ResetPassword = lazy(() => import('./modules/auth/pages/ResetPassword'));
const VerifyEmail = lazy(() => import('./modules/auth/pages/VerifyEmail'));
const Activate = lazy(() => import('./modules/activation/pages/Activate'));
const Purchase = lazy(() => import('./modules/activation/pages/Purchase'));
const AdminPanel = lazy(() => import('./modules/admin/pages/AdminPanel'));
const Backup = lazy(() => import('./modules/backup/pages/Backup'));

// Create a query client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      suspense: false,
      useErrorBoundary: true,
    },
    mutations: {
      useErrorBoundary: true,
    },
  },
});

// Register service worker for PWA
const updateSW = registerSW({
  onNeedRefresh() {
    // This will be handled by the PWAUpdateNotification component
  },
  onOfflineReady() {
    console.log('App is ready for offline use');
  },
  immediate: true,
});

// Theme context types
type ThemeMode = 'light' | 'dark' | 'system';

interface ThemeContextType {
  mode: ThemeMode;
  setMode: (mode: ThemeMode) => void;
  isDark: boolean;
}

// Create theme context
const ThemeContext = createContext<ThemeContextType>({
  mode: 'system',
  setMode: () => {},
  isDark: false,
});

// Theme provider component
const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setMode] = useState<ThemeMode>(() => {
    const savedMode = localStorage.getItem('clinick_theme') as ThemeMode | null;
    return savedMode || 'system';
  });

  const [isDark, setIsDark] = useState<boolean>(false);

  useEffect(() => {
    // Save theme preference to localStorage
    localStorage.setItem('clinick_theme', mode);

    // Apply theme to document
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const shouldApplyDark = mode === 'dark' || (mode === 'system' && prefersDark);
    
    setIsDark(shouldApplyDark);
    
    if (shouldApplyDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [mode]);

  // Listen for system theme changes
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleChange = () => {
      if (mode === 'system') {
        setIsDark(mediaQuery.matches);
        if (mediaQuery.matches) {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
      }
    };
    
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [mode]);

  return (
    <ThemeContext.Provider value={{ mode, setMode, isDark }}>
      {children}
    </ThemeContext.Provider>
  );
};

// Hook to use theme context
export const useTheme = () => useContext(ThemeContext);

// Auth protection component
interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredMode?: LicenseMode;
  adminOnly?: boolean;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requiredMode = LicenseMode.FULL,
  adminOnly = false
}) => {
  const location = useLocation();
  const { verificationResult, isLoading } = useLicense();
  const { currentLanguage } = useI18n();
  
  // Get user from local storage or context
  const userString = localStorage.getItem('clinick_user');
  const user = userString ? JSON.parse(userString) : null;
  
  if (isLoading) {
    return <LoadingScreen />;
  }
  
  // Check if user is authenticated
  if (!user) {
    return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}&lang=${currentLanguage}`} replace />;
  }
  
  // Check if admin only and user is not admin
  if (adminOnly && !user.roles.includes('SUPER_ADMIN') && !user.roles.includes('TENANT_ADMIN')) {
    return <Navigate to="/dashboard" replace />;
  }
  
  // Check license mode
  const modeHierarchy = [
    LicenseMode.RESTRICTED,
    LicenseMode.BACKUP_ONLY,
    LicenseMode.READ_ONLY,
    LicenseMode.FULL
  ];
  
  const currentModeIndex = modeHierarchy.indexOf(verificationResult.mode);
  const requiredModeIndex = modeHierarchy.indexOf(requiredMode);
  
  if (currentModeIndex < requiredModeIndex) {
    // If license is in backup-only mode, redirect to backup page
    if (verificationResult.mode === LicenseMode.BACKUP_ONLY) {
      return <Navigate to="/backup" replace />;
    }
    
    // If license is expired or restricted, redirect to activation
    if (verificationResult.mode === LicenseMode.RESTRICTED) {
      return <Navigate to="/activate" replace />;
    }
  }
  
  return <>{children}</>;
};

// Main App component
const App: React.FC = () => {
  const [isInitialized, setIsInitialized] = useState(false);
  
  // Initialize license service
  useEffect(() => {
    const initApp = async () => {
      try {
        await LicenseService.getInstance().initialize();
      } catch (error) {
        console.error('Failed to initialize license service:', error);
      } finally {
        setIsInitialized(true);
      }
    };
    
    initApp();
  }, []);
  
  if (!isInitialized) {
    return <LoadingScreen />;
  }
  
  return (
    <ErrorBoundary FallbackComponent={ErrorFallback}>
      <QueryClientProvider client={queryClient}>
        <I18nProvider>
          <ThemeProvider>
            <Router>
              <AppRoutes />
            </Router>
            <Toaster />
            <PWAUpdateNotification updateSW={updateSW} />
          </ThemeProvider>
        </I18nProvider>
        {process.env.NODE_ENV === 'development' && <ReactQueryDevtools initialIsOpen={false} />}
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

// App routes component
const AppRoutes: React.FC = () => {
  const { verificationResult, isLoading } = useLicense();
  const location = useLocation();
  
  // Public routes that don't require authentication or license
  const publicRoutes = [
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/verify-email',
    '/activate',
    '/purchase'
  ];
  
  const isPublicRoute = publicRoutes.some(route => location.pathname.startsWith(route));
  
  // If still loading license verification and not on a public route, show loading screen
  if (isLoading && !isPublicRoute) {
    return <LoadingScreen />;
  }
  
  // If license is not valid and not on a public route, redirect to activation
  if (!isPublicRoute && !verificationResult.isValid && 
      location.pathname !== '/backup' && 
      verificationResult.mode === LicenseMode.RESTRICTED) {
    return <Navigate to="/activate" replace />;
  }
  
  // If license is in backup-only mode and not on backup page, redirect to backup page
  if (!isPublicRoute && 
      verificationResult.mode === LicenseMode.BACKUP_ONLY && 
      location.pathname !== '/backup') {
    return <Navigate to="/backup" replace />;
  }
  
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<AuthLayout><Login /></AuthLayout>} />
        <Route path="/register" element={<AuthLayout><Register /></AuthLayout>} />
        <Route path="/forgot-password" element={<AuthLayout><ForgotPassword /></AuthLayout>} />
        <Route path="/reset-password" element={<AuthLayout><ResetPassword /></AuthLayout>} />
        <Route path="/verify-email" element={<AuthLayout><VerifyEmail /></AuthLayout>} />
        
        {/* Activation Routes */}
        <Route path="/activate" element={<ActivationLayout><Activate /></ActivationLayout>} />
        <Route path="/purchase" element={<ActivationLayout><Purchase /></ActivationLayout>} />
        
        {/* Backup Route - Available in BACKUP_ONLY mode */}
        <Route path="/backup" element={
          <ProtectedRoute requiredMode={LicenseMode.BACKUP_ONLY}>
            <MainLayout>
              <Backup />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        {/* Protected Routes */}
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <MainLayout>
              <Dashboard />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/appointments/*" element={
          <ProtectedRoute>
            <MainLayout>
              <Appointments />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/patients/*" element={
          <ProtectedRoute>
            <MainLayout>
              <Patients />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/billing/*" element={
          <ProtectedRoute>
            <MainLayout>
              <Billing />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/inventory/*" element={
          <ProtectedRoute>
            <MainLayout>
              <Inventory />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/reports/*" element={
          <ProtectedRoute>
            <MainLayout>
              <Reports />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/settings/*" element={
          <ProtectedRoute>
            <MainLayout>
              <Settings />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/profile" element={
          <ProtectedRoute>
            <MainLayout>
              <Profile />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        {/* Admin Routes */}
        <Route path="/admin/*" element={
          <ProtectedRoute adminOnly>
            <MainLayout>
              <AdminPanel />
            </MainLayout>
          </ProtectedRoute>
        } />
        
        {/* Redirect root to dashboard or activate */}
        <Route path="/" element={
          verificationResult.isValid 
            ? <Navigate to="/dashboard" replace /> 
            : <Navigate to="/activate" replace />
        } />
        
        {/* 404 Not Found */}
        <Route path="*" element={<PageNotFound />} />
      </Routes>
    </Suspense>
  );
};

export default App;
