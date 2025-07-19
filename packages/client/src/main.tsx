/**
 * Main Entry Point for Clinick Medical Clinic Management System
 * 
 * This file initializes the React application with:
 * - React 18 concurrent features via createRoot
 * - Global styles and TailwindCSS
 * - Error handling for the entire application
 * - Strict Mode for development best practices
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

// Import global styles and TailwindCSS
import './styles/index.css';
import './styles/tailwind.css';

// Error handling for the entire application
const handleError = (error: Error, errorInfo: React.ErrorInfo) => {
  console.error('Application Error:', error);
  console.error('Error Info:', errorInfo);
  
  // In production, you might want to send this to an error tracking service
  if (process.env.NODE_ENV === 'production') {
    // Example: sendToErrorTrackingService(error, errorInfo);
  }
};

// Error boundary class for the entire application
class AppErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(_: Error) {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    handleError(error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-neutral-50 dark:bg-neutral-900 text-neutral-900 dark:text-neutral-50">
          <div className="max-w-md p-6 bg-white dark:bg-neutral-800 rounded-lg shadow-lg">
            <h1 className="text-2xl font-bold text-danger-600 dark:text-danger-400 mb-4">
              Something went wrong
            </h1>
            <p className="mb-4">
              We apologize for the inconvenience. Please try refreshing the page or contact support if the problem persists.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-md transition-colors"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Get the root element
const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Failed to find the root element. Make sure there is a div with id "root" in your HTML.');
}

// Create root using React 18's concurrent features
const root = createRoot(rootElement);

// Render the application wrapped in StrictMode and ErrorBoundary
root.render(
  <React.StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>
);
