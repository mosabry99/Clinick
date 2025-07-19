import type { Config } from 'tailwindcss';
import plugin from 'tailwindcss/plugin';

export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
    './src/modules/**/*.{js,ts,jsx,tsx}',
    './src/ui/**/*.{js,ts,jsx,tsx}',
    './src/core/**/*.{js,ts,jsx,tsx}'
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Medical/Healthcare color palette
        primary: {
          50: '#eef8ff',
          100: '#d9eeff',
          200: '#bce0ff',
          300: '#8ecdff',
          400: '#59b0ff',
          500: '#3690fe',
          600: '#1a70f5',
          700: '#1359e2',
          800: '#1747b7',
          900: '#19408f',
          950: '#142a5a',
        },
        secondary: {
          50: '#f0fdf6',
          100: '#dcfceb',
          200: '#bbf5d7',
          300: '#86e9bc',
          400: '#4fd496',
          500: '#27b674',
          600: '#179560',
          700: '#137750',
          800: '#125f43',
          900: '#114e38',
          950: '#072c1f',
        },
        accent: {
          50: '#fff8ed',
          100: '#ffefd4',
          200: '#ffdca8',
          300: '#ffc271',
          400: '#ff9e38',
          500: '#ff7e10',
          600: '#f85d04',
          700: '#cc4302',
          800: '#a13508',
          900: '#832e0c',
          950: '#461505',
        },
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
          950: '#450a0a',
        },
        success: {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
        },
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
          950: '#451a03',
        },
        info: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        // Neutral colors
        neutral: {
          50: '#f9fafb',
          100: '#f3f4f6',
          200: '#e5e7eb',
          300: '#d1d5db',
          400: '#9ca3af',
          500: '#6b7280',
          600: '#4b5563',
          700: '#374151',
          800: '#1f2937',
          900: '#111827',
          950: '#030712',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          'Noto Sans',
          'Noto Sans Arabic',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        serif: [
          'Noto Serif',
          'Noto Serif Arabic',
          'ui-serif',
          'Georgia',
          'Cambria',
          'Times New Roman',
          'Times',
          'serif',
        ],
        mono: [
          'JetBrains Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'Liberation Mono',
          'Courier New',
          'monospace',
        ],
      },
      spacing: {
        '4.5': '1.125rem',
        '18': '4.5rem',
        '68': '17rem',
        '128': '32rem',
        '144': '36rem',
      },
      borderRadius: {
        '4xl': '2rem',
        '5xl': '2.5rem',
      },
      boxShadow: {
        'inner-lg': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.1)',
        'card': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        'card-hover': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'fade-out': {
          '0%': { opacity: '1' },
          '100%': { opacity: '0' },
        },
        'slide-in-right': {
          '0%': { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(0)' },
        },
        'slide-out-right': {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(100%)' },
        },
        'slide-in-left': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(0)' },
        },
        'slide-out-left': {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-100%)' },
        },
        'slide-in-top': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(0)' },
        },
        'slide-out-top': {
          '0%': { transform: 'translateY(0)' },
          '100%': { transform: 'translateY(-100%)' },
        },
        'slide-in-bottom': {
          '0%': { transform: 'translateY(100%)' },
          '100%': { transform: 'translateY(0)' },
        },
        'slide-out-bottom': {
          '0%': { transform: 'translateY(0)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'pulse-scale': {
          '0%, 100%': { transform: 'scale(1)' },
          '50%': { transform: 'scale(1.05)' },
        },
        'bounce-light': {
          '0%, 100%': {
            transform: 'translateY(0)',
            animationTimingFunction: 'cubic-bezier(0.8, 0, 1, 1)',
          },
          '50%': {
            transform: 'translateY(-5px)',
            animationTimingFunction: 'cubic-bezier(0, 0, 0.2, 1)',
          },
        },
        'spin-slow': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.3s ease-in-out',
        'fade-out': 'fade-out 0.3s ease-in-out',
        'slide-in-right': 'slide-in-right 0.3s ease-in-out',
        'slide-out-right': 'slide-out-right 0.3s ease-in-out',
        'slide-in-left': 'slide-in-left 0.3s ease-in-out',
        'slide-out-left': 'slide-out-left 0.3s ease-in-out',
        'slide-in-top': 'slide-in-top 0.3s ease-in-out',
        'slide-out-top': 'slide-out-top 0.3s ease-in-out',
        'slide-in-bottom': 'slide-in-bottom 0.3s ease-in-out',
        'slide-out-bottom': 'slide-out-bottom 0.3s ease-in-out',
        'pulse-scale': 'pulse-scale 2s ease-in-out infinite',
        'bounce-light': 'bounce-light 1.5s infinite',
        'spin-slow': 'spin-slow 3s linear infinite',
      },
      screens: {
        'xs': '480px',
        '3xl': '1920px',
      },
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
    },
  },
  plugins: [
    // RTL support plugin
    plugin(({ addUtilities, addVariant }) => {
      // RTL variants
      addVariant('rtl', '[dir="rtl"] &');
      addVariant('ltr', '[dir="ltr"] &');
      
      // RTL utilities
      addUtilities({
        '.text-start': {
          'text-align': 'start',
        },
        '.text-end': {
          'text-align': 'end',
        },
        '.float-start': {
          'float': 'inline-start',
        },
        '.float-end': {
          'float': 'inline-end',
        },
        '.me-auto': {
          'margin-inline-end': 'auto',
        },
        '.ms-auto': {
          'margin-inline-start': 'auto',
        },
        '.ps-0': {
          'padding-inline-start': '0',
        },
        '.ps-1': {
          'padding-inline-start': '0.25rem',
        },
        '.ps-2': {
          'padding-inline-start': '0.5rem',
        },
        '.ps-3': {
          'padding-inline-start': '0.75rem',
        },
        '.ps-4': {
          'padding-inline-start': '1rem',
        },
        '.pe-0': {
          'padding-inline-end': '0',
        },
        '.pe-1': {
          'padding-inline-end': '0.25rem',
        },
        '.pe-2': {
          'padding-inline-end': '0.5rem',
        },
        '.pe-3': {
          'padding-inline-end': '0.75rem',
        },
        '.pe-4': {
          'padding-inline-end': '1rem',
        },
        '.ms-0': {
          'margin-inline-start': '0',
        },
        '.ms-1': {
          'margin-inline-start': '0.25rem',
        },
        '.ms-2': {
          'margin-inline-start': '0.5rem',
        },
        '.ms-3': {
          'margin-inline-start': '0.75rem',
        },
        '.ms-4': {
          'margin-inline-start': '1rem',
        },
        '.me-0': {
          'margin-inline-end': '0',
        },
        '.me-1': {
          'margin-inline-end': '0.25rem',
        },
        '.me-2': {
          'margin-inline-end': '0.5rem',
        },
        '.me-3': {
          'margin-inline-end': '0.75rem',
        },
        '.me-4': {
          'margin-inline-end': '1rem',
        },
        '.rounded-start': {
          'border-start-start-radius': '0.25rem',
          'border-end-start-radius': '0.25rem',
        },
        '.rounded-end': {
          'border-start-end-radius': '0.25rem',
          'border-end-end-radius': '0.25rem',
        },
        '.border-start': {
          'border-inline-start-width': '1px',
        },
        '.border-end': {
          'border-inline-end-width': '1px',
        },
      });
    }),
    
    // Form elements plugin
    plugin(({ addComponents }) => {
      addComponents({
        '.btn': {
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '0.375rem',
          padding: '0.5rem 1rem',
          fontSize: '0.875rem',
          fontWeight: '500',
          lineHeight: '1.25rem',
          transitionProperty: 'color, background-color, border-color, text-decoration-color, fill, stroke',
          transitionTimingFunction: 'cubic-bezier(0.4, 0, 0.2, 1)',
          transitionDuration: '150ms',
          '&:focus': {
            outline: '2px solid transparent',
            outlineOffset: '2px',
          },
          '&:disabled': {
            opacity: '0.65',
            pointerEvents: 'none',
          },
        },
        '.btn-primary': {
          backgroundColor: 'var(--color-primary-600)',
          color: 'white',
          '&:hover': {
            backgroundColor: 'var(--color-primary-700)',
          },
          '&:focus': {
            boxShadow: '0 0 0 2px var(--color-primary-200)',
          },
        },
        '.btn-secondary': {
          backgroundColor: 'var(--color-secondary-600)',
          color: 'white',
          '&:hover': {
            backgroundColor: 'var(--color-secondary-700)',
          },
          '&:focus': {
            boxShadow: '0 0 0 2px var(--color-secondary-200)',
          },
        },
        '.btn-danger': {
          backgroundColor: 'var(--color-danger-600)',
          color: 'white',
          '&:hover': {
            backgroundColor: 'var(--color-danger-700)',
          },
          '&:focus': {
            boxShadow: '0 0 0 2px var(--color-danger-200)',
          },
        },
        '.btn-outline': {
          backgroundColor: 'transparent',
          borderWidth: '1px',
          borderColor: 'var(--color-primary-600)',
          color: 'var(--color-primary-600)',
          '&:hover': {
            backgroundColor: 'var(--color-primary-50)',
          },
          '&:focus': {
            boxShadow: '0 0 0 2px var(--color-primary-200)',
          },
        },
        '.form-input': {
          display: 'block',
          width: '100%',
          padding: '0.5rem 0.75rem',
          borderRadius: '0.375rem',
          borderWidth: '1px',
          borderColor: 'var(--color-neutral-300)',
          backgroundColor: 'white',
          fontSize: '0.875rem',
          lineHeight: '1.25rem',
          '&:focus': {
            outline: 'none',
            borderColor: 'var(--color-primary-500)',
            boxShadow: '0 0 0 1px var(--color-primary-500)',
          },
          '&:disabled': {
            backgroundColor: 'var(--color-neutral-100)',
            opacity: '0.65',
          },
        },
        '.form-select': {
          display: 'block',
          width: '100%',
          padding: '0.5rem 2rem 0.5rem 0.75rem',
          borderRadius: '0.375rem',
          borderWidth: '1px',
          borderColor: 'var(--color-neutral-300)',
          backgroundColor: 'white',
          backgroundImage: `url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e")`,
          backgroundPosition: 'right 0.5rem center',
          backgroundRepeat: 'no-repeat',
          backgroundSize: '1.5em 1.5em',
          fontSize: '0.875rem',
          lineHeight: '1.25rem',
          appearance: 'none',
          '&:focus': {
            outline: 'none',
            borderColor: 'var(--color-primary-500)',
            boxShadow: '0 0 0 1px var(--color-primary-500)',
          },
          '&:disabled': {
            backgroundColor: 'var(--color-neutral-100)',
            opacity: '0.65',
          },
        },
        '.form-checkbox': {
          appearance: 'none',
          colorAdjust: 'exact',
          display: 'inline-block',
          verticalAlign: 'middle',
          backgroundOrigin: 'border-box',
          userSelect: 'none',
          flexShrink: '0',
          height: '1rem',
          width: '1rem',
          borderRadius: '0.25rem',
          borderWidth: '1px',
          borderColor: 'var(--color-neutral-300)',
          backgroundColor: 'white',
          '&:checked': {
            borderColor: 'transparent',
            backgroundColor: 'var(--color-primary-600)',
            backgroundImage: `url("data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3cpath d='M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z'/%3e%3c/svg%3e")`,
            backgroundSize: '100% 100%',
            backgroundPosition: 'center',
            backgroundRepeat: 'no-repeat',
          },
          '&:focus': {
            outline: 'none',
            boxShadow: '0 0 0 2px var(--color-primary-200)',
          },
        },
        '.form-radio': {
          appearance: 'none',
          colorAdjust: 'exact',
          display: 'inline-block',
          verticalAlign: 'middle',
          backgroundOrigin: 'border-box',
          userSelect: 'none',
          flexShrink: '0',
          height: '1rem',
          width: '1rem',
          borderRadius: '100%',
          borderWidth: '1px',
          borderColor: 'var(--color-neutral-300)',
          backgroundColor: 'white',
          '&:checked': {
            borderColor: 'transparent',
            backgroundColor: 'var(--color-primary-600)',
            backgroundImage: `url("data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3ccircle cx='8' cy='8' r='3'/%3e%3c/svg%3e")`,
            backgroundSize: '100% 100%',
            backgroundPosition: 'center',
            backgroundRepeat: 'no-repeat',
          },
          '&:focus': {
            outline: 'none',
            boxShadow: '0 0 0 2px var(--color-primary-200)',
          },
        },
      });
    }),
    
    // Medical components plugin
    plugin(({ addComponents }) => {
      addComponents({
        '.card-patient': {
          borderRadius: '0.5rem',
          boxShadow: 'var(--shadow-card)',
          backgroundColor: 'white',
          overflow: 'hidden',
          transition: 'all 0.2s ease-in-out',
          '&:hover': {
            boxShadow: 'var(--shadow-card-hover)',
            transform: 'translateY(-2px)',
          },
        },
        '.appointment-slot': {
          borderRadius: '0.375rem',
          padding: '0.5rem',
          border: '1px solid var(--color-neutral-200)',
          backgroundColor: 'white',
          cursor: 'pointer',
          transition: 'all 0.2s ease-in-out',
          '&:hover': {
            borderColor: 'var(--color-primary-500)',
            backgroundColor: 'var(--color-primary-50)',
          },
          '&.selected': {
            borderColor: 'var(--color-primary-500)',
            backgroundColor: 'var(--color-primary-100)',
          },
          '&.unavailable': {
            opacity: '0.5',
            cursor: 'not-allowed',
            backgroundColor: 'var(--color-neutral-100)',
          },
        },
        '.status-badge': {
          display: 'inline-flex',
          alignItems: 'center',
          borderRadius: '9999px',
          padding: '0.25rem 0.75rem',
          fontSize: '0.75rem',
          fontWeight: '500',
          '&.status-active': {
            backgroundColor: 'var(--color-success-100)',
            color: 'var(--color-success-800)',
          },
          '&.status-pending': {
            backgroundColor: 'var(--color-warning-100)',
            color: 'var(--color-warning-800)',
          },
          '&.status-cancelled': {
            backgroundColor: 'var(--color-danger-100)',
            color: 'var(--color-danger-800)',
          },
          '&.status-completed': {
            backgroundColor: 'var(--color-info-100)',
            color: 'var(--color-info-800)',
          },
        },
        '.medical-tab': {
          padding: '0.75rem 1rem',
          borderBottomWidth: '2px',
          borderBottomColor: 'transparent',
          fontWeight: '500',
          transition: 'all 0.2s ease-in-out',
          '&.active': {
            borderBottomColor: 'var(--color-primary-600)',
            color: 'var(--color-primary-700)',
          },
          '&:hover:not(.active)': {
            borderBottomColor: 'var(--color-neutral-300)',
          },
        },
      });
    }),
  ],
  // Add CSS variables for colors to allow easy theme switching
  corePlugins: {
    preflight: true,
  },
} satisfies Config;
