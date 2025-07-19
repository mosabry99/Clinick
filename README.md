# Clinick – Medical Clinic Management System

A full-stack, multi-tenant platform that streamlines every aspect of running a medical clinic—from patient intake to real-time analytics—built with TypeScript, React, Node.js, and Prisma.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Feature List](#feature-list)
3. [Architecture & Tech Stack](#architecture--tech-stack)
4. [Installation & Setup](#installation--setup)
5. [Usage Guide](#usage-guide)
6. [API Documentation](#api-documentation)
7. [Screenshots / Demo](#screenshots--demo)
8. [Deployment](#deployment)
9. [Contributing](#contributing)
10. [License](#license)
11. [Contact](#contact)

---

## Project Overview
Clinick is a **comprehensive medical clinic management system** designed for modern, multi-location healthcare providers.  
Key goals:
* Centralize clinical, administrative, and financial workflows.  
* Provide secure, role-based access for staff, practitioners, and patients.  
* Offer real-time communication, advanced analytics, and seamless integrations.  
* Fulfill compliance requirements (HIPAA/GDPR) out-of-the-box.  

---

## Feature List
### Core Modules
| Module | Highlights |
| ------ | ---------- |
| **Authentication & User Management** | JWT & refresh tokens, MFA, password policies, RBAC, session management, audit logs |
| **Patient Management** | Demographics, insurance, emergency contacts, document uploads, medical & family history |
| **Appointment Scheduling** | Multi-provider calendars, recurring slots, reminders (SMS/email), wait-lists, timezone support |
| **Medical Records (EHR)** | Versioned records, vitals tracking, labs & imaging, prescriptions, allergies, treatment plans |
| **Billing & Payments** | Invoicing, multiple gateways, insurance claims, payment plans, refunds, tax & revenue reports |
| **Inventory Management** | Supplies/equipment, reorder levels, expirations, supplier data, barcode support |
| **Communication System** | Internal messaging, patient notifications, templates, push/SMS/email |
| **Reports & Analytics** | Financial KPIs, patient demographics, utilization, doctor performance, custom report builder |
| **Settings & Configuration** | Clinic branding, notification prefs, security, integrations, backup/restore |
| **Integrations** | HL7/FHIR, payment gateways, lab systems, email/SMS providers, insurance verification |
| **Real-Time Features** | WebSocket presence, live chat, instant alerts, real-time dashboards |
| **Audit & Compliance** | Detailed audit trails, data encryption, retention policies, export tools |

---

## Architecture & Tech Stack
### High-Level Diagram
```
Client (React + Vite + Tailwind)  <--Socket.IO-->
      |
      | HTTPS / REST / WebSocket
      v
Server (Node.js + Express 5)
      |
Prisma ORM  ->  PostgreSQL (multi-tenant) / SQLite (per-tenant option)
```

### Technologies
* **Front-end:** React 18, TypeScript, Vite, Tailwind CSS, i18next (English/Arabic), PWA
* **Back-end:** Node.js ≥ 18, Express 5, TypeScript (ESM), Socket.IO, Multer
* **Database:** PostgreSQL (default) with Prisma; supports per-tenant SQLite
* **Auth & Security:** JWT, bcrypt, Helmet, CORS, rate-limiting, MFA
* **Real-time:** Socket.IO namespaces (appointments, notifications, chat)
* **DevOps:** Docker, Nodemon, ts-node-esm, ESLint, Prettier, Jest, ts-jest
* **Monitoring & Logging:** Winston, response-time, health/readiness endpoints
* **CI/CD ready** with container builds and automated migrations

---

## Installation & Setup
Prerequisites: **Node 18+**, **npm**, **Docker** (optional), **PostgreSQL** (or edit `DATABASE_URL` for SQLite testing).

```bash
git clone https://github.com/mosabry99/Clinick.git
cd Clinick
npm install           # root (monorepo scripts & husky hooks)

# install package dependencies
cd packages/client && npm install
cd ../server && npm install
```

### Environment Variables
Create `packages/server/.env` (or `.env.production`) and set at minimum:
```
NODE_ENV=development
PORT=3000
HOST=0.0.0.0
DATABASE_URL=postgresql://user:password@localhost:5432/clinick
JWT_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret
```

### Database
```bash
# from packages/server
npm run db:generate
npm run db:migrate
npm run db:seed   # optional demo data
```

### Running in Development
```bash
# Terminal 1 – back-end
cd packages/server
npm run dev

# Terminal 2 – front-end
cd packages/client
npm run dev
```
Open `http://localhost:5173` (Vite default) to access the client.  
API base URL defaults to `http://localhost:3000/api/v1`.

---

## Usage Guide
1. **Register** the first user (will become `TENANT_ADMIN`).  
2. **Create clinic settings** in the Settings module.  
3. **Add practitioners** and assign roles.  
4. **Import or add patients** manually or via CSV.  
5. **Schedule appointments** via the calendar.  
6. **Record consultations** and update medical records.  
7. **Generate invoices** and collect payments.  
8. **Monitor analytics** on the dashboard.

Front-end uses **react-router**; back-end exposes REST endpoints under `/api/v1`. Authenticated requests require `Authorization: Bearer <token>`.

---

## API Documentation
Swagger UI is auto-generated at:

```
GET /api-docs        # human-friendly UI
GET /api-docs.json   # raw OpenAPI spec
```

Key endpoints:
* `POST /api/v1/auth/login`
* `GET  /api/v1/patients`
* `POST /api/v1/appointments`
* `PATCH /api/v1/billing/invoices/:id`
* …and many more across 12 modules.  
See Swagger for schemas, examples, and error codes.

---

## Screenshots / Demo
> _Screenshots and demo videos coming soon._

| Screen | Description |
| ------ | ----------- |
| ![](docs/screens/dashboard.png) | Dashboard overview |
| ![](docs/screens/appointments.png) | Appointment calendar |
| ![](docs/screens/patient-record.png) | EHR view |

---

## Deployment
### Docker
```bash
# build image
cd packages/server
npm run docker:build

# run container
npm run docker:run
```

### Production Checklist
1. Set `NODE_ENV=production` and strong secrets.  
2. Enable HTTPS/SSL termination (Nginx / Cloud provider).  
3. Configure domain & CORS origins.  
4. Set `ENABLE_CLUSTERING=true` for multi-CPU scaling.  
5. Provision managed PostgreSQL and Redis (for Socket.IO scaling).  
6. Use CI/CD to run `npm run db:migrate` on deploy.

---

## Contributing
1. Fork the repository and create your branch: `git checkout -b feature/my-feature`.  
2. Commit changes and run linter/tests:  
   ```bash
   npm run lint && npm test
   ```  
3. Push to GitHub and open a Pull Request against **main**.  
4. Ensure your PR description references any related issues.  
5. All new features must include unit/integration tests and update documentation.

---

## License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full text.

---

## Contact
**Project Lead:** Thomas Flynn  
**Maintainer:** [@mosabry99](https://github.com/mosabry99)  
• Email: support@clinick.app  
• Issues: <https://github.com/mosabry99/Clinick/issues>

---

_Thank you for using Clinick!_  
_Built with ❤️ to empower healthcare providers everywhere._
