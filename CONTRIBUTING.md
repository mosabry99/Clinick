# Contributing to **Clinick**

Thank you for considering contributing to Clinick!  
We welcome pull requests, bug reports, feature ideas, and documentation improvements.  
This guide explains how to get your contribution accepted quickly and smoothly.

---

## Table of Contents
1. [Project Structure](#project-structure)
2. [Development Setup](#development-setup)
3. [Code Style & Formatting](#code-style--formatting)
4. [Testing](#testing)
5. [Git & Branching Strategy](#git--branching-strategy)
6. [Commit Message Convention](#commit-message-convention)
7. [Pull Request Checklist](#pull-request-checklist)
8. [Issue Reporting Guidelines](#issue-reporting-guidelines)
9. [Security Policy](#security-policy)
10. [Community Standards](#community-standards)

---

## Project Structure
Clinick is a **monorepo**:

```
Clinick/
├── packages/
│   ├── client/   # React + Vite front-end
│   └── server/   # Express + Prisma back-end
├── docs/         # Screenshots, diagrams
├── .github/      # Issue/PR templates, workflows
├── README.md
└── CONTRIBUTING.md
```

* **Client** targets modern browsers, uses TypeScript, React 18, Tailwind, Vite.
* **Server** targets Node ≥ 18, uses TypeScript (ESM), Express 5, Prisma.

---

## Development Setup

### Prerequisites
* Node **18 LTS** or newer
* npm **9** or newer
* PostgreSQL (or SQLite for quick tests)
* Docker (optional)  
* A GitHub account 😊

### Quick Start
```bash
# 1. Fork & clone your fork
git clone https://github.com/<your-username>/Clinick.git
cd Clinick
git remote add upstream https://github.com/mosabry99/Clinick.git

# 2. Install root scripts & husky hooks
npm install

# 3. Install each workspace’s dependencies
cd packages/client && npm install
cd ../server && npm install
```

### Running in Dev Mode
```bash
# Terminal 1 – back-end API
cd packages/server
npm run dev

# Terminal 2 – front-end app
cd packages/client
npm run dev
```

### Database setup (server)
```bash
npm run db:generate
npm run db:migrate
npm run db:seed  # optional
```

---

## Code Style & Formatting

| Tool        | Purpose                           | Command                     |
|-------------|-----------------------------------|-----------------------------|
| **ESLint**  | Lint TypeScript & React code      | `npm run lint`              |
| **Prettier**| Auto-format codebase              | `npm run format`            |
| **Stylelint** (soon) | Lint Tailwind/CSS        |                             |

* **Tabs vs Spaces:** 2-space soft tabs  
* **Quotes:** Single `'`  
* **Semicolons:** Yes  
* **Line length:** 100 chars soft limit  
* Lint checks run in CI – PRs must pass.

---

## Testing

| Package   | Framework | Command                      |
|-----------|-----------|------------------------------|
| Server    | Jest      | `npm test` (unit & integration) |
| Client    | Jest + RTL| `npm test` (component tests)   |
| E2E       | Coming soon (Playwright/Cypress) |               |

* Minimum **70 % coverage** (branches & functions) – enforced by CI.
* Add tests for new features or bug fixes.
* Run `npm test --watch` for TDD.

---

## Git & Branching Strategy

* **main** → protected; always deployable.  
* **feature/***, **bugfix/***, **docs/*** → short-lived topic branches.  
* Sync your fork periodically:

```bash
git checkout main
git pull upstream main
git push origin main
```

---

## Commit Message Convention

We follow **Conventional Commits**:

```
<type>(scope): <subject>
```

Types:  
`feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

Examples:
```
feat(appointments): add recurring appointment support
fix(auth): refresh token rotation bug
docs(readme): update installation instructions
```

---

## Pull Request Checklist

Before opening a PR:

1. **Tests** pass (`npm test`) and coverage ≥ 70 %.
2. **ESLint/Prettier** pass (`npm run lint && npm run format`).
3. Update **documentation** (README, docs, Swagger) if needed.
4. Rebase onto `upstream/main` (`git pull --rebase upstream main`).
5. **Squash** or tidy commits – 1 – 3 logical commits preferred.
6. Fill out the PR template:
   * **Description / Motivation**
   * **Related Issue** (`Fixes #123`)
   * **Screenshots** (UI changes)
   * **Checklist** ticks.

CI must pass for merge approval.

---

## Issue Reporting Guidelines

When opening an issue:

1. **Search first** – avoid duplicates.  
2. Use the correct **issue template** (`Bug`, `Feature`, `Question`).  
3. Include:
   * **Environment** (OS, browser, Node version).  
   * **Steps to reproduce** (code snippets / curl commands).  
   * **Expected vs actual** result.  
   * **Logs / stack traces** (redact sensitive data).  
4. Label appropriately (`bug`, `feature`, `docs`, `good-first-issue`).  
5. Be respectful – our maintainers are volunteers.

---

## Security Policy

If you discover a **security vulnerability**, please **do not open a public issue**.  
Email **security@clinick.app** or DM a maintainer for responsible disclosure.  
We aim to respond within 72 hours and release a fix ASAP.

---

## Community Standards

* Be kind and inclusive – follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
* Review discussions respectfully; provide constructive feedback.
* Spam, harassment, or inappropriate content will lead to removal.

---

### Thank You! 🎉
Your time and skills help make Clinick better for healthcare providers worldwide.  
Happy coding – and **welcome to the team!**
