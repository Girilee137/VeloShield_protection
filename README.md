# VeloShield

**Automated Web Security, Performance, and Deployment Readiness Assessment Platform**

![Stack](https://img.shields.io/badge/Java-21-orange) ![Stack](https://img.shields.io/badge/Tomcat-10.1-red) ![Stack](https://img.shields.io/badge/PostgreSQL-Neon-blue) ![Stack](https://img.shields.io/badge/Deployment-Render%20Alone-green) ![Stack](https://img.shields.io/badge/Architecture-Unified%20Single%20Service-blueviolet)

---

## Architecture: Unified Single-Service on Render

VeloShield runs as a single, self-contained service on Render. The embedded Apache Tomcat server serves both the modern responsive frontend web application and the high-performance REST APIs from the same origin:

```
                  ┌──────────────────────────────────────────────┐
                  │            Render Web Service                │
                  │   ┌────────────────────────────────────────┐ │
                  │   │        Embedded Apache Tomcat          │ │
                  │   │                                        │ │
                  │   │  Static Assets (/)                     │ │
                  │   │  ├── index.html                        │ │
                  │   │  ├── dashboard.html                    │ │
                  │   │  ├── css/                              │ │
                  │   │  └── js/                               │ │
                  │   │                                        │ │
                  │   │  REST APIs (/api/*)                    │ │
                  │   │  ├── /api/auth/*                       │ │
                  │   │  ├── /api/predeployment/*              │ │
                  │   │  ├── /api/postdeployment/*             │ │
                  │   │  ├── /api/targets/*                    │ │
                  │   │  ├── /api/tests/*                      │ │
                  │   │  └── /api/assessments/*                │ │
                  │   └──────────────────┬─────────────────────┘ │
                  └──────────────────────┼───────────────────────┘
                                         │ JDBC (SSL)
                                         ▼
                                  Neon PostgreSQL
```

### Key Advantages of Single-Service Deployment:
- **No Vercel Needed:** No split-service hosting, separate domains, or multi-platform coordination.
- **Zero CORS Issues:** Frontend and backend run on the exact same origin (`/api/...`), completely eliminating CORS preflight overhead and cross-origin blocking.
- **First-Party Cookies:** Full compatibility with modern browser privacy rules (Safari ITP, Chrome Privacy Sandbox) without third-party cookie restrictions.
- **Self-Contained Fat JAR:** All static assets are packaged directly into the JAR (`veloshield.jar`) with automatic fallback to local disk.

---

## Core Workflows

VeloShield provides two completely independent assessment workflows:

### 1. Workflow A — Before Deployment (Pre-Deployment)
Designed for developers before releasing to production:
- **Project & Source Code Security:** Scans project files (`pom.xml`, `package.json`, `requirements.txt`, `.env`, configuration files) for exposed secrets, API keys, passwords, and tokens (automatically masked).
- **Dependency Vulnerability Assessment:** Parses packages and versions across Maven, npm, PyPI, and Dart ecosystems.
- **Security Configuration Audit:** Verifies debug flags, production readiness, CORS settings, cookie policies, and error handling.
- **API & Route Inspection:** Detects exposed administrative routes, missing authentication patterns, and internal paths.
- **Pre-Deployment Readiness Score:** Generates categorical scores (Security, Configuration, Dependencies, Project) with readiness verdict.

### 2. Workflow B — After Deployment (Live Assessment)
Designed for assessing live public web applications:
- **Safe & Non-Destructive Scanning:** Non-intrusive inspection of public endpoints with strict SSRF protection and internal network blocklists.
- **Security Headers & TLS Audit:** Verifies HSTS, Content-Security-Policy, X-Frame-Options, secure cookies, and certificate health.
- **Performance & Latency Telemetry:** Measures DNS resolution, TCP handshake, TLS negotiation, TTFB, and download speeds.
- **API & Asset Health:** Discovers robots.txt, sitemap.xml, security.txt, tracks third-party scripts, CDNs, and trackers.
- **Post-Deployment Health Score:** Comprehensive scorecard and actionable remediation guidance.

### 3. Authorized Load & Resilience Testing (Preserved)
- Target domain verification via `/.well-known/veloshield-verification.txt`.
- Controlled concurrent stress testing with bounded thread pools (`ExecutorService`), latency tracking (Avg, P95), and CSV report export.
- Automated Nginx & Cloudflare WAF mitigation generator.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Architecture | Unified Single-Service (Frontend + Backend in One) |
| Frontend | HTML5, CSS3, Modern ES6+ JavaScript, Responsive Dark Theme |
| Backend | Java 21, Java Servlets (Jakarta EE), Maven |
| Embedded Server | Embedded Apache Tomcat 10.1 (No external Tomcat installation required) |
| Database | Neon Serverless PostgreSQL (JDBC Connection Pool with automatic recovery) |
| Authentication | BCrypt Password Hashing + HTTP Session Cookies |
| Deployment | **Render Alone** via Multi-Stage Dockerfile & `render.yaml` |

---

## Deployment on Render (Step-by-Step)

### Option 1: Automatic Blueprint (Recommended)

1. Push your repository to **GitHub**.
2. Log in to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** and select **Blueprint**.
4. Connect your GitHub repository. Render will automatically detect `render.yaml`.
5. Set the environment variable `DATABASE_URL` with your Neon PostgreSQL connection string:
   ```
   postgresql://user:password@ep-xxxx.neon.tech/neondb?sslmode=require
   ```
6. Click **Apply**. Render will automatically build the multi-stage Docker container and deploy the service.

### Option 2: Manual Web Service Creation

1. In the Render Dashboard, click **New +** > **Web Service**.
2. Connect your GitHub repository.
3. Configure the service:
   - **Name:** `veloshield`
   - **Region:** Any (e.g., Singapore, Frankfurt, Oregon)
   - **Environment:** `Docker` (Render automatically uses the root `Dockerfile`)
   - **Plan:** `Free`
4. In the **Environment Variables** section, add:
   - `DATABASE_URL`: `postgresql://user:password@ep-xxxx.neon.tech/neondb?sslmode=require`
   - `PORT`: `8080`
5. Set **Health Check Path** to:
   - `/`
6. Click **Deploy Web Service**.

Once deployed, your application is live at `https://<your-service-name>.onrender.com`!

---

## Local Development & Testing

### Prerequisites
- Java 21+ JDK
- Maven 3.8+
- Neon PostgreSQL database connection string

### Run Locally

1. Set your database environment variable:
   ```powershell
   # PowerShell (Windows)
   $env:DATABASE_URL="postgresql://user:password@ep-xxxx.neon.tech/neondb?sslmode=require"

   # Bash (Linux/macOS)
   export DATABASE_URL="postgresql://user:password@ep-xxxx.neon.tech/neondb?sslmode=require"
   ```

2. Package and run the single-service JAR:
   ```bash
   cd backend
   mvn clean package -DskipTests
   java -jar target/veloshield.jar
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8080/
   ```

Both the web interface and the REST APIs are served immediately from port 8080.

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register new user account |
| POST | `/api/auth/login` | Log in and establish session |
| POST | `/api/auth/logout` | Log out and destroy session |
| GET | `/api/auth/me` | Current authenticated user profile |

### Workflow A — Pre-Deployment
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/predeployment/scans` | Submit project files for pre-deployment analysis |
| GET | `/api/predeployment/scans/{id}` | Retrieve pre-deployment scan summary & score |
| GET | `/api/predeployment/scans/{id}/findings` | Retrieve detailed findings and secret masking |
| GET | `/api/predeployment/scans/{id}/report` | Download CSV assessment report |

### Workflow B — Post-Deployment
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/postdeployment/scans` | Run safe scan against public URL |
| GET | `/api/postdeployment/scans/{id}` | Retrieve post-deployment score and metrics |
| GET | `/api/postdeployment/scans/{id}/findings` | Retrieve live security and health findings |
| GET | `/api/postdeployment/scans/{id}/report` | Download CSV assessment report |

### Assessment History & Comparative Diff
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/assessments` | List all historical assessments |
| GET | `/api/assessments/{id}` | Get assessment details and findings |
| GET | `/api/assessments/diff?id1={id1}&id2={id2}` | Comparative score & finding diff |

### Targets & Load Resilience Testing (Preserved)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/targets` | List registered targets |
| POST | `/api/targets` | Add target for load testing |
| DELETE | `/api/targets/{id}` | Delete target |
| POST | `/api/targets/{id}/verify` | Verify domain ownership via `.well-known` token |
| GET | `/api/tests` | List load test runs |
| POST | `/api/tests` | Launch authorized load test |
| GET | `/api/tests/{id}` | Poll load test metrics |
| GET | `/api/mitigation/{id}` | Generate Nginx & Cloudflare WAF rules |
