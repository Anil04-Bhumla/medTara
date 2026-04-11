# Secure Healthcare Data Platform with AI-Driven TARA

## Project Overview

This project is a secure healthcare data sharing platform developed for a **Data Security and Privacy** course. It demonstrates how sensitive medical data can be protected using authentication, role-based access control, encryption, security logging, and a Threat Analysis and Risk Assessment (TARA) module.

The system allows different types of users such as **patients**, **doctors**, and **admins** to interact with healthcare records under controlled permissions. It also includes a security monitoring module that analyzes suspicious events and assigns risk levels through an AI-driven Threat Analysis and Risk Assessment (TARA) workflow backed by Gemini, with graceful fallback to baseline platform rules when the AI service is unavailable.

## Main Objectives

- Protect sensitive healthcare files and user accounts
- Implement secure role-based access to medical records
- Encrypt uploaded healthcare files before storage
- Monitor suspicious activity such as failed logins and unauthorized access
- Demonstrate a TARA workflow for identifying threats and recommending mitigations

## Implemented Features

### Authentication and Access Control

- User registration for `patient` and `doctor`
- Secure login using hashed passwords with `bcryptjs`
- JWT-based session authentication
- Role-Based Access Control (RBAC) for:
  - patient
  - doctor
  - admin
- Basic account lockout after repeated failed login attempts

### Secure File Handling

- Doctors and admins can upload healthcare files
- Files are encrypted on the backend before storage
- Download access is restricted to:
  - assigned patient
  - assigned doctor
  - uploader
  - admin
- Original filenames are preserved for better usability

### Healthcare Record Assignment

- Records can be assigned to a patient and doctor
- Doctors must assign records to a patient during upload
- Admins can manage patient-doctor record assignment after upload
- Patients can only view records assigned to them

### Security Monitoring

- Activity logging for login attempts, uploads, downloads, and suspicious actions
- Admin-only security log access
- Detection of suspicious patterns such as:
  - repeated failed login attempts
  - unauthorized download attempts
  - suspicious input patterns

### TARA Module

- AI-driven threat analysis using a Gemini-backed service
- Rule-based baseline detection retained as a fallback and as contextual hints for the AI pipeline
- Threat assessment includes:
  - attack type
  - severity
  - risk score
  - likely impact
  - recommended mitigation
  - AI confidence
  - attack vector analysis
- Admin dashboard for:
  - viewing security logs
  - viewing threat assessments
  - manually previewing suspicious payloads

## Tech Stack

### Frontend

- React.js
- React Router
- Axios
- CSS

### Backend

- Node.js
- Express.js
- MongoDB with Mongoose
- JWT
- bcryptjs
- Multer
- Node `crypto`

## Project Structure

```text
secure-healthcare-platform/
├── backend/
│   ├── config/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── scripts/
│   ├── services/
│   ├── uploads/
│   ├── utils/
│   ├── package.json
│   └── server.js
├── frontend/
│   ├── public/
│   ├── src/
│   └── package.json
└── README.md
```

## Current Modules

### Frontend Pages

- Login
- Register
- Dashboard
- Upload Center
- Records Page
- TARA / Security Dashboard
- Admin Assignment Manager

### Backend APIs

- `/api/auth`
- `/api/user`
- `/api/file`
- `/api/security`

## How to Run the Project

### 1. Open the project in VS Code

Open:

```bash
/Users/anilgurjar/Desktop/secure-healthcare-platform
```

### 2. Configure backend environment

Create or update:

`backend/.env`

Example:

```env
PORT=8000
JWT_SECRET=your_jwt_secret
AES_SECRET=your_aes_secret
MONGO_URI=your_mongodb_connection_string
```

Optional isolated demo mode:

```env
ALLOW_FILE_DB=true
```

Optional HTTPS mode:

```env
HTTPS_ENABLED=true
SSL_KEY_PATH=path_to_private_key
SSL_CERT_PATH=path_to_certificate
```

If `ALLOW_FILE_DB=true`, the backend runs in local demo mode and stores data in `backend/data/local-db.json`.

Optional AI service connection:

```env
AI_SERVICE_URL=http://localhost:5001
```

### 3. Install backend dependencies

```bash
cd backend
npm install
```

### 4. Start backend

```bash
npm start
```

Backend runs on:

```text
https://localhost:8000
```

### 5. Install frontend dependencies

Open a second terminal:

```bash
cd frontend
npm install
```

### 6. Start frontend

```bash
npm start
```

Frontend runs on:

```text
http://localhost:5173
```

### 7. Start AI services

Open a third terminal:

```bash
cd ai-services
pip install -r requirements.txt
python app.py
```

Add `ai-services/.env` with:

```env
GEMINI_API_KEY=your_actual_gemini_api_key
GEMINI_MODEL=gemini-2.0-flash
```

## Demo Seed Accounts

After MongoDB is connected, you can create demo users:

```bash
cd backend
npm run seed:demo
```

Demo users:

- Admin: `admin@securehealth.local` / `Admin@123`
- Doctor: `doctor@securehealth.local` / `Doctor@123`
- Patient: `patient@securehealth.local` / `Patient@123`

## Demo Workflow

### Doctor Flow

- Login as doctor
- Open upload center
- Select a patient
- Upload a medical report
- View assigned records

### Patient Flow

- Login as patient
- View assigned records
- Download authorized documents

### Admin Flow

- Login as admin
- View all records
- Open TARA dashboard
- Analyze suspicious logs
- Reassign records using assignment manager

## Security Features Demonstrated

- Password hashing using bcrypt
- JWT-based authentication
- Role-based authorization
- AES-based backend file encryption
- Access restriction for sensitive records
- Security activity logging
- AI-driven threat detection and risk scoring

## Important Notes

### What is currently implemented

- Secure authentication and RBAC
- Encrypted file upload/download flow
- Patient-doctor record assignment
- Security logging and suspicious activity detection
- AI-driven TARA dashboard with Gemini-backed assessments and fallback baseline analysis

### What is not fully implemented yet

- Real HTTPS/TLS deployment configuration
- Full LLM API integration for threat explanation
- Automated backend/frontend tests
- Production-grade validation and deployment hardening

## Limitations

- AI-driven TARA depends on the optional `ai-services` Gemini service
- HTTPS is described as part of real deployment architecture, but local development uses standard HTTP
- The project is designed as a secure academic prototype, not a production hospital system

## Future Improvements

- Integrate Gemini or another LLM API for AI-assisted threat explanation
- Add advanced anomaly detection and correlation rules
- Use HTTPS with certificates in deployment
- Add automated testing
- Add audit reports and compliance-oriented logging
- Add database-level encryption and key management improvements

## Academic Relevance

This project demonstrates core concepts from **data security and privacy**:

- confidentiality through encryption
- integrity through controlled access and secure handling
- authentication and authorization
- accountability through logs
- risk analysis through TARA

It shows how cybersecurity principles can be applied to healthcare data systems where privacy is critical.

## Suggested Screenshots for Report

- Login page
- Dashboard
- Upload page
- Records page
- TARA dashboard
- Admin assignment manager

## Author Note

This project is intended for academic demonstration of secure healthcare data sharing and threat analysis concepts.
