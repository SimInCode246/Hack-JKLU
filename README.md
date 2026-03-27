# Hack-JKLU 🔐 — Security Vulnerability Scanner

A full-stack cybersecurity web application that scans for security vulnerabilities. Built for the Hack-JKLU Hackathon, featuring a Node.js/Express backend that handles scanning logic and a React (Vite) frontend dashboard to visualize results.

---

## 🛡️ Features

- 🔍 **Vulnerability Scanning** — Scans targets for common security weaknesses and misconfigurations
- 📊 **Security Dashboard** — Clean visual interface to view and interpret scan results
- ⚡ **Real-time Results** — Live feedback as the scanner discovers vulnerabilities
- 🗂️ **Scan History** — Keep track of previous scans and compare results
- 🌐 **Full Stack Architecture** — Decoupled backend API and frontend for easy scalability

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## ✅ Prerequisites

Before you begin, make sure the following are installed on your PC:

| Tool | Why You Need It | Download |
|------|----------------|----------|
| **Node.js** (v18 or above) | Runs the backend server and frontend dev tools | [nodejs.org](https://nodejs.org) |
| **npm** | Comes with Node.js — installs packages | Included with Node.js |
| **Git** | To clone the repository | [git-scm.com](https://git-scm.com) |

To verify everything is installed, open your terminal and run:

```bash
node --version
npm --version
git --version
```

All three should print a version number without errors. ✅

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Node.js, Express.js |
| **Frontend** | React, Vite |

---

## 🚀 Getting Started

Follow these steps **exactly in order** from a fresh clone.

---

### Step 1 — Clone the Repository

Open your terminal and run:

```bash
git clone https://github.com/your-username/Hack-JKLU.git
```

> 📝 Replace `your-username` with the actual GitHub username where the repo is hosted.

---

### Step 2 — Go Into the Project Folder

```bash
cd Hack-JKLU
```

> ⚠️ This step is critical. Always `cd` into the project before running any commands or you will get errors.

---

### Step 3 — Install Root Dependencies

```bash
npm install
```

---

### Step 4 — Install Backend Dependencies

```bash
cd backend
npm install
cd ..
```

---

### Step 5 — Install Frontend Dependencies

```bash
cd Frontend/security-scanner-dashboard
npm install
cd ../..
```

---

### Step 6 — Run the Project

From the **root folder** of the project, run:

```bash
npm run start-all
```

This single command starts both the backend and frontend servers simultaneously.

---

### Step 7 — Open in Browser

Once both servers are running, you will see output like:

```
[0] Server running on http://localhost:5000      ← Backend API
[1] Local:   http://localhost:5173               ← Frontend Dashboard
```

Open your browser and visit:

```
http://localhost:5173
```

You should see the security scanner dashboard. 🎉

---

## 📁 Project Structure

```
Hack-JKLU/
│
├── package.json                           ← Root config (runs both servers together)
│
├── backend/
│   ├── package.json                       ← Backend dependencies (Express, etc.)
│   └── server.js                          ← Express server + scanning logic
│
└── Frontend/
    └── security-scanner-dashboard/
        ├── package.json                   ← Frontend dependencies (React, Vite)
        └── src/                           ← React components and dashboard UI
```

---

## ⚠️ Troubleshooting

### `Error: Cannot find module 'express'`

You forgot to install backend dependencies separately. Run:

```bash
cd backend
npm install
cd ..
```

---

### `npm error: Could not read package.json`

You ran `npm` from the wrong folder. Make sure you are inside the project root:

```bash
cd Hack-JKLU
```

Then re-run the command.

---

### `DeprecationWarning: util._extend is deprecated`

This is just a **warning, not an error.** It comes from an older library used internally. You can safely ignore it — the project runs fine.

---

### Port already in use (`EADDRINUSE`)

Another process is already using port 5000 or 5173. Either:
- Restart your PC, or
- On Windows: open Task Manager → find Node.js → End Task
- On Mac/Linux: run `kill -9 $(lsof -ti:5000)`

---

## 📄 License

This project was built for the **Hack-JKLU Hackathon**.
