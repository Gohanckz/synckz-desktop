# 🔐 Synckz Desktop - Ethical Hacking Platform

<div align="center">

**Professional-grade ethical hacking toolkit with local-first architecture and cloud synchronization**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Made with Go](https://img.shields.io/badge/Made%20with-Go-00ADD8.svg)](https://golang.org/)
[![React](https://img.shields.io/badge/React-18.x-61DAFB.svg)](https://reactjs.org/)

[Features](#-features) • [Architecture](#-architecture) • [Installation](#-installation) • [Documentation](#-documentation)

</div>

---

## 🎯 Overview

**Synckz Desktop** is a comprehensive ethical hacking platform that combines the power of local-first architecture with optional cloud synchronization. Built like Burp Suite or Postman, it works 100% offline while giving you the option to sync and share your findings with the Synckz community.

### 🌟 Why Synckz?

- **🔒 Privacy First**: All sensitive data stays on your machine by default
- **⚡ Lightning Fast**: Local SQLite databases for instant access
- **🌐 Optional Sync**: Connect to synckz.com to share walkthroughs and findings
- **🛠️ Modular**: 10 microservices for different security tasks
- **🎨 Modern UI**: Built with React and TypeScript

---

## ✨ Features

| Feature | Description | Status |
|---------|-------------|--------|
| **🌐 Subdomain Scanner** | Discover subdomains | ✅ Active |
| **🔍 Port Scanner** | Fast port scanning | ✅ Active |
| **🔎 Google Dork Manager** | Organize Google dorks | ✅ Active |
| **📚 Methodology Library** | Hacking methodologies | ✅ Active |
| **📝 Walkthrough Editor** | Write walkthroughs | ✅ Active |
| **📋 Kanban Boards** | Project organization | ✅ Active |
| **🔒 Credential Vault** | Encrypted storage | ✅ Active |
| **☁️ Cloud Sync** | Sync with synckz.com | 🚧 In Progress |

---

## 🏗️ Architecture

📊 **[View Complete Architecture Diagrams](docs/architecture-reports/COMPLETE-SYSTEM-ARCHITECTURE.md)**

Hybrid architecture: Local microservices + Optional cloud sync

- **Frontend**: React + TypeScript (:5177)
- **Backend**: 10 Go microservices (:8080-8090)
- **Database**: SQLite (local)
- **Cloud**: Django + PostgreSQL (optional)

---

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/Gohanckz/synckz-desktop.git
cd synckz-desktop

# Install & run
cd frontend
npm install
npm run dev
```

---

## 📚 Documentation

- [Complete Architecture](docs/architecture-reports/COMPLETE-SYSTEM-ARCHITECTURE.md)
- [Hybrid Architecture Details](docs/architecture-reports/HYBRID-ARCHITECTURE-DETAILED.md)

---

## 🛠️ Tech Stack

**Frontend**: React 18, TypeScript, Vite, TailwindCSS
**Backend**: Go 1.24, Gin, SQLite, JWT
**Cloud**: Django 5.2, PostgreSQL, Redis

---

## ⚠️ Disclaimer

For **ethical hacking and authorized testing only**. Users must have proper authorization.

---

Made with 🔐 by [Gohanckz](https://github.com/Gohanckz)
