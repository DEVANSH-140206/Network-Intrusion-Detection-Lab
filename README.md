# Network Intrusion Detection Lab

> A practical cybersecurity lab that simulates, detects, analyses, and visualises network attacks using open-source security tools.

---

## 📌 Project Overview

This project demonstrates how a Network Intrusion Detection System (NIDS) works by creating a controlled cybersecurity lab. The goal is to simulate common network attacks, capture and analyse network traffic, detect malicious activity using an Intrusion Detection System (IDS), and display the results through a simple dashboard.

The entire project is developed using open-source tools and virtual machines in a safe laboratory environment.

---

## 🎯 Objectives

- Understand how network attacks work.
- Capture and analyse network traffic.
- Detect malicious activities using an IDS.
- Visualise security alerts through a dashboard.
- Learn collaborative software development using Git and GitHub.

---

## 🏗️ Project Architecture

```
Attacker (Kali Linux)
          │
          ▼
Victim (Metasploitable2)
          │
          ▼
Network Traffic
          │
          ▼
IDS (Suricata)
          │
          ▼
Alert Logs
          │
          ▼
Dashboard (Flask)
```

---

## 👥 Team Roles

| Member | Role | Primary Folder |
|---------|------|----------------|
| Member 1 | Team Leader & Attack Simulation | `attack/` |
| Member 2 | Detection Engineer | `detection/` |
| Member 3 | Traffic Analysis | `analysis/` |
| Member 4 | Dashboard Development | `dashboard/` |
| Member 5 | Documentation & Reporting | `docs/` |

---

## 📂 Repository Structure

```
Network-Intrusion-Detection-Lab/

│── README.md

│── attack/
│   ├── logs/
│   ├── scripts/
│   └── commands.md

│── detection/
│   ├── rules/
│   ├── alerts/
│   └── notes.md

│── analysis/
│   ├── captures/
│   ├── reports/
│   └── wireshark-notes.md

│── dashboard/
│   ├── app/
│   ├── templates/
│   ├── static/
│   └── README.md

│── docs/
│   ├── meeting-notes/
│   ├── weekly-progress/
│   ├── screenshots/
│   └── final-report.md
```

---

## 🛠️ Technologies

- Kali Linux
- Metasploitable2
- Ubuntu
- Suricata
- Wireshark
- Flask
- Python
- VirtualBox
- Git
- GitHub

---

## 🔄 Project Workflow

```
Attack
   ↓
Capture Network Traffic
   ↓
Analyse Packets
   ↓
Detect Threats
   ↓
Generate Alerts
   ↓
Display Dashboard
```

---

## 📅 Development Timeline

- Week 1 – Repository & Lab Setup
- Week 2 – Tool Installation & Basic Learning
- Week 3 – First Attack & Detection
- Week 4 – Integration
- Week 5 – Additional Attack Scenarios
- Week 6 – Full System Testing
- Week 7 – Documentation & Improvements
- Week 8 – Final Demonstration & Submission

---

## 📖 Learning Goals

By the end of this project, the team will have practical experience with:

- Network Security
- Intrusion Detection Systems
- Network Traffic Analysis
- Ethical Attack Simulation
- Python Web Development
- Git & GitHub Collaboration
- Virtual Machine Networking

---

## ⚠️ Disclaimer

This project is developed strictly for educational purposes. All attacks are performed inside an isolated laboratory environment on intentionally vulnerable virtual machines. No testing is performed on public or unauthorised systems.

---

## 📌 Project Status

**Current Phase:** Week 1 – Repository & Environment Setup 🚧

---

## 📜 License

This project is intended for educational purposes.