# NETWORK INTRUSION DETECTION LAB

> A practical cybersecurity laboratory for simulating controlled network activity, analyzing traffic, detecting suspicious behavior, and visualizing security alerts using open-source tools.

---

## 01. PROJECT OVERVIEW

The **Network Intrusion Detection Lab** demonstrates the basic workflow of a **Network Intrusion Detection System (NIDS)** in a controlled and isolated environment.

The project combines reconnaissance, traffic generation, packet analysis, intrusion detection, alert processing, and visualization into a single end-to-end cybersecurity laboratory.

### Proposed Workflow

```text
+------------------------+
| Attack / Reconnaissance|
+-----------+------------+
            |
            v
+------------------------+
|    Network Traffic     |
+-----------+------------+
            |
            v
+------------------------+
|    Traffic Analysis    |
+-----------+------------+
            |
            v
+------------------------+
|     IDS Detection      |
+-----------+------------+
            |
            v
+------------------------+
|    Security Alerts     |
+-----------+------------+
            |
            v
+------------------------+
|     Visualization      |
+------------------------+
```

All activities are performed against intentionally vulnerable systems inside an isolated laboratory or other explicitly authorized infrastructure.

---

## 02. OBJECTIVES

The primary objectives of this project are:

* Build a controlled cybersecurity laboratory environment.
* Simulate and study network reconnaissance and controlled attack traffic.
* Capture and analyze network packets.
* Detect suspicious network activity using an IDS.
* Generate and process security alerts.
* Visualize detected events through a web dashboard.
* Understand the complete NIDS workflow from traffic generation to alert visualization.
* Practice collaborative cybersecurity development using Git and GitHub.
* Perform controlled end-to-end testing of the detection pipeline.

---

## 03. PROPOSED ARCHITECTURE

```text
                         +----------------+
                         |   Kali Linux   |
                         | Attack / Recon |
                         +-------+--------+
                                 |
                                 |
                                 v
                         +----------------+
                         | Metasploitable2|
                         |     Victim     |
                         +-------+--------+
                                 |
                                 v
                         +----------------+
                         | Network Traffic|
                         +-------+--------+
                                 |
                    +------------+------------+
                    |                         |
                    v                         v
             +-------------+           +-------------+
             |  Wireshark  |           |  Suricata   |
             |   Analysis  |           |     IDS     |
             +-------------+           +------+------+
                                             |
                                             v
                                      +-------------+
                                      |    Alerts   |
                                      +------+------+
                                             |
                                             v
                                      +-------------+
                                      |    Alert    |
                                      |  Processing |
                                      +------+------+
                                             |
                                             v
                                      +-------------+
                                      |    Flask    |
                                      |  Dashboard  |
                                      +-------------+
```

### Architecture Components

| Component        | Purpose                                     |
| ---------------- | ------------------------------------------- |
| Kali Linux       | Attack simulation and reconnaissance        |
| Metasploitable2  | Intentionally vulnerable target environment |
| Wireshark        | Packet capture and traffic analysis         |
| Suricata         | Network intrusion detection                 |
| Alert Processing | Processes and prepares IDS alerts           |
| Flask            | Web-based visualization dashboard           |
| Git / GitHub     | Version control and team collaboration      |

---

## 04. LAB ENVIRONMENT

The project uses an isolated virtualized environment to safely perform cybersecurity experiments.

### Virtualization

```text
+--------------------------------------------------+
|                 Oracle VirtualBox                |
|                                                  |
|   +----------------+       +----------------+    |
|   |   Kali Linux   |       | Metasploitable2|    |
|   |                |       |                |    |
|   | Attack System  | <---> | Victim System  |    |
|   +----------------+       +----------------+    |
|                                                  |
|              Host-Only Network                  |
+--------------------------------------------------+
```

The laboratory uses **Host-only networking** to allow communication between the virtual machines while keeping the testing environment isolated from the external network.

---

## 05. TEAM

| Member                 | Responsibility                        |
| ---------------------- | ------------------------------------- |
| **Devansh Chaubey**    | Team Leader & Attack / Reconnaissance |
| **Divija Srivastava**  | IDS & Detection / Suricata            |
| **Manya**              | Victim Environment & Traffic Analysis |
| **Anshika Srivastava** | Flask / Python Dashboard              |
| **Sharat Chodhary**    | Integration & Testing                 |

---

## 06. TECHNOLOGY STACK

### Infrastructure

```text
Oracle VirtualBox
Kali Linux
Metasploitable2
Ubuntu
```

### Security & Network Tools

```text
Nmap
Wireshark
Suricata
```

### Development

```text
Python
Flask
Git
GitHub
```

---

## 07. PROJECT MODULES

The project is divided into several major modules.

### 07.1 ATTACK / RECONNAISSANCE

Responsible for generating controlled network activity and reconnaissance traffic from the attacker machine.

Primary tool:

```text
Nmap
```

Activities include:

* Host discovery
* Port scanning
* Service enumeration
* Controlled reconnaissance
* Authorized attack simulation

---

### 07.2 TRAFFIC ANALYSIS

Responsible for capturing and analyzing the network traffic generated during laboratory activities.

Primary tool:

```text
Wireshark
```

Activities include:

* Packet capture
* Protocol identification
* Traffic inspection
* Source and destination analysis
* Identification of suspicious network patterns

---

### 07.3 IDS / DETECTION

Responsible for detecting suspicious traffic and generating security alerts.

Primary tool:

```text
Suricata
```

Activities include:

* IDS configuration
* Detection rule development
* Traffic inspection
* Signature-based detection
* Alert generation

---

### 07.4 ALERT PROCESSING

The alert-processing layer receives IDS-generated alerts and prepares the relevant information for visualization.

Proposed responsibilities:

```text
Suricata Alerts
       |
       v
Alert Parsing
       |
       v
Event Processing
       |
       v
Structured Alert Data
       |
       v
Dashboard
```

---

### 07.5 DASHBOARD

The dashboard provides a visual representation of detected security events.

Technology:

```text
Python + Flask
```

Possible dashboard information includes:

* Detected events
* Alert severity
* Source IP
* Destination IP
* Protocol
* Timestamp
* Detection signature
* Event count

---

## 08. CURRENT PROGRESS

### COMPLETED

```text
[✓] VirtualBox laboratory setup
[✓] Kali Linux VM setup
[✓] Metasploitable2 VM setup
[✓] Host-only networking
[✓] Kali <-> Metasploitable2 communication
[✓] Nmap reconnaissance
[✓] Service enumeration
[✓] Wireshark packet capture
[✓] Initial traffic analysis
[✓] Git / GitHub collaboration setup
```

### IN PROGRESS

```text
[~] Suricata detection environment
[~] Detection rules
[~] Alert processing
[~] Flask dashboard
[~] System integration
[~] Integration testing
```

### NEXT STEPS

```text
[ ] Complete attack -> detection -> visualization pipeline
[ ] Implement end-to-end alert processing
[ ] Complete Flask dashboard
[ ] Perform multi-machine demonstration
[ ] Conduct complete integration testing
[ ] Validate detection results
[ ] Perform final refinement
[ ] Prepare final project demonstration
```

---

## 09. END-TO-END PIPELINE

The final system is intended to demonstrate the following complete workflow:

```text
                         ATTACKER
                            |
                            v
                    +---------------+
                    |   Kali Linux  |
                    +-------+-------+
                            |
                            | Reconnaissance /
                            | Controlled Traffic
                            v
                    +---------------+
                    | Metasploitable|
                    |      2        |
                    +-------+-------+
                            |
                            v
                    +---------------+
                    | Network       |
                    | Traffic       |
                    +-------+-------+
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          +-------------+       +-------------+
          |  Wireshark  |       |  Suricata   |
          |   Analysis  |       |     IDS     |
          +-------------+       +------+------+
                                       |
                                       v
                                +-------------+
                                | IDS Alerts  |
                                +------+------+
                                       |
                                       v
                                +-------------+
                                |    Alert    |
                                |  Processing |
                                +------+------+
                                       |
                                       v
                                +-------------+
                                |    Flask    |
                                |  Dashboard  |
                                +-------------+
```

---

## 10. REPOSITORY STRUCTURE

```text
Network-Intrusion-Detection-Lab/
│
├── attack/
│   ├── reconnaissance/
│   └── README.md
│
├── analysis/
│   ├── captures/
│   ├── screenshots/
│   └── README.md
│
├── detection/
│   ├── rules/
│   ├── suricata/
│   └── README.md
│
├── dashboard/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── README.md
│
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   ├── setup.md
│   ├── testing.md
│   └── week1-progress.md
│
├── README.md
└── .gitignore
```

---

## 11. REPOSITORY GUIDE

| Folder       | Purpose                                                             |
| ------------ | ------------------------------------------------------------------- |
| `attack/`    | Nmap reconnaissance and controlled attack activities                |
| `analysis/`  | Wireshark captures and network traffic analysis                     |
| `detection/` | Suricata configuration, rules and detection development             |
| `dashboard/` | Flask / Python dashboard development                                |
| `docs/`      | Architecture, setup, methodology, testing and project documentation |

---

## 12. DOCUMENTATION

Detailed project documentation is maintained inside the `docs/` directory.

```text
docs/
│
├── architecture.md
├── methodology.md
├── setup.md
├── testing.md
└── week1-progress.md
```

### Documentation Overview

#### `architecture.md`

Describes:

* System architecture
* Network topology
* Major components
* Data flow
* Component interactions

#### `methodology.md`

Describes:

* Project methodology
* Reconnaissance process
* Traffic generation
* Packet analysis
* IDS detection
* Alert processing

#### `setup.md`

Contains:

* VirtualBox setup
* VM configuration
* Network configuration
* Required tools
* Laboratory setup instructions

#### `testing.md`

Describes:

* Test cases
* Detection validation
* Integration testing
* Expected results
* Observed results

#### `week1-progress.md`

Contains the project's development progress and implementation updates.

---

## 13. SECURITY AND ETHICAL USE

This project is intended strictly for:

```text
Educational
     +
Research
     +
Authorized
     +
Controlled
```

All scanning, traffic generation, reconnaissance, and attack activities are performed only against intentionally vulnerable systems inside the controlled project laboratory or other explicitly authorized infrastructure.

No unauthorized systems or networks should be targeted.

---

## 14. PROJECT LEARNING OUTCOMES

Through this project, the team aims to gain practical experience with:

```text
Network Reconnaissance
        |
        v
Network Protocols
        |
        v
Packet Capture
        |
        v
Traffic Analysis
        |
        v
Intrusion Detection
        |
        v
Security Alerting
        |
        v
Alert Processing
        |
        v
Security Visualization
        |
        v
System Integration
```

The project also provides practical experience in:

* Linux-based cybersecurity environments
* Virtual machine networking
* Network reconnaissance
* Packet analysis
* IDS technologies
* Detection rules
* Python development
* Flask web development
* Git version control
* GitHub collaboration
* Team-based cybersecurity development

---

## 15. PROJECT STATUS

```text
==================================================
              PROJECT STATUS
==================================================

Review: 1
Stage: Early Implementation

--------------------------------------------------

Laboratory Setup              COMPLETED
Reconnaissance                COMPLETED
Service Enumeration           COMPLETED
Packet Analysis               COMPLETED
Git / GitHub Collaboration    COMPLETED

--------------------------------------------------

Suricata IDS                  IN PROGRESS
Detection Rules               IN PROGRESS
Alert Processing              IN PROGRESS
Flask Dashboard               IN PROGRESS
System Integration            IN PROGRESS

--------------------------------------------------

Final End-to-End Pipeline     UPCOMING
Multi-Machine Demo            UPCOMING
Final Integration Testing     UPCOMING
Final Refinement              UPCOMING

==================================================
```

---

## 16. FINAL GOAL

The final objective of the project is to create a functional and demonstrable cybersecurity laboratory capable of showing the complete process:

```text
+--------------------+
| Reconnaissance     |
+---------+----------+
          |
          v
+--------------------+
| Network Activity   |
+---------+----------+
          |
          v
+--------------------+
| Packet Capture     |
+---------+----------+
          |
          v
+--------------------+
| IDS Detection      |
+---------+----------+
          |
          v
+--------------------+
| Security Alert     |
+---------+----------+
          |
          v
+--------------------+
| Alert Processing   |
+---------+----------+
          |
          v
+--------------------+
| Visualization      |
+--------------------+
```

The completed system will demonstrate how network activity can be generated in a controlled environment, observed through packet analysis, detected by an IDS, converted into security alerts, and finally presented through a visualization layer.

---

## 17. PROJECT PHILOSOPHY

```text
LEARN
  |
  v
BUILD
  |
  v
TEST
  |
  v
ANALYZE
  |
  v
IMPROVE
  |
  v
DEMONSTRATE
```

This project focuses on practical cybersecurity learning through controlled experimentation, collaboration, documentation, and iterative development.

---

## 18. PROJECT STATUS SUMMARY

```text
==================================================
       NETWORK INTRUSION DETECTION LAB
==================================================

Environment       : Virtualized Cybersecurity Lab
Attacker           : Kali Linux
Target             : Metasploitable2
Packet Analysis    : Wireshark
IDS                : Suricata
Backend / Dashboard: Python + Flask
Version Control    : Git + GitHub

--------------------------------------------------

CURRENT STAGE
Review 1 — Early Implementation

--------------------------------------------------

CORE LAB
[✓] Virtual Machines
[✓] Host-only Network
[✓] Connectivity
[✓] Reconnaissance
[✓] Service Enumeration
[✓] Packet Capture
[✓] Initial Traffic Analysis

--------------------------------------------------

SYSTEM DEVELOPMENT
[~] Suricata
[~] Detection Rules
[~] Alert Processing
[~] Flask Dashboard
[~] Integration

--------------------------------------------------

FINAL TARGET
Attack
  ↓
Traffic
  ↓
Analysis
  ↓
Detection
  ↓
Alerts
  ↓
Visualization

==================================================
```

---

## 19. DISCLAIMER

This repository contains material intended for **authorized cybersecurity education, experimentation, and research**.

The laboratory is designed around intentionally vulnerable systems and isolated environments. Users are responsible for ensuring that all security testing is performed only on systems they own or have explicit permission to test.

---

## 20. PROJECT DEVELOPMENT

This project is being developed collaboratively using Git and GitHub.

The repository will continue to evolve as the team completes:

```text
Detection
     ↓
Alert Processing
     ↓
Dashboard
     ↓
Integration
     ↓
Testing
     ↓
Demonstration
     ↓
Final Release
```

---

# NETWORK INTRUSION DETECTION LAB

```text
CONTROLLED ENVIRONMENT
        +
PRACTICAL SECURITY
        +
NETWORK ANALYSIS
        +
INTRUSION DETECTION
        +
VISUALIZATION
```

---
