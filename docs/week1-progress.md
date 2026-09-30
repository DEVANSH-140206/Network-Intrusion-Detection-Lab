# Week 1 Progress

## Objective

Establish the foundation for the Network Intrusion Detection Lab by setting up the virtual environment, assigning team responsibilities, preparing the development workflow, and ensuring every team member understands their role before implementation begins.

---

# Week 1 Goals

- Build an isolated cybersecurity practice lab.
- Assign responsibilities to all team members.
- Set up the project repository.
- Configure the required virtual machines.
- Learn the tools required for each module.
- Ensure every team member can contribute using Git and GitHub.

---

# Team Responsibilities

### Team Leader (Attack Module)

Responsibilities

- Planned the overall project architecture.
- Created and organized the GitHub repository.
- Assigned responsibilities to each team member.
- Set up the attack environment.
- Learned and tested attack simulation tools.
- Coordinated communication between all members.

Current Progress

- Installed Oracle VirtualBox.
- Imported Kali Linux Virtual Machine.
- Imported Metasploitable2 Virtual Machine.
- Configured Host-only networking.
- Verified communication between both virtual machines.
- Performed host discovery using Nmap.
- Performed service enumeration using Nmap.
- Captured generated traffic using Wireshark.
- Studied VirtualBox networking concepts.
- Prepared documentation for future project development.

---

### Team Member 2 (Detection Module)

Responsibilities

- Learn Ubuntu Linux.
- Install Ubuntu Virtual Machine.
- Research Suricata IDS.
- Prepare the detection environment.
- Learn Suricata configuration and rule creation.

Current Progress

- Learning Git and GitHub workflow.
- Studying Linux basics.
- Preparing Ubuntu installation.
- Researching Suricata architecture and deployment.

---

### Team Member 3 (Victim Machine Module)

Responsibilities

- Configure the victim environment.
- Prepare vulnerable operating system.
- Assist in testing attacks.
- Generate network traffic for IDS analysis.

Current Progress

- Learning Git and GitHub workflow.
- Preparing the Metasploitable2 environment.
- Understanding the role of the victim machine within the project.
- Researching common vulnerable services available in Metasploitable2.

---

# Tasks Completed

- Installed Oracle VirtualBox.
- Configured VirtualBox environment.
- Imported Kali Linux VM.
- Imported Metasploitable2 VM.
- Configured Host-only networking.
- Verified communication between virtual machines.
- Successfully scanned the victim machine using Nmap.
- Captured attack traffic using Wireshark.
- Created the project repository structure.
- Assigned team responsibilities.
- Initialized Git workflow for project collaboration.

---

# Skills Learned

## Virtualization

- Virtual Machines
- Hypervisors
- Host OS
- Guest OS
- Virtual Hard Disks
- Snapshots
- Shared Clipboard
- Shared Folders

---

## Virtual Networking

- NAT
- Host-only Adapter
- Bridged Adapter
- Internal Network
- Multiple Network Adapters
- VM Communication

---

## Reconnaissance

- Host Discovery
- Port Scanning
- Service Enumeration
- Understanding IP Addressing
- Network Segmentation

---

## Packet Analysis

- Wireshark Interface Selection
- Live Packet Capture
- Packet Inspection
- Source and Destination IP Analysis
- Understanding Captured Network Traffic

---

## Collaboration

- Git Repository Structure
- Branch Workflow
- Basic Git Commands
- Team Collaboration Strategy
- Project Documentation

---

# Challenges Faced

## Technical Challenges

- Kali Linux initially displayed a black screen after boot.
- Understanding VirtualBox networking modes.
- Distinguishing between NAT, Host-only, Bridged, and Internal networking.
- Identifying the correct IP address of the victim machine.
- Understanding multiple virtual network adapters.
- Configuring communication between virtual machines.

---

## Team Challenges

- Dividing project responsibilities fairly among members.
- Ensuring each member understood their assigned module.
- Helping team members begin learning Git and GitHub.
- Planning the overall development timeline.
- Designing a repository structure that remains organized as the project grows.
- Coordinating learning while simultaneously building the project.

---

# Outcome

At the end of Week 1, the team successfully established a functional cybersecurity lab environment. The attack environment is operational, communication between virtual machines has been verified, and basic reconnaissance and packet capture have been successfully demonstrated. Team responsibilities have been finalized, the GitHub repository has been organized, and every member has started preparing for their respective project modules. This provides a stable foundation for integrating the detection system in the coming weeks.

---

# Next Week Goals

- Install Ubuntu Virtual Machine.
- Install and configure Suricata IDS.
- Configure network communication between Kali, Ubuntu, and Metasploitable2.
- Generate attack traffic from Kali.
- Verify that Suricata detects generated attacks.
- Begin developing the log analysis module.
- Continue documenting project progress and testing results.