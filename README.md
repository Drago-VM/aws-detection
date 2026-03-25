<!-- 🔥 Banner -->

<h1 align="center">🚨 AWS Threat Detection Skills</h1>
<p align="center">
<b>Claude-Powered Cloud Security Detection System</b><br>
Detect • Analyze • Explain
</p>

<p align="center">
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python"/>
<img src="https://img.shields.io/badge/AWS-CloudTrail-orange?style=for-the-badge&logo=amazonaws"/>
<img src="https://img.shields.io/badge/AI-Claude-purple?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

---

## 🧠 Overview

This project simulates a **real-world SOC (Security Operations Center)** system that:

- 📡 Monitors AWS activity logs  
- 🔍 Detects suspicious behavior  
- 🤖 Uses AI (Claude) to explain threats  
- 📝 Produces analyst-ready insights  

---

## ⚡ Architecture

```text
AWS CloudTrail Logs
       ↓
Detection Logic (Python)
       ↓
Claude API (Prompt Analysis)
       ↓
Plain-English Security Insights
```

## 📂 Project Structure

```text
aws-detection-skills/
│
├── skills/
│   ├── iam/
│   │   └── root_login_detection/
│   │       ├── metadata.yaml
├── iam/
│   ├── root_login_detection/
|   |       ├── metadata.yaml
│   │       ├── detection.py
│   │       ├── prompt.txt
│   │       └── tests/sample.json   
│   └── get_user_policy_anomaly/
|   |       ├── metadata.yaml
│   │       ├── detection.py
│   │       ├── prompt.txt
│   │       └── tests/sample.json     
├── s3/
│   ├── data_exfiltration/
|   |       ├── metadata.yaml
│   │       ├── detection.py
│   │       ├── prompt.txt
│   │       └── tests/sample.json        
│   └── put_encrypted_object_anomaly/
|   |       ├── metadata.yaml
│   │       ├── detection.py
│   │       ├── prompt.txt
│   │       └── tests/sample.json 
└── logging/
|    └── cloudtrail_digest_validation/
|   |       ├── metadata.yaml
│   │       ├── detection.py
│   │       ├── prompt.txt
│   │       └── tests/sample.json 
├── shared/
│   └── claude_utils.py
│
└── README.md
```
## 🚀 Quick Start

```text
git clone https://github.com/yourname/aws-detection-skills.git
cd aws-detection-skills
```
## ▶️ Run Detection
```text
python skills/iam/root_login_detection/detection.py
```
