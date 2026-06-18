# BOD 26-04 Automated Exposure Analyzer

Automated AWS network exposure analysis aligned to **CISA Binding Operational Directive 26-04**, using Amazon VPC Network Access Analyzer and the Boto3 SDK to generate risk-priority reports based on actual network topology rather than abstract CVSS scores alone.

---

## Why This Exists

CISA BOD 26-04 requires federal agencies and their contractors to identify and remediate internet-exposed assets within aggressive compliance windows. The directive introduces an **Asset Exposure** metric that demands organizations know not just *what* vulnerabilities exist on their systems, but *which vulnerable assets are actually reachable from the public internet*.

Traditional vulnerability scanners report CVSS scores in isolation. A critical CVE on an air-gapped internal server carries a very different real-world risk than the same CVE on a publicly routable EC2 instance. This tool bridges that gap.

**This project automates the following workflow:**
1. Define a VPC Network Access Analyzer scope targeting your Internet Gateway as the source and internal compute security groups as the destination
2. Execute the analysis programmatically via Boto3
3. Correlate internet-reachable instances against a vulnerability feed (simulated CVE tags in this lab; production deployments would integrate AWS Inspector or Tenable)
4. Generate an instantaneous risk-priority report ranked by actual exposure, not theoretical CVSS severity alone

---

## Architecture

```
Internet Gateway (Source)
        |
        v
VPC Network Access Analyzer Scope
        |
        v
Security Group Targets (Destination)
        |
        v
Boto3 Analysis Script (analyzer.py)
        |
        v
Risk Priority Report (JSON + Console Output)
```

---

## Prerequisites

- Python 3.8+
- AWS CLI configured with appropriate credentials (`aws configure`)
- IAM permissions: `ec2:CreateNetworkInsightsAccessScope`, `ec2:StartNetworkInsightsAccessScopeAnalysis`, `ec2:GetNetworkInsightsAccessScopeAnalysisFindings`, `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`
- An existing VPC with an attached Internet Gateway

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/DBX1995/bod-26-04-exposure-analyzer.git
cd bod-26-04-exposure-analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure your environment

Edit the `config.py` file with your AWS resource IDs:

```python
IGW_ID = "igw-xxxxxxxxxxxxxxxxx"       # Your Internet Gateway ID
SECURITY_GROUP_IDS = [                  # Target security groups to analyze
    "sg-xxxxxxxxxxxxxxxxx",
    "sg-xxxxxxxxxxxxxxxxx"
]
REGION = "us-east-1"
```

---

## Usage

### Run the full analysis

```bash
python analyzer.py
```

### Sample output

```
====================================================
  BOD 26-04 NETWORK EXPOSURE RISK REPORT
====================================================
Analysis Timestamp : 2026-06-17T14:32:01Z
Scope ID           : nis-scope-0abc123def456
IGW Source         : igw-0741b2eaf916b9f8c
Targets Analyzed   : 2 security groups

----------------------------------------------------
FINDINGS SUMMARY
----------------------------------------------------
Total instances evaluated  : 3
Internet-reachable          : 2
Not reachable               : 1

----------------------------------------------------
RISK-PRIORITIZED INSTANCE LIST
----------------------------------------------------
[CRITICAL] i-0abc123def456789a
  Security Group : sg-09af48cc9413d8ba2 (containerofcats-SG)
  Internet Reachable : YES
  CVE Tags       : CVE-2026-43284 (CVSS 9.8)
  Risk Score     : CRITICAL — Exposed + Critical Vulnerability
  Recommendation : Isolate immediately. Patch or apply compensating control within 3 days per BOD 26-04.

[HIGH] i-0def456abc789012b
  Security Group : sg-035c10964af604666 (default)
  Internet Reachable : YES
  CVE Tags       : None detected
  Risk Score     : HIGH — Internet-exposed with no confirmed patch status
  Recommendation : Verify patch status. Confirm exposure is intentional and documented.

[LOW] i-0ghi789def012345c
  Security Group : sg-035c10964af604666 (default)
  Internet Reachable : NO
  CVE Tags       : CVE-2026-43284 (CVSS 9.8)
  Risk Score     : LOW — Critical CVE present but not internet-reachable
  Recommendation : Patch per standard maintenance window. Not a BOD 26-04 priority.

====================================================
  END OF REPORT
====================================================
```

---

## Key Concepts

**Why network topology changes your risk calculus:**
A CVSS 9.8 vulnerability on an internal-only instance with no internet path is a patching priority but not an emergency. The same vulnerability on an internet-facing instance is a BOD 26-04 compliance incident requiring action within 3 days. This tool makes that distinction programmatically and automatically.

**VPC Network Access Analyzer:**
AWS Network Access Analyzer identifies unintended network access to your resources. Unlike Security Group audits that check rules in isolation, Network Access Analyzer traces the full network path — routing tables, NACLs, security groups, and gateway configurations — to determine if a path from source to destination actually exists end-to-end.

**Production integration points:**
In a production environment, the CVE correlation step would be replaced with a live feed from:
- AWS Inspector (native integration, no additional tooling required)
- Tenable.io or Qualys API
- CISA Known Exploited Vulnerabilities (KEV) catalog API

---

## File Structure

```
bod-26-04-exposure-analyzer/
├── README.md               # This file
├── config.py               # Your AWS resource IDs (edit before running)
├── analyzer.py             # Main analysis script
├── setup/
│   └── create_scope.sh     # CLI commands to manually create the NAA scope
├── sample_output/
│   └── sample_report.json  # Example output with sanitized IDs
└── requirements.txt        # Python dependencies
```

---

## Compliance Context

| BOD 26-04 Requirement | How This Tool Addresses It |
|---|---|
| Identify internet-exposed assets | VPC Network Access Analyzer scope traces full network path from IGW |
| Prioritize by actual exposure | Risk score combines reachability + vulnerability status |
| 3-day remediation window for critical | CRITICAL-rated findings include BOD 26-04 remediation language |
| Automated reporting | Script generates timestamped JSON report on every run |

---

## Author

**DBX1995** — Cloud Security Portfolio Project  
Demonstrating BOD 26-04 compliance automation for federal and defense contractor environments.
