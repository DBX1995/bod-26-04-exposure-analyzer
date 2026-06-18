# =============================================================
# BOD 26-04 Exposure Analyzer — Configuration
# =============================================================
# Edit these values with your actual AWS resource IDs before
# running analyzer.py.
#
# Your IDs can be found in the AWS Console under:
#   VPC > Internet Gateways
#   VPC > Security Groups
# =============================================================

# AWS Region
REGION = "us-east-1"

# Internet Gateway ID (source for the Network Access Analyzer scope)
# This is the IGW attached to the VPC you want to analyze.
IGW_ID = "igw-0741b2eaf916b9f8c"

# Security Group IDs (destinations for the analysis)
# These represent the compute resources you want to check for internet reachability.
SECURITY_GROUP_IDS = [
    "sg-035c10964af604666",   # default VPC security group
    "sg-09af48cc9413d8ba2",   # containerofcats-SG
]

# Scope name tag (used to identify the scope in the AWS Console)
SCOPE_NAME = "BOD-26-04-Exposure-Scope"

# Simulated CVE data for lab demonstration
# In production, replace this with a live feed from AWS Inspector,
# Tenable, or the CISA KEV catalog API.
SIMULATED_CVE_MAP = {
    # Format: "instance-id": [{"cve_id": "...", "cvss": float}]
    # This is populated dynamically in analyzer.py based on tagged instances.
    # To simulate a vulnerable instance, add a tag in the AWS Console:
    #   Key   = "CVE"
    #   Value = "CVE-2026-43284"
}

# CVE severity reference (CVSS score thresholds)
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0
