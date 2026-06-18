"""
BOD 26-04 Automated Exposure Analyzer
======================================
Uses AWS VPC Network Access Analyzer via Boto3 to identify
internet-reachable instances and correlate them against
vulnerability data for risk-prioritized reporting.

Aligned to CISA Binding Operational Directive 26-04.

Usage:
    python analyzer.py

Requirements:
    pip install -r requirements.txt
    AWS credentials configured via: aws configure
"""

import boto3
import json
import time
import datetime
from config import (
    REGION,
    IGW_ID,
    SECURITY_GROUP_IDS,
    SCOPE_NAME,
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
)

# Initialize Boto3 clients
ec2_client = boto3.client("ec2", region_name=REGION)


# =============================================================
# STEP 1: Create the Network Access Analyzer Scope
# =============================================================

def create_network_access_scope():
    """
    Creates a VPC Network Access Analyzer scope that traces paths
    from the Internet Gateway to the specified security groups.

    This scope definition is the core of BOD 26-04 asset exposure
    analysis: it asks AWS to find any route that allows traffic
    originating from the public internet to reach our compute resources.
    """
    print("[*] Creating Network Access Analyzer scope...")
    print(f"    Source  : Internet Gateway ({IGW_ID})")
    print(f"    Targets : {len(SECURITY_GROUP_IDS)} security group(s)")

    # Build destination filters from security group list
    destinations = [
        {"SecurityGroups": {"GroupId": sg_id}}
        for sg_id in SECURITY_GROUP_IDS
    ]

    try:
        response = ec2_client.create_network_insights_access_scope(
            MatchPaths=[
                {
                    "Source": {
                        "ResourceStatement": {
                            "ResourceTypes": ["AWS::EC2::InternetGateway"]
                        }
                    },
                    "Destination": {
                        "ResourceStatement": {
                            "ResourceTypes": ["AWS::EC2::SecurityGroup"]
                        }
                    }
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": "network-insights-access-scope",
                    "Tags": [{"Key": "Name", "Value": SCOPE_NAME}]
                }
            ]
        )

        scope_id = response["NetworkInsightsAccessScope"]["NetworkInsightsAccessScopeId"]
        print(f"[+] Scope created successfully: {scope_id}\n")
        return scope_id

    except ec2_client.exceptions.ClientError as e:
        # If the scope already exists, find and reuse it
        if "already exists" in str(e) or "Duplicate" in str(e):
            print("[!] Scope may already exist. Searching for existing scope...")
            return find_existing_scope()
        raise e


def find_existing_scope():
    """Finds an existing Network Access Analyzer scope by name tag."""
    response = ec2_client.describe_network_insights_access_scopes(
        Filters=[{"Name": "tag:Name", "Values": [SCOPE_NAME]}]
    )
    scopes = response.get("NetworkInsightsAccessScopes", [])
    if scopes:
        scope_id = scopes[0]["NetworkInsightsAccessScopeId"]
        print(f"[+] Found existing scope: {scope_id}\n")
        return scope_id
    raise RuntimeError("No existing scope found and could not create a new one.")


# =============================================================
# STEP 2: Run the Analysis
# =============================================================

def run_analysis(scope_id):
    """
    Starts a Network Access Analyzer analysis against the defined scope
    and polls until completion. Analysis typically takes 1-3 minutes.
    """
    print("[*] Starting network access scope analysis...")
    print("    This may take 1-3 minutes. AWS is tracing all network paths...\n")

    response = ec2_client.start_network_insights_access_scope_analysis(
        NetworkInsightsAccessScopeId=scope_id
    )

    analysis_id = response["NetworkInsightsAccessScopeAnalysis"]["NetworkInsightsAccessScopeAnalysisId"]
    print(f"[*] Analysis started: {analysis_id}")

    # Poll for completion
    while True:
        status_response = ec2_client.describe_network_insights_access_scope_analyses(
            NetworkInsightsAccessScopeAnalysisIds=[analysis_id]
        )
        status = status_response["NetworkInsightsAccessScopeAnalyses"][0]["Status"]
        print(f"    Status: {status}")

        if status == "succeeded":
            print("[+] Analysis complete.\n")
            break
        elif status == "failed":
            raise RuntimeError("Network Access Analyzer analysis failed. Check IAM permissions.")

        time.sleep(15)

    return analysis_id


# =============================================================
# STEP 3: Retrieve Findings
# =============================================================

def get_findings(analysis_id):
    """
    Retrieves the findings from the completed analysis.
    Findings represent confirmed network paths from the IGW
    to security group members — i.e., internet-reachable resources.
    """
    print("[*] Retrieving analysis findings...")

    response = ec2_client.get_network_insights_access_scope_analysis_findings(
        NetworkInsightsAccessScopeAnalysisId=analysis_id
    )

    findings = response.get("AnalysisFindings", [])
    print(f"[+] Findings retrieved: {len(findings)} internet-reachable path(s) found.\n")
    return findings


# =============================================================
# STEP 4: Enumerate Instances and Check CVE Tags
# =============================================================

def get_instances_with_cve_tags():
    """
    Pulls all EC2 instances in the account and checks for CVE tags.

    In this lab, CVE data is simulated via EC2 instance tags.
    To simulate a vulnerable instance, add a tag in the AWS Console:
        Key   = CVE
        Value = CVE-2026-43284

    In production, replace this function with a call to:
        - AWS Inspector: ec2_client.describe_findings()
        - Tenable or Qualys API
        - CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """
    print("[*] Enumerating EC2 instances and checking for vulnerability tags...")

    response = ec2_client.describe_instances()
    instances = []

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            state = instance["State"]["Name"]
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            security_groups = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
            cve_tag = tags.get("CVE", None)

            instances.append({
                "instance_id": instance_id,
                "state": state,
                "security_groups": security_groups,
                "cve": cve_tag,
                "name": tags.get("Name", "Unnamed"),
            })

    print(f"[+] Found {len(instances)} instance(s).\n")
    return instances


# =============================================================
# STEP 5: Correlate Reachability with Vulnerability Data
# =============================================================

def correlate_findings(findings, instances):
    """
    Cross-references internet-reachable paths with instance vulnerability data.

    This is the core BOD 26-04 logic:
      - An instance that IS reachable AND HAS a critical CVE = CRITICAL priority
      - An instance that IS reachable but has no CVE data = HIGH (unknown patch status)
      - An instance that is NOT reachable but has a CVE = LOW (patch normally)
      - An instance that is NOT reachable and has no CVE = MINIMAL
    """
    print("[*] Correlating reachability findings with vulnerability data...")

    # Extract security groups that have confirmed internet-reachable paths
    reachable_sgs = set()
    for finding in findings:
        for component in finding.get("FindingComponents", []):
            if component.get("Component", {}).get("ResourceType") == "AWS::EC2::SecurityGroup":
                reachable_sgs.add(component["Component"]["Id"])

    results = []
    for instance in instances:
        if instance["state"] != "running":
            continue

        is_reachable = any(sg in reachable_sgs for sg in instance["security_groups"])
        cve = instance.get("cve")

        # Assign risk score
        if is_reachable and cve:
            risk_level = "CRITICAL"
            recommendation = (
                "Isolate immediately. Patch or apply compensating control "
                "within 3 days per BOD 26-04 Section 3(a)."
            )
        elif is_reachable and not cve:
            risk_level = "HIGH"
            recommendation = (
                "Instance is internet-exposed. Verify patch status immediately. "
                "Confirm exposure is intentional and documented in your asset inventory."
            )
        elif not is_reachable and cve:
            risk_level = "LOW"
            recommendation = (
                "CVE detected but no internet path found. Patch per standard "
                "maintenance window. Not a BOD 26-04 priority."
            )
        else:
            risk_level = "MINIMAL"
            recommendation = "No internet exposure detected and no CVE tags found."

        results.append({
            "instance_id": instance["instance_id"],
            "name": instance["name"],
            "security_groups": instance["security_groups"],
            "internet_reachable": is_reachable,
            "cve": cve,
            "risk_level": risk_level,
            "recommendation": recommendation,
        })

    # Sort by risk level priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "LOW": 2, "MINIMAL": 3}
    results.sort(key=lambda x: priority_order.get(x["risk_level"], 99))

    print(f"[+] Correlation complete. {len(results)} instance(s) evaluated.\n")
    return results


# =============================================================
# STEP 6: Generate Report
# =============================================================

def generate_report(scope_id, analysis_id, results):
    """
    Outputs a formatted risk-priority report to the console
    and saves a JSON version for documentation and audit trails.
    """
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    print("=" * 60)
    print("  BOD 26-04 NETWORK EXPOSURE RISK REPORT")
    print("=" * 60)
    print(f"  Timestamp  : {timestamp}")
    print(f"  Scope ID   : {scope_id}")
    print(f"  Analysis ID: {analysis_id}")
    print(f"  IGW Source : {IGW_ID}")
    print(f"  Region     : {REGION}")
    print("=" * 60)

    counts = {"CRITICAL": 0, "HIGH": 0, "LOW": 0, "MINIMAL": 0}
    for r in results:
        counts[r["risk_level"]] = counts.get(r["risk_level"], 0) + 1

    print("\nSUMMARY")
    print("-" * 60)
    print(f"  Total instances evaluated : {len(results)}")
    print(f"  CRITICAL                  : {counts['CRITICAL']}")
    print(f"  HIGH                      : {counts['HIGH']}")
    print(f"  LOW                       : {counts['LOW']}")
    print(f"  MINIMAL                   : {counts['MINIMAL']}")

    print("\nRISK-PRIORITIZED FINDINGS")
    print("-" * 60)

    for r in results:
        print(f"\n[{r['risk_level']}] {r['instance_id']} ({r['name']})")
        print(f"  Security Groups    : {', '.join(r['security_groups'])}")
        print(f"  Internet Reachable : {'YES' if r['internet_reachable'] else 'NO'}")
        print(f"  CVE               : {r['cve'] if r['cve'] else 'None detected'}")
        print(f"  Recommendation    : {r['recommendation']}")

    print("\n" + "=" * 60)
    print("  END OF REPORT")
    print("=" * 60)

    # Save JSON report
    report = {
        "report_metadata": {
            "timestamp": timestamp,
            "scope_id": scope_id,
            "analysis_id": analysis_id,
            "igw_source": IGW_ID,
            "region": REGION,
            "directive": "CISA BOD 26-04",
        },
        "summary": counts,
        "findings": results,
    }

    output_path = "sample_output/sample_report.json"
    try:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report saved to: {output_path}")
    except FileNotFoundError:
        with open("sample_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("\n[+] JSON report saved to: sample_report.json")

    return report


# =============================================================
# MAIN
# =============================================================

def main():
    print("\nBOD 26-04 Automated Exposure Analyzer")
    print("Aligned to CISA Binding Operational Directive 26-04\n")

    try:
        scope_id = create_network_access_scope()
        analysis_id = run_analysis(scope_id)
        findings = get_findings(analysis_id)
        instances = get_instances_with_cve_tags()
        results = correlate_findings(findings, instances)
        generate_report(scope_id, analysis_id, results)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        print("\nTroubleshooting:")
        print("  1. Confirm AWS credentials: run 'aws sts get-caller-identity'")
        print("  2. Verify your IAM user has the required EC2 permissions in config.py")
        print("  3. Confirm your IGW_ID and SECURITY_GROUP_IDS in config.py are correct")


if __name__ == "__main__":
    main()
