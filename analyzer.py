"""
BOD 26-04 Automated Exposure Analyzer
======================================
Uses AWS VPC Network Access Analyzer and Network Insights Paths
via Boto3 to identify internet-reachable instances and correlate
them against vulnerability data for risk-prioritized reporting.

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
)

# Initialize Boto3 clients
ec2_client = boto3.client("ec2", region_name=REGION)


# =============================================================
# STEP 1: Enumerate Instances and Check CVE Tags
# =============================================================

def get_instances_with_cve_tags():
    """
    Pulls all running EC2 instances in the account and checks for CVE tags.

    In this lab, CVE data is simulated via EC2 instance tags.
    To simulate a vulnerable instance, add a tag in the AWS Console:
        Key   = CVE
        Value = CVE-2026-43284

    In production, replace this function with a live feed from:
        - AWS Inspector: ec2_client.describe_findings()
        - Tenable or Qualys API
        - CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """
    print("[*] Enumerating EC2 instances and checking for vulnerability tags...")

    response = ec2_client.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
    instances = []

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            security_groups = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
            cve_tag = tags.get("CVE", None)

            # Get the primary network interface ID for path analysis
            network_interfaces = instance.get("NetworkInterfaces", [])
            primary_eni = network_interfaces[0]["NetworkInterfaceId"] if network_interfaces else None

            # Check if instance is in one of our target security groups
            in_scope = any(sg in SECURITY_GROUP_IDS for sg in security_groups)

            instances.append({
                "instance_id": instance_id,
                "state": instance["State"]["Name"],
                "security_groups": security_groups,
                "cve": cve_tag,
                "name": tags.get("Name", "Unnamed"),
                "primary_eni": primary_eni,
                "in_scope": in_scope,
                "public_ip": instance.get("PublicIpAddress", None),
            })

    print(f"[+] Found {len(instances)} running instance(s).\n")
    return instances


# =============================================================
# STEP 2: Check Reachability via Network Insights Path
# =============================================================

def check_internet_reachability(instance):
    """
    Uses AWS Network Insights Path to trace whether a specific
    EC2 instance is reachable from the Internet Gateway.

    This is the most accurate method: it traces the full network
    path including routing tables, NACLs, and security group rules.
    """
    instance_id = instance["instance_id"]
    eni_id = instance["primary_eni"]

    if not eni_id:
        print(f"  [!] {instance_id}: No network interface found, skipping.")
        return False

    print(f"  [*] Checking reachability for {instance_id} ({instance['name']})...")

    try:
        # Create a network insights path from IGW to this instance's ENI
        path_response = ec2_client.create_network_insights_path(
            Source=IGW_ID,
            Destination=eni_id,
            Protocol="TCP",
            TagSpecifications=[
                {
                    "ResourceType": "network-insights-path",
                    "Tags": [{"Key": "Name", "Value": f"BOD-26-04-path-{instance_id}"}]
                }
            ]
        )
        path_id = path_response["NetworkInsightsPath"]["NetworkInsightsPathId"]

        # Start the analysis
        analysis_response = ec2_client.start_network_insights_analysis(
            NetworkInsightsPathId=path_id
        )
        analysis_id = analysis_response["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]

        # Poll for completion
        for _ in range(20):
            status_response = ec2_client.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id]
            )
            analysis = status_response["NetworkInsightsAnalyses"][0]
            status = analysis["Status"]

            if status == "succeeded":
                # NetworkPathFound can be True, False, or None
                reachable = analysis.get("NetworkPathFound")
                if reachable is None:
                    reachable = False
                print(f"      Path found: {reachable}")

                # Clean up: delete analysis first, then path
                try:
                    ec2_client.delete_network_insights_analysis(
                        NetworkInsightsAnalysisId=analysis_id
                    )
                except Exception:
                    pass
                try:
                    ec2_client.delete_network_insights_path(
                        NetworkInsightsPathId=path_id
                    )
                except Exception:
                    pass
                return reachable

            elif status == "failed":
                print(f"      Analysis failed.")
                try:
                    ec2_client.delete_network_insights_path(
                        NetworkInsightsPathId=path_id
                    )
                except Exception:
                    pass
                return False

            time.sleep(10)

        return False

    except Exception as e:
        print(f"      Error analyzing {instance_id}: {e}")
        return False


# =============================================================
# STEP 3: Correlate Reachability with Vulnerability Data
# =============================================================

def correlate_findings(instances):
    """
    Cross-references internet-reachable paths with instance vulnerability data.

    BOD 26-04 risk logic:
      - Reachable + CVE tag       = CRITICAL (3-day remediation window)
      - Reachable + no CVE        = HIGH (verify patch status immediately)
      - Not reachable + CVE       = LOW (standard patch cycle)
      - Not reachable + no CVE    = MINIMAL
    """
    print("\n[*] Running reachability analysis for each instance...")
    print("    (Each path analysis takes ~30 seconds)\n")

    results = []
    for instance in instances:
        is_reachable = check_internet_reachability(instance)
        cve = instance.get("cve")

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
            "public_ip": instance.get("public_ip"),
            "internet_reachable": is_reachable,
            "cve": cve,
            "risk_level": risk_level,
            "recommendation": recommendation,
        })

    # Sort by risk priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "LOW": 2, "MINIMAL": 3}
    results.sort(key=lambda x: priority_order.get(x["risk_level"], 99))

    print(f"\n[+] Correlation complete. {len(results)} instance(s) evaluated.\n")
    return results


# =============================================================
# STEP 4: Generate Report
# =============================================================

def generate_report(results):
    """
    Outputs a formatted risk-priority report to the console
    and saves a JSON version for documentation and audit trails.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print("=" * 60)
    print("  BOD 26-04 NETWORK EXPOSURE RISK REPORT")
    print("=" * 60)
    print(f"  Timestamp  : {timestamp}")
    print(f"  IGW Source : {IGW_ID}")
    print(f"  Region     : {REGION}")
    print(f"  Directive  : CISA BOD 26-04")
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
        print(f"  Public IP          : {r.get('public_ip', 'None')}")
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
        instances = get_instances_with_cve_tags()

        if not instances:
            print("[!] No running instances found. Launch an EC2 instance and try again.")
            return

        results = correlate_findings(instances)
        generate_report(results)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        print("\nTroubleshooting:")
        print("  1. Confirm AWS credentials: run 'aws sts get-caller-identity'")
        print("  2. Verify your IAM user has EC2 permissions")
        print("  3. Confirm your IGW_ID in config.py is correct")


if __name__ == "__main__":
    main()
