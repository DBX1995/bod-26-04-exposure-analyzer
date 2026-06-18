#!/bin/bash
# =============================================================
# BOD 26-04 Exposure Analyzer — Manual Scope Setup
# =============================================================
# Use this script to create the Network Access Analyzer scope
# via the AWS CLI if you prefer not to use the Python script.
#
# Prerequisites:
#   AWS CLI installed and configured (aws configure)
#   Replace the placeholder IDs below with your actual values.
# =============================================================

REGION="us-east-1"
IGW_ID="igw-0741b2eaf916b9f8c"
SCOPE_NAME="BOD-26-04-Exposure-Scope"

echo "========================================================"
echo "  BOD 26-04 — Creating Network Access Analyzer Scope"
echo "========================================================"
echo "  Region : $REGION"
echo "  IGW    : $IGW_ID"
echo "  Scope  : $SCOPE_NAME"
echo ""

# Step 1: Create the Network Insights Access Scope
echo "[*] Creating Network Insights Access Scope..."

SCOPE_RESPONSE=$(aws ec2 create-network-insights-access-scope \
  --region "$REGION" \
  --match-paths '[
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
  ]' \
  --tag-specifications "ResourceType=network-insights-access-scope,Tags=[{Key=Name,Value=$SCOPE_NAME}]" \
  --output json)

SCOPE_ID=$(echo "$SCOPE_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['NetworkInsightsAccessScope']['NetworkInsightsAccessScopeId'])")

echo "[+] Scope created: $SCOPE_ID"
echo ""

# Step 2: Start the analysis
echo "[*] Starting analysis (this takes 1-3 minutes)..."

ANALYSIS_RESPONSE=$(aws ec2 start-network-insights-access-scope-analysis \
  --region "$REGION" \
  --network-insights-access-scope-id "$SCOPE_ID" \
  --output json)

ANALYSIS_ID=$(echo "$ANALYSIS_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['NetworkInsightsAccessScopeAnalysis']['NetworkInsightsAccessScopeAnalysisId'])")

echo "[+] Analysis started: $ANALYSIS_ID"
echo ""

# Step 3: Poll for completion
echo "[*] Waiting for analysis to complete..."

while true; do
  STATUS=$(aws ec2 describe-network-insights-access-scope-analyses \
    --region "$REGION" \
    --network-insights-access-scope-analysis-ids "$ANALYSIS_ID" \
    --query "NetworkInsightsAccessScopeAnalyses[0].Status" \
    --output text)

  echo "    Status: $STATUS"

  if [ "$STATUS" == "succeeded" ]; then
    echo "[+] Analysis complete."
    break
  elif [ "$STATUS" == "failed" ]; then
    echo "[!] Analysis failed. Check IAM permissions."
    exit 1
  fi

  sleep 15
done

echo ""

# Step 4: Retrieve findings
echo "[*] Retrieving findings..."

aws ec2 get-network-insights-access-scope-analysis-findings \
  --region "$REGION" \
  --network-insights-access-scope-analysis-id "$ANALYSIS_ID" \
  --output json > ../sample_output/raw_findings.json

echo "[+] Raw findings saved to sample_output/raw_findings.json"
echo ""
echo "========================================================"
echo "  Setup complete. Run: python analyzer.py"
echo "========================================================"
