#!/usr/bin/env python3
"""Auditor basico de configuracao cloud (AWS foco inicial).
Uso:
  python security_tools/cloud_config_auditor.py --provider aws
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone


def audit_aws() -> list[str]:
    findings: list[str] = []
    try:
        import boto3
    except ImportError:
        return ["boto3 nao instalado. Rode: pip install boto3"]

    s3 = boto3.client("s3")
    iam = boto3.client("iam")
    ec2 = boto3.client("ec2")

    # S3 publico
    for bucket in s3.list_buckets().get("Buckets", []):
        bname = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=bname)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            if not all(cfg.get(k, False) for k in [
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
            ]):
                findings.append(f"S3 possivelmente publico: {bname}")
        except Exception:
            findings.append(f"Nao foi possivel validar bloqueio publico do bucket: {bname}")

    # Chaves IAM antigas (> 90 dias)
    users = iam.list_users().get("Users", [])
    now = datetime.now(timezone.utc)
    for user in users:
        uname = user["UserName"]
        keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
        for key in keys:
            age_days = (now - key["CreateDate"]).days
            if key["Status"] == "Active" and age_days > 90:
                findings.append(f"Access key antiga ({age_days}d): {uname} / {key['AccessKeyId']}")

    # Security Groups abertos para internet
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    for sg in sgs:
        sg_name = sg.get("GroupName", sg.get("GroupId"))
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            for ipr in perm.get("IpRanges", []):
                if ipr.get("CidrIp") == "0.0.0.0/0":
                    findings.append(f"SG aberto para internet: {sg_name} porta {from_port}-{to_port}")

    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="Auditor cloud")
    ap.add_argument("--provider", choices=["aws", "azure", "gcp"], default="aws")
    args = ap.parse_args()

    if args.provider != "aws":
        print("[INFO] MVP atual implementa verificacoes automaticas para AWS")
        print("[TODO] Adicionar Azure e GCP")
        return

    findings = audit_aws()
    if not findings:
        print("[OK] Nenhuma nao-conformidade detectada nas regras MVP")
        return

    print("[ALERT] Achados cloud:")
    for f in findings:
        print(f"- {f}")


if __name__ == "__main__":
    main()
