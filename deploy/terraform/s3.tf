# ==============================================================================
# S3 Storage Architecture for SOC Telemetry & Audit Archives
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Compliant Hardened S3 Bucket (SSE-KMS, Versioning, Public Access Block)
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "soc_audit_vault" {
  bucket = "cybermind-soc-audit-vault-compliant"

  tags = {
    DataClassification = "Confidential-Audit"
    Retention          = "7-Years"
  }
}

resource "aws_s3_bucket_versioning" "soc_audit_vault_versioning" {
  bucket = aws_s3_bucket.soc_audit_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "soc_audit_vault_encryption" {
  bucket = aws_s3_bucket.soc_audit_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "soc_audit_vault_pab" {
  bucket = aws_s3_bucket.soc_audit_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------------------------
# 2. VULNERABLE S3 BUCKET (Deliberate IaC Misconfiguration for CSPM Demo)
# Triggers: Checkov CKV_AWS_19 (Ensure all data stored in the S3 bucket is securely encrypted at rest)
# Triggers: Checkov CKV_AWS_21 (Ensure all data stored in the S3 bucket has versioning enabled)
# Triggers: Checkov CKV_AWS_53, 54, 55, 56 (Ensure S3 bucket has public access blocks enabled)
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "soc_raw_telemetry_unencrypted" {
  bucket = "cybermind-raw-telemetry-unencrypted-demo"

  # CRITICAL FLAW 1: Missing aws_s3_bucket_server_side_encryption_configuration (Plaintext at rest)
  # CRITICAL FLAW 2: Missing aws_s3_bucket_public_access_block (Risk of public data leak)
  # CRITICAL FLAW 3: Missing aws_s3_bucket_versioning (No protection against accidental deletion or ransomware)

  tags = {
    Name            = "soc-raw-telemetry-unencrypted"
    SecurityAudit   = "CSPM-Test-Vulnerable-Target"
    IntentionalRisk = "True"
  }
}
