resource "aws_secretsmanager_secret" "payment_api" {
  name       = "prod/payment-api"
  kms_key_id = aws_kms_key.primary.arn

  replica {
    region = var.failover_region
  }
}

resource "aws_iam_policy" "dr_secret_reader" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "kms:Decrypt"]
      Resource = "*"
    }]
  })
}
