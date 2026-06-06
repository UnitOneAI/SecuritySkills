terraform {
  source = "../modules/storage"
}

inputs = {
  enable_public_bucket   = true
  logging_enabled        = false
  deletion_protection    = false
  backup_retention_days  = 0
}
