terraform {
  required_version = ">= 1.6.0"
  required_providers { random = { source = "hashicorp/random", version = "~> 3.6" } }
}

variable "environment" { type = string, default = "staging" }
variable "region" { type = string, default = "eu-central-1" }

resource "random_password" "database" { length = 32, special = true }

output "environment" { value = var.environment }
output "region" { value = var.region }

# Provider-specific managed PostgreSQL, object storage, KMS, network, and
# secret-manager resources are intentionally supplied by the deployment owner.
# This skeleton must not embed credentials or imply a cloud-vendor choice.
