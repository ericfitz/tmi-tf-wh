resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_ocid
  display_name   = "tmi-tf-wh-vault"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "master" {
  compartment_id      = var.compartment_ocid
  display_name        = "tmi-tf-wh-master-key"
  management_endpoint = oci_kms_vault.main.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32 # 256 bits
  }
}

resource "oci_vault_secret" "webhook_secret" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.main.id
  key_id         = oci_kms_key.master.id
  secret_name    = "webhook-secret"
  description    = "GitHub webhook HMAC secret"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("placeholder-webhook-secret")
    name         = "initial"
    stage        = "CURRENT"
  }
}

resource "oci_vault_secret" "tmi_client_id" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.main.id
  key_id         = oci_kms_key.master.id
  secret_name    = "tmi-client-id"
  description    = "TMI OAuth client ID"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("placeholder-tmi-client-id")
    name         = "initial"
    stage        = "CURRENT"
  }
}

resource "oci_vault_secret" "tmi_client_secret" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.main.id
  key_id         = oci_kms_key.master.id
  secret_name    = "tmi-client-secret"
  description    = "TMI OAuth client secret"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("placeholder-tmi-client-secret")
    name         = "initial"
    stage        = "CURRENT"
  }
}

resource "oci_vault_secret" "llm_api_key" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.main.id
  key_id         = oci_kms_key.master.id
  secret_name    = "llm-api-key"
  description    = "LLM provider API key"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("placeholder-llm-api-key")
    name         = "initial"
    stage        = "CURRENT"
  }
}

resource "oci_vault_secret" "github_token" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.main.id
  key_id         = oci_kms_key.master.id
  secret_name    = "github-token"
  description    = "GitHub personal access token"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("placeholder-github-token")
    name         = "initial"
    stage        = "CURRENT"
  }
}
