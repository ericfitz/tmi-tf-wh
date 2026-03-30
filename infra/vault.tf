resource "oci_kms_vault" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-vault"
  vault_type     = "DEFAULT"

  freeform_tags = {
    "app" = "tmi-tf-wh"
  }
}

resource "oci_kms_key" "master" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-master-key"

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  management_endpoint = oci_kms_vault.this.management_endpoint

  protection_mode = "SOFTWARE"
}

# Secret shells — deployer populates values after apply via OCI CLI or Console
resource "oci_vault_secret" "webhook_secret" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "webhook-secret"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "tmi_client_id" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "tmi-client-id"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "tmi_client_secret" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "tmi-client-secret"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "llm_api_key" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "llm-api-key"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "github_token" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "github-token"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}
