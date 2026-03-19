resource "oci_logging_log_group" "main" {
  compartment_id = var.compartment_ocid
  display_name   = "tmi-tf-wh-log-group"
  description    = "Log group for the TMI Terraform Webhook Analyzer"
}

resource "oci_logging_log" "app" {
  display_name = "tmi-tf-wh-app-log"
  log_group_id = oci_logging_log_group.main.id
  log_type     = "CUSTOM"
  is_enabled   = true

  retention_duration = 30
}

resource "oci_logging_unified_agent_configuration" "app" {
  compartment_id = var.compartment_ocid
  display_name   = "tmi-tf-wh-agent-config"
  description    = "Unified monitoring agent configuration for the tmi-tf-wh compute instance"
  is_enabled     = true

  service_configuration {
    configuration_type = "LOGGING"

    sources {
      source_type = "LOG_TAIL"
      name        = "tmi-tf-wh-systemd"
      paths       = ["/var/log/tmi-tf-wh.log"]
    }

    destination {
      log_object_id = oci_logging_log.app.id
    }
  }

  group_association {
    group_list = [oci_identity_dynamic_group.app_instance.id]
  }
}
