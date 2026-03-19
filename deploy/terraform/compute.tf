# Data source for the latest Oracle Linux 9 ARM image
data "oci_core_images" "ol9_arm" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Oracle Linux"
  operating_system_version = "9"
  shape                    = var.shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"

  filter {
    name   = "display_name"
    values = ["Oracle-Linux-9.*-aarch64-.*"]
    regex  = true
  }
}

locals {
  ol9_arm_image_id = data.oci_core_images.ol9_arm.images[0].id

  cloud_init_script = <<-EOT
    #!/usr/bin/env bash
    set -euo pipefail

    # Install system packages
    dnf install -y python3 python3-pip git oracle-cloud-agent

    # Enable and start the OCI cloud agent
    systemctl enable --now oracle-cloud-agent

    # Create the tmi-tf system user
    useradd --system --shell /sbin/nologin --home-dir /opt/tmi-tf-wh --create-home tmi-tf

    # Deploy the application
    cd /opt/tmi-tf-wh
    git clone https://github.com/your-org/tmi-tf-wh.git .
    pip3 install --no-cache-dir -r requirements.txt

    # Install and enable the systemd service
    cp deploy/tmi-tf-wh.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now tmi-tf-wh
  EOT
}

resource "oci_core_instance" "app" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = "tmi-tf-wh"
  shape               = var.shape

  shape_config {
    ocpus         = var.shape_ocpus
    memory_in_gbs = var.shape_memory_in_gbs
  }

  source_details {
    source_type = "image"
    source_id   = local.ol9_arm_image_id
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.private.id
    display_name     = "tmi-tf-wh-vnic"
    assign_public_ip = false
    hostname_label   = "tmi-tf-wh"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_authorized_keys
    user_data           = base64encode(local.cloud_init_script)
  }
}
