resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_block     = "10.3.0.0/16"
  display_name   = "tmi-vcn"
  dns_label      = "tmi"
}

resource "oci_core_subnet" "private" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.3.1.0/24"
  prohibit_public_ip_on_vnic = true
  display_name               = "private"
}

resource "oci_core_security_list" "private" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "private"
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }
}

resource "oci_core_network_security_group" "app" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app"
}

resource "oci_objectstorage_bucket" "data" {
  compartment_id = var.compartment_id
  namespace      = "ns"
  name           = "tmi-data"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  freeform_tags  = { env = "test" }
}

resource "oci_core_instance" "web" {
  compartment_id      = var.compartment_id
  availability_domain = "AD-1"
  shape               = "VM.Standard.E4.Flex"
  display_name        = "web"
  create_vnic_details {
    subnet_id        = oci_core_subnet.private.id
    assign_public_ip = false
    nsg_ids          = [oci_core_network_security_group.app.id]
  }
  source_details {
    source_type = "image"
    source_id   = "ocid1.image.oc1..example"
  }
  metadata = {
    ssh_authorized_keys = "ssh-ed25519 AAAA"
    user_data           = base64encode("#!/bin/bash\necho hi")
  }
}

variable "compartment_id" {
  type = string
}
