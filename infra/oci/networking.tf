# --- Look up existing VCN gateways ---

data "oci_core_internet_gateways" "this" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
}

data "oci_core_nat_gateways" "this" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
}

data "oci_core_services" "all" {
}

locals {
  internet_gateway_id = data.oci_core_internet_gateways.this.gateways[0].id
  nat_gateway_id      = data.oci_core_nat_gateways.this.nat_gateways[0].id
}

# --- Route Tables ---

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.cluster_name}-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = local.internet_gateway_id
  }
}

resource "oci_core_route_table" "private" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.cluster_name}-private-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = local.nat_gateway_id
  }
}

# --- Security Lists ---

resource "oci_core_security_list" "oke_api" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.cluster_name}-oke-api-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }

  ingress_security_rules {
    source    = "0.0.0.0/0"
    protocol  = "6" # TCP
    stateless = false

    tcp_options {
      min = 6443
      max = 6443
    }
  }
}

resource "oci_core_security_list" "oke_nodes" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.cluster_name}-oke-nodes-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }

  # Allow all traffic within the VCN
  ingress_security_rules {
    source    = "10.0.0.0/16"
    protocol  = "all"
    stateless = false
  }
}

resource "oci_core_security_list" "oke_lb" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.cluster_name}-oke-lb-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }

  ingress_security_rules {
    source    = "0.0.0.0/0"
    protocol  = "6" # TCP
    stateless = false

    tcp_options {
      min = 8080
      max = 8080
    }
  }
}

resource "oci_core_security_list" "api_gateway" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.cluster_name}-apigw-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }

  ingress_security_rules {
    source    = "0.0.0.0/0"
    protocol  = "6" # TCP
    stateless = false

    tcp_options {
      min = 443
      max = 443
    }
  }
}

# --- Subnets ---

resource "oci_core_subnet" "oke_api" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = var.vcn_id
  display_name               = "${var.cluster_name}-oke-api"
  cidr_block                 = var.subnet_cidr_oke_api
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.oke_api.id]
}

resource "oci_core_subnet" "oke_nodes" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = var.vcn_id
  display_name               = "${var.cluster_name}-oke-nodes"
  cidr_block                 = var.subnet_cidr_oke_nodes
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.private.id
  security_list_ids          = [oci_core_security_list.oke_nodes.id]
}

resource "oci_core_subnet" "oke_lb" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = var.vcn_id
  display_name               = "${var.cluster_name}-oke-lb"
  cidr_block                 = var.subnet_cidr_oke_lb
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.oke_lb.id]
}

resource "oci_core_subnet" "api_gateway" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = var.vcn_id
  display_name               = "${var.cluster_name}-apigw"
  cidr_block                 = var.subnet_cidr_api_gateway
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.api_gateway.id]
}
