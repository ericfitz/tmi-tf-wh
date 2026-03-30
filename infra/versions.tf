terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 6.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
  }
}

provider "oci" {
  region = var.region
}

provider "kubernetes" {
  host                   = oci_containerengine_cluster.this.endpoints[0].kubernetes
  cluster_ca_certificate = base64decode(oci_containerengine_cluster.this.endpoints[0].public_endpoint != "" ? data.oci_containerengine_cluster_kube_config.this.content : "")
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "oci"
    args = [
      "ce", "cluster", "generate-token",
      "--cluster-id", oci_containerengine_cluster.this.id,
      "--region", var.region,
    ]
  }
}

data "oci_containerengine_cluster_kube_config" "this" {
  cluster_id = oci_containerengine_cluster.this.id
}

data "oci_identity_tenancy" "this" {
  tenancy_id = var.tenancy_ocid
}
