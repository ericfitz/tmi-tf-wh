"""Validity tests for tmi_tf/data/resource_registry.yaml (issue #10)."""

import re
from pathlib import Path

import yaml  # pyright: ignore[reportMissingModuleSource]

from tmi_tf.tf_filter import ALLOWED_CATEGORIES

REGISTRY_PATH = (
    Path(__file__).parent.parent / "tmi_tf" / "data" / "resource_registry.yaml"
)

ATTR_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")


def _registry() -> dict:
    return yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))


class TestRegistryStructure:
    def test_top_level_keys(self):
        reg = _registry()
        assert set(reg) == {"providers", "resources", "defaults"}
        assert reg["defaults"]["unknown_category"] == "other"
        assert reg["defaults"]["unknown_attrs"] == "all"
        assert "user_data" in reg["defaults"]["hash_only_attrs"]

    def test_provider_prefixes(self):
        for prefix, info in _registry()["providers"].items():
            assert prefix.endswith("_"), prefix
            assert info["name"] and info["type"], prefix

    def test_every_resource_is_well_formed(self):
        reg = _registry()
        prefixes = tuple(reg["providers"])
        for rtype, entry in reg["resources"].items():
            assert entry["category"] in ALLOWED_CATEGORIES, rtype
            attrs = entry["security_attrs"]
            assert isinstance(attrs, list), rtype
            assert len(attrs) == len(set(attrs)), f"{rtype}: duplicate attrs"
            for a in attrs:
                assert ATTR_PATH_RE.match(a), f"{rtype}: bad attr path {a!r}"
            assert rtype.startswith(prefixes), f"{rtype}: no provider prefix"

    def test_four_cloud_providers_are_covered(self):
        types = set(_registry()["resources"])
        expected = {
            "aws": [
                "aws_instance",
                "aws_s3_bucket",
                "aws_security_group",
                "aws_iam_role",
                "aws_vpc",
                "aws_db_instance",
                "aws_lambda_function",
                "aws_eks_cluster",
            ],
            "azurerm": [
                "azurerm_linux_virtual_machine",
                "azurerm_storage_account",
                "azurerm_network_security_group",
                "azurerm_key_vault",
                "azurerm_kubernetes_cluster",
                "azurerm_postgresql_flexible_server",
            ],
            "google": [
                "google_compute_instance",
                "google_storage_bucket",
                "google_compute_firewall",
                "google_container_cluster",
                "google_sql_database_instance",
                "google_service_account",
            ],
            "oci": [
                "oci_core_instance",
                "oci_objectstorage_bucket",
                "oci_core_security_list",
                "oci_core_network_security_group",
                "oci_containerengine_cluster",
                "oci_database_autonomous_database",
                "oci_vault_secret",
            ],
        }
        for provider, names in expected.items():
            missing = [n for n in names if n not in types]
            assert not missing, f"{provider}: missing {missing}"

    def test_tmi_repo_resource_types_are_covered(self):
        """Every type used by ~/Projects/tmi/terraform that is not a utility provider."""
        types = set(_registry()["resources"])
        used = [
            "aws_accessanalyzer_analyzer",
            "aws_acm_certificate",
            "aws_cloudtrail",
            "aws_cloudwatch_log_group",
            "aws_db_instance",
            "aws_ecr_repository",
            "aws_eip",
            "aws_eks_addon",
            "aws_eks_cluster",
            "aws_eks_node_group",
            "aws_flow_log",
            "aws_iam_openid_connect_provider",
            "aws_iam_policy",
            "aws_iam_role",
            "aws_iam_role_policy",
            "aws_iam_role_policy_attachment",
            "aws_internet_gateway",
            "aws_launch_template",
            "aws_nat_gateway",
            "aws_route53_record",
            "aws_route_table",
            "aws_s3_bucket",
            "aws_s3_bucket_policy",
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_server_side_encryption_configuration",
            "aws_secretsmanager_secret",
            "aws_security_group",
            "aws_sns_topic",
            "aws_subnet",
            "aws_vpc",
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_egress_rule",
            "azurerm_container_registry",
            "azurerm_key_vault",
            "azurerm_key_vault_secret",
            "azurerm_kubernetes_cluster",
            "azurerm_log_analytics_workspace",
            "azurerm_nat_gateway",
            "azurerm_network_security_group",
            "azurerm_postgresql_flexible_server",
            "azurerm_public_ip",
            "azurerm_role_assignment",
            "azurerm_subnet",
            "azurerm_virtual_network",
            "google_artifact_registry_repository",
            "google_compute_firewall",
            "google_compute_network",
            "google_compute_router_nat",
            "google_compute_subnetwork",
            "google_container_cluster",
            "google_secret_manager_secret",
            "google_service_account",
            "google_sql_database_instance",
            "google_storage_bucket",
            "oci_containerengine_cluster",
            "oci_containerengine_node_pool",
            "oci_core_internet_gateway",
            "oci_core_nat_gateway",
            "oci_core_network_security_group",
            "oci_core_route_table",
            "oci_core_security_list",
            "oci_core_subnet",
            "oci_core_vcn",
            "oci_database_autonomous_database",
            "oci_functions_function",
            "oci_identity_policy",
            "oci_kms_key",
            "oci_kms_vault",
            "oci_load_balancer_load_balancer",
            "oci_logging_log",
            "oci_objectstorage_bucket",
            "oci_vault_secret",
            "kubernetes_deployment_v1",
            "kubernetes_service_v1",
            "kubernetes_ingress_v1",
            "kubernetes_secret_v1",
            "helm_release",
        ]
        missing = [t for t in used if t not in types]
        assert not missing, missing

    def test_kubernetes_manifest_preserves_api_version_casing(self):
        """HCL/Kubernetes attribute keys are case-sensitive; apiVersion must
        not get lowercased to apiversion or Task 3's filter will never match
        it and will strip apiVersion from every kubernetes_manifest block."""
        attrs = _registry()["resources"]["kubernetes_manifest"]["security_attrs"]
        assert "manifest.apiVersion" in attrs
