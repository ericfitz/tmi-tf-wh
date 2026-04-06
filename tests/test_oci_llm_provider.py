# tests/test_oci_llm_provider.py
"""Tests for OciLLMProvider."""

import os
from unittest.mock import MagicMock, patch

import pytest

from tmi_tf.providers.oci import OciLLMProvider


class TestOciLLMProvider:
    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_reads_compartment_from_env(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "aa:bb:cc",
            "tenancy": "ocid1.tenancy.oc1..test",
            "key_file": "/path/to/key.pem",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                provider = OciLLMProvider(model=None)
                assert (
                    provider._extra_kwargs["oci_compartment_id"]
                    == "ocid1.compartment.oc1..test"
                )
                assert provider._extra_kwargs["oci_region"] == "us-ashburn-1"

    @patch.dict(os.environ, {}, clear=False)
    def test_raises_when_no_compartment_id(self):
        os.environ.pop("OCI_COMPARTMENT_ID", None)
        with pytest.raises(ValueError, match="OCI_COMPARTMENT_ID"):
            OciLLMProvider(model=None)

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_uses_instance_principal_when_no_config_file(self):
        mock_signer = MagicMock()
        mock_signer.region = "us-phoenix-1"
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "oci.auth.signers.get_resource_principals_signer",
                return_value=mock_signer,
            ):
                provider = OciLLMProvider(model=None)
                assert provider._extra_kwargs["oci_signer"] is mock_signer
                assert provider._extra_kwargs["oci_region"] == "us-phoenix-1"

    @patch.dict(
        os.environ,
        {
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
            "OCI_CONFIG_PROFILE": "CUSTOM",
        },
        clear=False,
    )
    def test_uses_custom_config_profile(self):
        mock_oci_config = {
            "region": "eu-frankfurt-1",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "dd:ee:ff",
            "tenancy": "ocid1.tenancy.oc1..test",
            "key_file": "/path/to/key.pem",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch(
                "oci.config.from_file", return_value=mock_oci_config
            ) as mock_from_file:
                OciLLMProvider(model=None)
                call_args = mock_from_file.call_args
                assert call_args[0][1] == "CUSTOM"

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_default_model(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "u",
            "fingerprint": "f",
            "tenancy": "t",
            "key_file": "k",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                provider = OciLLMProvider(model=None)
                assert provider.model.startswith("oci/")

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_custom_model_gets_prefix(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "u",
            "fingerprint": "f",
            "tenancy": "t",
            "key_file": "k",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                provider = OciLLMProvider(model="xai.grok-4")
                assert provider.model == "oci/xai.grok-4"
