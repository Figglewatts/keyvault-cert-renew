"""config

Contains schemas, data structures, and functions related to loading and
validation of application config.

Author:
    Figglewatts <me@figglewatts.co.uk>
"""
from dataclasses import dataclass
import logging
from typing import List, Optional

from marshmallow import Schema, fields, post_load, validate, \
    ValidationError, EXCLUDE
import pytimeparse
import yaml


class CertificateConfigSchema(Schema):
    """Marshmallow schema for validating certificate config."""
    name = fields.Str(required=True,
                      allow_none=False,
                      validate=validate.Length(min=1))
    domains = fields.List(fields.Str,
                          required=True,
                          allow_none=False,
                          validate=validate.Length(min=1))
    renew_before = fields.Str(required=True, allow_none=False)
    staging = fields.Bool(required=False,
                          missing=False,
                          default=False,
                          allow_none=False)

    @post_load
    def make_certificate_config(self, data, **kwargs):
        # parse the timespan to a number of seconds, raise error if
        # it could not be parsed
        data["renew_before"] = pytimeparse.parse(data["renew_before"])
        if data["renew_before"] is None:
            raise ValidationError("Unable to parse timespan", "renew_before")
        return CertificateConfig(**data)


@dataclass
class CertificateConfig:
    """Configuration for a certificate in a key vault we manage.

    Attributes:
        name: The name of this certificate.
        domains: The list of domains this certificate is for.
        renew_before: The seconds before the expiry to renew the certificate.
        staging: Whether to use the staging Let's Encrypt server or not.
    """
    name: str
    domains: List[str]
    renew_before: int
    staging: bool = False


class KeyVaultConfigSchema(Schema):
    """Marshmallow schema for validating key vault config."""
    certificates = fields.List(fields.Nested(CertificateConfigSchema),
                               required=True,
                               allow_none=False,
                               validate=validate.Length(min=1))
    vault_url = fields.Url(schemes=["http", "https"],
                           required=True,
                           allow_none=False)

    @post_load
    def make_key_vault_config(self, data, **kwargs):
        return KeyVaultConfig(**data)


@dataclass
class KeyVaultConfig:
    """Configuration for a key vault we manage, containing a list
    of managed certificates.

    Attributes:
        certificates: The config of certificates in this vault we manage.
        vault_url: The URL of the key vault we're managing.
    """
    certificates: List[CertificateConfig]
    vault_url: str


class AppConfigSchema(Schema):
    """Marshmallow schema for validating application config."""
    key_vaults = fields.List(fields.Nested(KeyVaultConfigSchema),
                             required=True,
                             allow_none=False,
                             validate=validate.Length(min=1))
    logging = fields.Dict(required=False, missing=None, default=None)

    @post_load
    def make_app_config(self, data, **kwargs):
        return AppConfig(**data)


@dataclass
class AppConfig:
    """The configuration for the application.

    Attributes:
        key_vaults: The key vaults we're managing.
        logging: The logging config.
    """
    key_vaults: List[KeyVaultConfig]
    logging: Optional[dict] = None


def load(file_path: str) -> AppConfig:
    """Load application config at a given path.

    Args:
        file_path: The path to the config to load.

    Returns:
        AppConfig: The application configuration.

    Raises:
        RuntimeError: If config could not be loaded.
    """
    APP_CONFIG_SCHEMA = AppConfigSchema(unknown=EXCLUDE)
    try:
        with open(file_path, 'r') as config_file:
            raw_config = yaml.safe_load(config_file)
            return APP_CONFIG_SCHEMA.load(raw_config)
    except (OSError, yaml.YAMLError, ValidationError) as err:
        raise RuntimeError("Unable to load config") from err