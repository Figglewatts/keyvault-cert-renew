import asyncio
from datetime import datetime
import logging
import logging.config
from os import path
import tempfile
from typing import List, Optional

import aiorun
from azure.core.exceptions import ResourceNotFoundError
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.certificates import KeyVaultCertificate
from azure.keyvault.certificates.aio import CertificateClient
import certbot
import pem

import config

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PEMFile = List[pem.AbstractPEMObject]


def configure_logging(log_config: Optional[dict] = None) -> None:
    """Configure application logging.
    
    Args:
        log_config: The logging config of the application.
    """
    if log_config:
        logging.config.dictConfig(log_config)
    else:
        logging.basicConfig(
            datefmt="%Y-%m-%d %H:%M:%S",
            format=
            "%(asctime)s.%(msecs)03dZ <%(name)s> [%(levelname)s]: %(message)s",
            level=logging.INFO)


def pem_to_str(pem: PEMFile) -> str:
    """Convert a PEMFile to a str."""
    return "".join(pem)


def valid_pem(pem: PEMFile) -> bool:
    """Returns whether a PEMFile contains valid data or not."""
    return len(pem) > 0


def add_private_key_to_cert(cert_pem: PEMFile, key_dir: str) -> PEMFile:
    """Given a PEM containing a certbot-generated certificate (fullchain.pem),
    add the private key to the file (privkey.pem).

    Args:
        cert_pem: The certificate PEM, loaded from fullchain.pem.
        key_dir: The directory where we will find privkey.pem.

    Returns:
        PEMFile: The new PEM file with the cert and key inside.

    Raises:
        RuntimeError: If we were unable to parse privkey.pem.
    """
    private_key_path = path.join(key_dir, "privkey.pem")
    private_key_pem = pem.parse_file(private_key_path)
    if not valid_pem(private_key_pem):
        raise RuntimeError("Unable to parse privkey.pem")

    return cert_pem + private_key_pem


def create_certificate(cert: config.CertificateConfig) -> PEMFile:
    """Given a certificate config, create a certificate from it using certbot.

    Args:
        cert: The certificate config to use.

    Returns:
        PEMFile: The created certificate with its private key.

    Raises:
        RuntimeError: If something went wrong while creating the certificate.
    """
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_args = [f"-d {domain}" for domain in cert.domains]
            if cert.staging:
                cert_args += "--staging"

            try:
                certbot.main.main([
                    "certonly", "--authenticator dns-azure",
                    "--preferred-challenges dns", "--noninteractive",
                    "--agree-tos", f"--config-dir {temp_dir}",
                    f"--work-dir {temp_dir}", f"--logs-dir {temp_dir}"
                ] + cert_args)
            except Exception as err:
                raise RuntimeError("Error running certbot") from err

            cert_path = path.join(temp_dir, "fullchain.pem")
            cert_pem = pem.parse_file(cert_path)
            if not valid_pem(cert_pem):
                raise RuntimeError("Unable to parse fullchain.pem")

            cert_pem = add_private_key_to_cert(cert_pem, temp_dir)
            return cert_pem
    except OSError as err:
        raise RuntimeError("Unable to create certificate") from err


def make_certificate_client(vault_url: str) -> None:
    """Given a vault URL, make a client for key vault certificate operations"""
    logger.info(f"Making CertificateClient for vault '{vault_url}'")
    cred = DefaultAzureCredential()
    return CertificateClient(vault_url=vault_url, credential=cred)


async def certificate_exists(
        cert: config.CertificateConfig,
        client: CertificateClient) -> Optional[KeyVaultCertificate]:
    """Check if a certificate already exists.

    Args:
        cert: The certificate we're checking.
        client: The CertificateClient to use.

    Returns:
        KeyVaultCertificate: If the certificate existed.
        None: If it did not exist.
    """
    try:
        return await client.get_certificate(cert.name)
    except ResourceNotFoundError:
        return None


def certificate_in_renewal_period(cert_config: config.CertificateConfig,
                                  cert: KeyVaultCertificate) -> bool:
    """Checks whether the current certificate is within the configured
    renewal period.

    Args:
        cert_config: The CertificateConfig from the app config file.
        cert: The existing certificate from the key vault.

    Returns:
        bool: True if we're within the renewal period, False otherwise.
    """
    expires_on_timestamp = cert.properties.expires_on.timestamp()
    current_timestamp = datetime.now().timestamp()
    renew_before_timestamp = expires_on_timestamp - cert_config.renew_before
    return current_timestamp >= renew_before_timestamp


def import_certificate(cert_config: config.CertificateConfig,
                       cert_pem: PEMFile, client: CertificateClient) -> None:
    cert_bytes = pem_to_str(cert_pem).encode("utf-8")
    await client.import_certificate(certificate_name=cert_config.name, certificate_bytes=cert_bytes)


async def main() -> None:
    configure_logging()  # default config, before customisations are loaded

    logger.info("Initialising application...")
    try:
        loaded_config = config.load("example_config.yml")
    except RuntimeError:
        logger.exception("Unable to load config")
        raise SystemExit(1)
    logger.info("Loaded config")

    # load in customisations for logging config
    configure_logging(loaded_config.logging)

    for kv in loaded_config.key_vaults:
        kv_client = make_certificate_client(kv.vault_url)
        for cert in kv.certificates:
            existing_cert = await certificate_exists(cert, kv_client)

            # create/import a new certificate if any of 2 conditions are met:
            # 1. the cert already existed and we're within the renewal period
            # 2. it didn't exist yet (and hence is new)
            if existing_cert and certificate_in_renewal_period(
                    cert, existing_cert) or not existing_cert:
                created_pem = create_certificate(cert)
                import_certificate(cert, created_pem, kv_client)


if __name__ == "__main__":
    aiorun.run(main(), stop_on_unhandled_errors=True)