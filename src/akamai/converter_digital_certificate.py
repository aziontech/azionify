from typing import Dict, List, Any, Optional
import logging

from azion_resources import AzionResource


def create_digital_certificate(
        azion_resources: AzionResource,
        custom_certificates: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
    """
    Creates a Digital Certificate resource in Azion based on Akamai customCertificates.

    Parameters:
        azion_resources (AzionResource): The Azion resource container.
        custom_certificates (List[Dict[str, Any]]): List of Akamai custom certificates.

    Returns:
        Optional[Dict[str, Any]]: The reference ID of the created Azion Digital Certificate resource.
    """
    if not custom_certificates:
        logging.warning("No custom certificates provided. Skipping certificate creation.")
        return None

    try:
        for cert in custom_certificates:
            pem_cert = cert.get("pemEncodedCert")
            if not pem_cert:
                logging.warning("Certificate is missing PEM-encoded data. Skipping.")
                continue

            cert_name = cert.get("subjectCN", "default_certificate")
            return {
                "type": "azion_digital_certificate",
                "name": cert_name,
                "attributes": {
                    "certificate_result": {
                        "name": cert_name,
                        "certificate_content": pem_cert,
                        "private_key": "",  # Replace with actual private key if available
                    }
                }
            }

    except ValueError as e:
        logging.error(f"Error creating digital certificate: {str(e)}")
        return None
