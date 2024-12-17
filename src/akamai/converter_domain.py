from typing import Dict, Any
import logging

from azion_resources import AzionResource

def create_domain(azion_resources: AzionResource, attributes: Dict[str, Any], main_setting_name: str) -> Dict[str, Any]:
    """
    Creates the Azion domain resource from Akamai attributes.

    Parameters:
        attributes (dict): Attributes from Akamai configuration.
        main_setting_name (str): The main setting name for Azion edge application.

    Returns:
        dict: Azion-compatible domain resource.
    """
    try:
        logging.info("Creating Azion domain resource.")

        # Extract and validate 'hostnames'
        hostnames = attributes.get("hostnames", [])
        if not isinstance(hostnames, list):
            logging.warning(f"Invalid 'hostnames' format: {hostnames}. Defaulting to an empty list.")
            hostnames = []

        # Extract cname_from values
        cnames = [f'"{hostname["cname_from"]}"' for hostname in hostnames if "cname_from" in hostname]
        if not cnames:
            logging.warning("No valid CNAMEs found in hostnames. Defaulting to an empty list.")
            cnames = []

        # Extract domain name or apply default
        domain_name = attributes.get("name", "default-domain")
        if not isinstance(domain_name, str) or not domain_name.strip():
            logging.warning(f"Invalid 'name' format: {domain_name}. Defaulting to 'default-domain'.")
            domain_name = "default-domain"

        # Set digital_certificate_id based on cert_provisioning_type
        digital_certificate_id = None  # Default to Azion SAN certificate
        for hostname in hostnames:
            cert_provisioning_type = hostname.get("cert_provisioning_type")
            if cert_provisioning_type == "CPS_MANAGED":
                digital_certificate_id = '"lets_encrypt"'  # Add quotes for Terraform compatibility
                break
            elif cert_provisioning_type == "EXISTING_CERTIFICATE":
                digital_certificate_id = hostname.get("certificate_id", None)  # Assume user provides an integer ID
                if not isinstance(digital_certificate_id, int):
                    logging.warning("Invalid or missing certificate ID for EXISTING_CERTIFICATE. Defaulting to null.")
                    digital_certificate_id = None
                break

        # Construct domain resource
        domain_resource = {
            "type": "azion_domain",
            "name": domain_name,
            "attributes": {
                "domain": {
                    "cnames": f"[{', '.join(cnames)}]",
                    "name": domain_name,
                    "digital_certificate_id": digital_certificate_id,
                    "cname_access_only": False,
                    "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                    "is_active": True,
                },
                "depends_on": [f"azion_edge_application_main_setting.{main_setting_name}"],
            },
        }

        logging.info(f"Domain resource created for '{domain_name}' with CNAMEs: {cnames}.")
        return domain_resource

    except Exception as e:
        logging.error(f"Error creating domain resource: {e}")
        raise