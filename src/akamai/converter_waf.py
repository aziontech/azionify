import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource

VALID_SENSITIVITY_LEVELS = {"low", "medium", "high", "highest"}

def create_waf_rule(azion_resources: AzionResource, attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Creates a WAF rule set resource for Azion from Akamai behaviors.

    Parameters:
        attributes (dict): Attributes from Akamai configuration.

    Returns:
        dict: Azion-compatible WAF rule resource, or None if no WAF behavior is found.
    """
    try:
        logging.info("Creating Azion WAF rule resource.")

        # Extract WAF behavior from Akamai attributes
        waf_behavior = next(
            (b for b in attributes.get("behaviors", []) if b.get("name") == "webApplicationFirewall"),
            None
        )
        if not waf_behavior:
            logging.warning("No WAF behavior found in Akamai configuration.")
            return None

        # Extract options and apply defaults
        options = waf_behavior.get("options", {})
        name = options.get("name", "Default WAF")
        mode = options.get("mode", "counting")
        active = options.get("active", True)

        # Validate sensitivity levels and apply defaults
        sensitivity_fields = [
            "sql_injection_sensitivity", "remote_file_inclusion_sensitivity",
            "directory_traversal_sensitivity", "cross_site_scripting_sensitivity",
            "evading_tricks_sensitivity", "file_upload_sensitivity",
            "unwanted_access_sensitivity", "identified_attack_sensitivity"
        ]
        for field in sensitivity_fields:
            if options.get(field, "medium") not in VALID_SENSITIVITY_LEVELS:
                logging.warning(f"Invalid {field} '{options.get(field)}', defaulting to 'medium'.")
                options[field] = "medium"

        # Build the WAF resource
        waf_resource = {
            "type": "azion_waf_rule_set",
            "name": name,
            "attributes": {
                "result": {
                    "name": name,
                    "mode": mode,
                    "active": active,
                    "sql_injection": options.get("sql_injection", False),
                    "sql_injection_sensitivity": options["sql_injection_sensitivity"],
                    "remote_file_inclusion": options.get("remote_file_inclusion", False),
                    "remote_file_inclusion_sensitivity": options["remote_file_inclusion_sensitivity"],
                    "directory_traversal": options.get("directory_traversal", False),
                    "directory_traversal_sensitivity": options["directory_traversal_sensitivity"],
                    "cross_site_scripting": options.get("cross_site_scripting", False),
                    "cross_site_scripting_sensitivity": options["cross_site_scripting_sensitivity"],
                    "evading_tricks": options.get("evading_tricks", False),
                    "evading_tricks_sensitivity": options["evading_tricks_sensitivity"],
                    "file_upload": options.get("file_upload", False),
                    "file_upload_sensitivity": options["file_upload_sensitivity"],
                    "unwanted_access": options.get("unwanted_access", False),
                    "unwanted_access_sensitivity": options["unwanted_access_sensitivity"],
                    "identified_attack": options.get("identified_attack", False),
                    "identified_attack_sensitivity": options["identified_attack_sensitivity"],
                    "bypass_addresses": options.get("bypass_addresses", []),
                }
            },
        }

        logging.info(f"WAF rule resource created: {name}")
        return waf_resource

    except Exception as e:
        logging.error(f"Error creating WAF rule resource: {e}")
        raise