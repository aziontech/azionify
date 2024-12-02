import logging
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)

# Mapping for Akamai to Azion behavior/criteria conversions
MAPPING = {
    "caching": {
        "CACHE": {"azion_behavior": "caching", "ttl": "ttl"},
        "NO_CACHE": {"azion_behavior": "caching", "enabled": False},
    },
    "origin": {
        "CUSTOMER": {"azion_origin_type": "custom"},
    },
    "criteria": {
        "fileExtension": {"azion_condition": "url_extension"},
        "path": {"azion_condition": "url_path"},
    },
}


def validate_and_apply_defaults(attributes: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and applies default values to the given attributes based on provided defaults.

    Parameters:
        attributes (dict): The input attributes to validate.
        defaults (dict): Default values for the attributes.

    Returns:
        dict: A dictionary containing the validated and normalized attributes.
    """
    validated = {}
    
    for key, default_value in defaults.items():
        # Extract the current value from attributes or use the default
        value = attributes.get(key, default_value)

        # Perform specific validations based on the key
        if key == "delivery_protocol" and value not in {"http", "https", "http,https"}:
            logging.warning(f"Invalid delivery_protocol '{value}', defaulting to '{default_value}'.")
            value = default_value

        elif key == "minimum_tls_version" and value not in {"", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"}:
            logging.warning(f"Invalid minimum_tls_version '{value}', defaulting to '{default_value}'.")
            value = default_value

        elif key == "supported_ciphers" and value not in {"all", "TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.3_2022"}:
            logging.warning(f"Invalid supported_ciphers '{value}', defaulting to '{default_value}'.")
            value = default_value

        elif key == "http_port" or key == "https_port":
            if not isinstance(value, list) or not all(isinstance(port, int) for port in value):
                logging.warning(f"Invalid {key} '{value}', defaulting to '{default_value}'.")
                value = default_value

        elif isinstance(default_value, bool) and not isinstance(value, bool):
            logging.warning(f"Invalid boolean value for {key} '{value}', defaulting to '{default_value}'.")
            value = default_value

        # Apply the validated or default value to the result
        validated[key] = value

    return validated


def process_resource(resource: Dict[str, Any], main_setting_name: str, edge_hostname: str) -> List[Dict[str, Any]]:
    """
    Processes a single Akamai resource and converts it to Azion.

    Parameters:
        resource (dict): The Akamai resource to process.
        main_setting_name (str): Name of the main setting resource.
        edge_hostname (str): Extracted edge hostname.

    Returns:
        List[Dict[str, Any]]: A list of Azion resources.
    """
    logging.info("Starting conversion of Akamai resources to Azion.")
    azion_resources = []

    # Process Akamai properties
    for resource_name, resource_data in resource.items():
        if resource_name == "akamai_property":
            logging.info(f"Found Akamai property: {resource_name}. Processing...")
            for instance_name, instance_data in resource_data.items():
                logging.info(f"Processing Akamai instance: {instance_name}")
                try:
                    converted_resources = convert_akamai_to_azion(instance_data, main_setting_name, edge_hostname)
                    azion_resources.extend(converted_resources)
                except KeyError as e:
                    logging.error(f"Missing expected key during processing of {instance_name}: {e}")
                except TypeError as e:
                    logging.error(f"Type error during processing of {instance_name}: {e}")
                except ValueError as e:
                    logging.error(f"Value error during processing of {instance_name}: {e}")
                except Exception as e:
                    logging.error(f"Unexpected error processing {instance_name}: {e}")
                    raise

    # Regenerate resources with updated information, if needed
    for resource in azion_resources:
        if resource["type"] == "azion_edge_application_origin":
            origin = resource["attributes"]["origin"]
            if origin["addresses"][0]["address"] == "placeholder.example.com":
                origin["addresses"][0]["address"] = edge_hostname
                logging.info("Updated origin address with extracted edge_hostname.")

    logging.info(f"Finished processing resources. Total Azion resources generated: {len(azion_resources)}")
    return azion_resources



def convert_akamai_to_azion(attributes: Dict[str, Any], main_setting_name: str, edge_hostname: str) -> List[Dict[str, Any]]:
    """
    Converts Akamai property to Azion resources.

    Parameters:
        attributes (dict): Akamai property attributes.
        main_setting_name (str): Main setting name for Azion.
        edge_hostname (str): The edge hostname extracted from Akamai configuration.

    Returns:
        List[Dict[str, Any]]: A list of Azion-compatible resources.
    """
    logging.info(f"Converting Akamai property: {attributes.get('name', 'Unknown')} to Azion format.")

    azion_resources = []

    try:
        # Create Main Setting, Origin, and Domain resources
        azion_resources.append(create_main_setting(attributes))
        azion_resources.append(create_origin(attributes, main_setting_name, edge_hostname))
        azion_resources.append(create_domain(attributes, main_setting_name))
        logging.info("Main setting, origin, and domain resources created.")
    except Exception as e:
        logging.error(f"Error creating main resources: {e}")
        raise

    # Process rules if they exist
    rules = attributes.get("rules", {})
    if isinstance(rules, str):
        logging.warning(f"Rules attribute is a string reference: {rules}. Skipping detailed processing.")
    elif isinstance(rules, dict):
        children = rules.get("children", [])
        if children:
            for rule in children:
                try:
                    logging.info(f"Processing rule: {rule.get('name', 'Unnamed Rule')}")
                    azion_resources.extend(create_rule_engine(rule, main_setting_name))
                except KeyError as e:
                    logging.error(f"Missing expected key in rule {rule.get('name', 'Unnamed Rule')}: {e}")
                except TypeError as e:
                    logging.error(f"Type error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
                except ValueError as e:
                    logging.error(f"Value error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
        else:
            logging.warning("No children rules found in rules attribute.")
    else:
        logging.warning(f"Unexpected type for rules: {type(rules)}. Skipping rule processing.")

    # Add WAF rules if available
    try:
        waf_rule = create_waf_rule(attributes)
        if waf_rule:
            logging.info("WAF rule detected and converted.")
            azion_resources.append(waf_rule)
    except KeyError as e:
        logging.error(f"Missing expected key in WAF rule creation: {e}")
    except TypeError as e:
        logging.error(f"Type error in WAF rule creation: {e}")
    except ValueError as e:
        logging.error(f"Value error in WAF rule creation: {e}")

    logging.info(f"Completed conversion for Akamai property: {attributes.get('name', 'Unknown')}.")
    return azion_resources



def create_main_setting(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates the main application setting resource for Azion.

    Parameters:
        attributes (dict): Attributes from Akamai configuration.
        main_setting_name (str): Name of the main Azion edge application resource.

    Returns:
        dict: Azion-compatible main_setting resource.
    """
    defaults = {
        "name": "Default Edge Application",
        "delivery_protocol": "http,https",
        "http_port": [80,8080],
        "https_port": [443],
        "supported_ciphers": "all",
        "minimum_tls_version": "",
        "debug_rules": False,
        "caching": True,
        "edge_firewall": False,
        "edge_functions": False,
        "image_optimization": False,
        "http3": False,
        "application_acceleration": False,
        "l2_caching": False,
        "load_balancer": False,
        "raw_logs": True,
        "device_detection": False,
        "web_application_firewall": False,
    }

    validated_attributes = validate_and_apply_defaults(attributes, defaults)

    return {
        "type": "azion_edge_application_main_setting",
        "attributes": {
            "edge_application": validated_attributes
        }
    }


def create_origin(attributes: Dict[str, Any], main_setting_name: str, edge_hostname: Optional[str]) -> Dict[str, Any]:
    """
    Creates the origin resource for Azion, dynamically mapping Akamai addresses.

    Parameters:
        attributes (dict): Attributes from Akamai configuration.
        main_setting_name (str): Name of the main Azion edge application resource.
        edge_hostname (Optional[str]): The edge hostname extracted from Akamai configuration.

    Returns:
        dict: Azion-compatible origin resource.
    """
    try:
        logging.info("Creating Azion origin resource.")

        # Extract and validate rules
        rules = attributes.get("rules", {})
        behaviors = []
        if isinstance(rules, str):
            logging.warning("Rules attribute is a string reference. Skipping detailed processing.")
        elif isinstance(rules, dict):
            behaviors = rules.get("behaviors", [])
        else:
            logging.warning("Unexpected type for rules. Defaulting to empty behaviors.")
        logging.debug(f"Rules attribute content: {rules}")

        # Extract origin behavior
        origin_behavior = next((b for b in behaviors if b.get("name") == "origin"), {})
        options = origin_behavior.get("options", {})

        # Extract origin-specific details
        hostname = options.get("hostname") or edge_hostname or "placeholder.example.com"
        origin_type = options.get("originType", "single_origin")
        origin_protocol_policy = options.get("origin_protocol_policy", "preserve")
        host_header = options.get("forwardHostHeader", "$${host}")
        origin_path = options.get("originPath", "/")
        hmac_authentication = attributes.get("hmac_authentication", False)
        hmac_region_name = attributes.get("hmac_region_name", "")
        hmac_access_key = attributes.get("hmac_access_key", "")
        hmac_secret_key = attributes.get("hmac_secret_key", "")

        # Validate extracted hostname
        if not hostname or hostname == "placeholder.example.com":
            logging.warning(f"Hostname not properly set. Using placeholder: {hostname}")

        # Construct the origin resource
        origin_resource = {
            "type": "azion_edge_application_origin",
            "attributes": {
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.application_id",
                "origin": {
                    "name": attributes.get("name", "Default Origin"),
                    "origin_type": origin_type,
                    "addresses": [{"address": hostname}],
                    "origin_protocol_policy": origin_protocol_policy,
                    "host_header": host_header,
                    "origin_path": origin_path,
                    "hmac_authentication": hmac_authentication,
                    "hmac_region_name": hmac_region_name,
                    "hmac_access_key": hmac_access_key,
                    "hmac_secret_key": hmac_secret_key,
                },
                "depends_on": [main_setting_name],
            },
        }

        logging.info(f"Origin resource created with hostname: {hostname}")
        return origin_resource

    except Exception as e:
        logging.error(f"Error creating origin resource: {e}")
        raise


def create_rule_and_cache(rule: Dict[str, Any], main_setting_name: str) -> List[Dict[str, Any]]:
    """
    Creates Azion cache settings and rule engine resources from Akamai rules.
    """
    if not isinstance(rule, dict):
        logging.warning(f"Skipping rule creation: Expected dict, got {type(rule)}.")
        return []

    resources = []

    # Cache settings
    cache_setting = create_cache_setting(rule, main_setting_name)
    if cache_setting:
        resources.append(cache_setting)

    # Rule engine
    rule_engine = create_rule_engine(rule, main_setting_name)
    resources.extend(rule_engine)

    return resources


def create_cache_setting(rule: Dict[str, Any], main_setting_name: str) -> Optional[Dict[str, Any]]:
    """
    Creates a single Azion cache setting resource.
    """
    logging.info(f"Creating cache setting for rule: {rule.get('name', 'Unnamed Rule')}")
    caching_behavior = next((b for b in rule.get("behaviors", []) if b.get("name") == "caching"), None)
    if caching_behavior:
        logging.info("Cache behavior found. Generating resource.")
        return {
            "type": "azion_edge_application_cache_setting",
            "attributes": {
                "cache_settings": {
                    "name": rule.get("name", "Default Cache Setting"),
                    "enable_stale_cache": True,
                    "cdn_cache_settings_maximum_ttl": caching_behavior.get("options", {}).get("ttl", 3600),
                },
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.application_id",
            },
        }
    logging.warning("No caching behavior found. Skipping cache setting creation.")
    return None


def create_rule_engine(rule: Dict[str, Any], main_setting_name: str) -> List[Dict[str, Any]]:
    """
    Creates Azion rule engine resources.

    Parameters:
        rule (dict): Rule data extracted from Akamai configuration.
        main_setting_name (str): Name of the main setting resource.

    Returns:
        List[Dict[str, Any]]: List of Azion rule engine resources.
    """
    resources = []
    rule_name = rule.get("name", "Unnamed Rule")
    logging.info(f"Processing rule: {rule_name}")

    # Extract behaviors and criteria
    behaviors = rule.get("behaviors", [])
    criteria = rule.get("criteria", [])

    logging.info(f"Found {len(behaviors)} behaviors and {len(criteria)} criteria for rule: {rule_name}")

    try:
        # Create resource if either behaviors or criteria exist
        if behaviors or criteria:
            resources.append({
                "type": "azion_edge_application_rule_engine",
                "attributes": {
                    "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.application_id",
                    "results": {
                        "name": rule_name,
                        "phase": rule.get("phase", "request"),
                        "description": rule.get("description", ""),
                        "behaviors": convert_behaviors(behaviors),
                        "criteria": convert_conditions(criteria),
                    },
                },
            })
            logging.info(f"Rule engine resource created for rule: {rule_name}")
        else:
            logging.warning(f"No behaviors or criteria found for rule: {rule_name}. Skipping.")
    except KeyError as e:
        logging.error(f"Missing key while processing rule {rule_name}: {e}")
    except TypeError as e:
        logging.error(f"Type error while processing rule {rule_name}: {e}")
    except ValueError as e:
        logging.error(f"Value error while processing rule {rule_name}: {e}")

    return resources


def convert_conditions(criteria_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    conditions = []
    for condition in criteria_list:
        entries = []
        options = condition.get("options", {})
        for value in options.get("values", []):
            entries.append({
                "variable": condition.get("name", ""),
                "operator": options.get("matchOperator", "EQUALS"),
                "input_value": value,
            })
        if entries:
            conditions.append({"entries": entries})  # No trailing comma
    return conditions


def convert_behaviors(behaviors_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    behaviors = []
    for behavior in behaviors_list:
        behavior_dict = {
            "name": behavior.get("name", ""),
        }
        options = behavior.get("options", {})
        if options:
            target_object = {}
            for key, value in options.items():
                if key == "behavior":
                    target_object[key] = value
            if target_object:
                behavior_dict["target_object"] = target_object
        behaviors.append(behavior_dict)  # No trailing comma
    return behaviors



VALID_SENSITIVITY_LEVELS = {"low", "medium", "high", "highest"}

def create_waf_rule(attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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


def create_domain(attributes: Dict[str, Any], main_setting_name: str) -> Dict[str, Any]:
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
            "attributes": {
                "domain": {
                    "cnames": f"[{', '.join(cnames)}]",
                    "name": domain_name,
                    "digital_certificate_id": digital_certificate_id,
                    "cname_access_only": False,
                    "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.application_id",
                    "is_active": True,
                },
                "depends_on": [main_setting_name],
            },
        }

        logging.info(f"Domain resource created for '{domain_name}' with CNAMEs: {cnames}.")
        return domain_resource

    except Exception as e:
        logging.error(f"Error creating domain resource: {e}")
        raise

