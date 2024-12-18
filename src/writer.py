from typing import Dict, Any
import logging
from utils import sanitize_name, write_indented
from io import StringIO

logging.basicConfig(level=logging.INFO)


def write_variable_block(f):
    """Writes the Terraform variable block for Azion API token."""
    write_indented(f, 'variable "azion_api_token" {', 0)
    write_indented(f, 'default     = null', 1)
    write_indented(f, 'description = "Azion API token"', 1)
    write_indented(f, '}', 0)
    write_indented(f, '', 0)


def write_provider_block(f):
    """Writes the Terraform provider block for Azion."""
    write_indented(f, 'provider "azion" {', 0)
    write_indented(f, 'api_token = var.azion_api_token', 1)
    write_indented(f, '}', 0)
    write_indented(f, '', 0)


def write_depends_on(f, attributes):
    """
    Writes the depends_on block for a Terraform resource.

    Parameters:
        f (file object): File object to write to.
        attributes (dict): Attributes containing depends_on data.
    """
    depends_on = attributes.get("depends_on", [])
    if depends_on:
        depends_on_list = ", ".join([f"{item}" for item in depends_on])
        write_indented(f, f"depends_on = [{depends_on_list}]", 1)


def write_main_setting_block(f, attributes):
    """
    Writes the Terraform block for the main Azion edge application setting.

    Parameters:
        f (file object): File object to write to.
        attributes (dict): Attributes for the main setting.
    """
    try: 
        edge_application = attributes["edge_application"]
        name = edge_application.get("name")
        if not name:
            name = "Unnamed Edge Application"
        normalized_name = sanitize_name(name)

        # Apply defaults and validate values
        delivery_protocol = edge_application.get("delivery_protocol", "http,https")
        http_port = edge_application.get("http_port", [80,8080])
        https_port = edge_application.get("https_port", [443])
        minimum_tls_version = edge_application.get("minimum_tls_version", "")
        supported_ciphers = edge_application.get("supported_ciphers", "all")

        # Default values for additional fields
        debug_rules = edge_application.get("debug_rules", False)
        caching = edge_application.get("caching", True)
        edge_firewall = edge_application.get("edge_firewall", False)
        edge_functions = edge_application.get("edge_functions", False)
        image_optimization = edge_application.get("image_optimization", False)
        http3 = edge_application.get("http3", False)
        application_acceleration = edge_application.get("application_acceleration", False)
        l2_caching = edge_application.get("l2_caching", False)
        load_balancer = edge_application.get("load_balancer", False)
        raw_logs = edge_application.get("raw_logs", True)
        device_detection = edge_application.get("device_detection", False)
        web_application_firewall = edge_application.get("web_application_firewall", False)

        # Write block
        write_indented(f, f'resource "azion_edge_application_main_setting" "{normalized_name}" {{', 0)
        write_indented(f, "edge_application = {", 1)
        write_indented(f, f'name                     = "{edge_application["name"]}"', 2)
        write_indented(f, f'supported_ciphers        = "{supported_ciphers}"', 2)
        write_indented(f, f'delivery_protocol        = "{delivery_protocol}"', 2)
        write_indented(f, f'http_port                = {http_port}', 2)
        write_indented(f, f'https_port               = {https_port}', 2)
        write_indented(f, f'minimum_tls_version      = "{minimum_tls_version}"', 2)
        write_indented(f, f'debug_rules              = {str(debug_rules).lower()}', 2)
        write_indented(f, f'caching                  = {str(caching).lower()}', 2)
        write_indented(f, f'edge_firewall            = {str(edge_firewall).lower()}', 2)
        write_indented(f, f'edge_functions           = {str(edge_functions).lower()}', 2)
        write_indented(f, f'image_optimization       = {str(image_optimization).lower()}', 2)
        write_indented(f, f'http3                    = {str(http3).lower()}', 2)
        write_indented(f, f'application_acceleration = {str(application_acceleration).lower()}', 2)
        write_indented(f, f'l2_caching               = {str(l2_caching).lower()}', 2)
        write_indented(f, f'load_balancer            = {str(load_balancer).lower()}', 2)
        write_indented(f, f'raw_logs                 = {str(raw_logs).lower()}', 2)
        write_indented(f, f'device_detection         = {str(device_detection).lower()}', 2)
        write_indented(f, f'web_application_firewall = {str(web_application_firewall).lower()}', 2)
        write_indented(f, "}", 1)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)
        logging.info(f"Main setting block written for {edge_application['name']}")
    except KeyError as e:
        logging.error(f"Missing key {e} in main setting attributes")
    except ValueError as e:
        logging.error(f"Unexpected error in write_main_setting_block: {e}")


def write_origin_block(f, attributes):
    """
    Writes the origin resource block for Azion based on its business rules.

    Parameters:
        f (file object): File object to write to.
        attributes (dict): Attributes for the origin.
    """
    try:
        origin = attributes["origin"]

        # Extract required values and apply defaults
        normalized_name = sanitize_name(origin["name"])
        edge_application_id = attributes["edge_application_id"]
        origin_type = origin.get("origin_type", "single_origin")
        addresses = origin.get("addresses", [{"address": "placeholder.example.com"}])
        origin_protocol_policy = origin.get("origin_protocol_policy", "preserve")
        host_header = origin.get("host_header", "$${host}")
        origin_path = origin.get("origin_path", "/")
        hmac_authentication = origin.get("hmac_authentication", False)
        hmac_region_name = origin.get("hmac_region_name", "")
        hmac_access_key = origin.get("hmac_access_key", "")
        hmac_secret_key = origin.get("hmac_secret_key", "")
        connection_timeout = origin.get("connection_timeout", 60)
        timeout_between_bytes = origin.get("timeout_between_bytes", 5)
        is_origin_redirection_enabled = origin.get("is_origin_redirection_enabled", False)

        # Write block
        write_indented(f, f'resource "azion_edge_application_origin" "{normalized_name}" {{', 0)
        write_indented(f, f'edge_application_id = {edge_application_id}', 1)
        write_indented(f, "origin = {", 1)
        write_indented(f, f'name        = "{origin["name"]}"', 2)
        write_indented(f, f'origin_type = "{origin_type}"', 2)

        # Write addresses block
        write_indented(f, "addresses = [", 2)
        for address in addresses:
            address_block = [
                f'"address" : "{address["address"]}"',
                f'"is_active" : {str(address.get("is_active", True)).lower()}',
                f'"server_role" : "{address.get("server_role", "primary")}"',
                f'"weight" : {address.get("weight", 0)}',
            ]
            write_indented(f, f'{{ {", ".join(address_block)} }},', 3)
        write_indented(f, "],", 2)

        # Write remaining fields
        write_indented(f, f'origin_protocol_policy = "{origin_protocol_policy}"', 2)
        write_indented(f, f'host_header = "{host_header}"', 2)
        write_indented(f, f'origin_path = "{origin_path}"', 2)
        write_indented(f, f'connection_timeout = {connection_timeout}', 2)
        write_indented(f, f'timeout_between_bytes = {timeout_between_bytes}', 2)
        write_indented(f, f'is_origin_redirection_enabled = {str(is_origin_redirection_enabled).lower()}', 2)
        write_indented(f, f'hmac_authentication = {str(hmac_authentication).lower()}', 2)
        write_indented(f, f'hmac_region_name = "{hmac_region_name}"', 2)
        write_indented(f, f'hmac_access_key = "{hmac_access_key}"', 2)
        write_indented(f, f'hmac_secret_key = "{hmac_secret_key}"', 2)
        write_indented(f, "}", 1)
        write_depends_on(f, attributes)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)

        logging.info(f"Origin block written for {origin['name']}")
    except KeyError as e:
        logging.error(f"Missing key {e} in origin attributes")
        raise
    except Exception as e:
        logging.error(f"Unexpected error in write_origin_block: {e}")
        raise


def write_domain_block(f, attributes):
    """
    Writes the Terraform block for Azion domain configuration.

    Parameters:
        f (file object): File object to write to.
        attributes (dict): Attributes for the domain resource.
    """
    try:
        domain = attributes["domain"]
        normalized_name = sanitize_name(domain["name"])
        write_indented(f, f'resource "azion_domain" "{normalized_name}" {{', 0)
        write_indented(f, "domain = {", 1)
        write_indented(f, f'cnames                    = {domain["cnames"]}', 2)
        write_indented(f, f'name                      = "{domain["name"]}"', 2)
        write_indented(f, f'digital_certificate_id    = {domain["digital_certificate_id"]}', 2)
        write_indented(f, f'cname_access_only         = {str(domain["cname_access_only"]).lower()}', 2)
        write_indented(f, f'edge_application_id       = {domain["edge_application_id"]}', 2)
        write_indented(f, f'is_active                 = {str(domain["is_active"]).lower()}', 2)
        write_indented(f, "}", 1)
        write_depends_on(f, attributes)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)
        logging.info(f"Domain block written for {domain['name']}")
    except KeyError as e:
        logging.error(f"Missing key {e} in domain attributes")
    except ValueError as e:
        logging.error(f"Unexpected error in write_domain_block: {e}")


def write_rule_engine_block(f, resource):
    """
    Write a rule engine block to the Terraform file.

    Parameters:
        f (file object): File object to write to.
        resource (dict): Resource data to write.
    """
    try:
        attributes = resource.get("attributes", {})
        results = attributes.get("results", {})

        # Get resource name from results
        name = results.get("name", "unnamed_rule")
        normalized_name = sanitize_name(name)

        # Write resource block header
        write_indented(f, f'resource "azion_edge_application_rule_engine" "{normalized_name}" {{', 0)
        write_indented(f, f'edge_application_id = {attributes.get("edge_application_id")}', 1)
        write_indented(f, "", 0)

        # Write results block
        write_indented(f, "results = {", 1)

        # Write basic attributes
        write_indented(f, f'name        = "{name}"', 2)
        write_indented(f, f'phase       = "{results.get("phase", "request")}"', 2)
        write_indented(f, f'description = "{results.get("description", "")}"', 2)

        # Write behaviors if present
        behaviors = results.get("behaviors", [])
        if behaviors:
            write_indented(f, "behaviors = [", 2)
            for behavior in behaviors:
                write_indented(f, "{", 3)
                write_indented(f, f'name = "{behavior.get("name")}"', 4)

                # Write target_object if present
                target = behavior.get("target", {})
                if target:
                    write_indented(f, "target_object = {", 4)
                    if isinstance(target, dict):
                        for key, value in target.items():
                            # Convert value based on its type
                            if key == "addresses" and isinstance(value, list):
                                # Convert list to HCL format
                                addresses_str = ", ".join([str(addr).replace("'", '"') for addr in value])
                                write_indented(f, f'{key} = [{addresses_str}]', 5)
                            elif isinstance(value, bool):
                                write_indented(f, f'{key} = {str(value).lower()}', 5)
                            elif isinstance(value, (int, float)):
                                write_indented(f, f'{key} = {value}', 5)
                            else:
                                write_indented(f, f'{key} = "{value}"', 5)
                    else:
                        write_indented(f, f'target = "{target}"', 5)
                    write_indented(f, "}", 4)
                else:
                    write_indented(f, "target_object = {}", 4)

                write_indented(f, "},", 3)
            write_indented(f, "]", 2)

        # Write criteria if present
        criteria = results.get("criteria", [])
        if criteria:
            write_indented(f, "criteria = [", 2)
            for criterion in criteria:
                write_indented(f, "{", 3)
                write_indented(f, "entries = [", 4)
                for entry in criterion.get("entries", []):
                    write_indented(f, "{", 5)
                    write_indented(f, f'variable    = "{entry.get("variable", "")}"', 6)
                    write_indented(f, f'operator    = "{entry.get("operator", "matches")}"', 6)
                    write_indented(f, f'conditional = "{entry.get("conditional", "and")}"', 6)

                    # Handle input_value safely
                    input_value = entry.get("input_value", "*")
                    if input_value:
                        write_indented(f, f'input_value = "{input_value}"', 6)

                    write_indented(f, "},", 5)
                write_indented(f, "]", 4)
                write_indented(f, "},", 3)
            write_indented(f, "]", 2)

        # Write order if present
        order = results.get("order")
        if order is not None:
            write_indented(f, f"order = {int(order)}", 2)

        # Close blocks
        write_indented(f, "}", 1)
        write_depends_on(f, attributes)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)

        logging.info(f"Rule engine block written for {normalized_name}")
    except ValueError as e:
        logging.error(f"Error writing rule engine block: {str(e)}")


def write_cache_setting_block(f, resource: dict):
    """
    Writes the cache settings block for Azion based on validated settings.

    Parameters:
        f (file object): The file to write the Terraform block.
        resource (dict): Resource to be written.
    """
    name = resource.get("name", "unnamed_cache_settings")
    try:
        # Validate and normalize cache settings
        validated_settings = validate_cache_settings(resource.get("attributes", {}).get("cache_settings", {}))

        # Write cache setting resource block
        write_indented(f, f'resource "azion_edge_application_cache_setting" "{name}" {{', 0)
        write_indented(f, "cache_settings = {", 1)
        write_indented(f, f'browser_cache_settings = "{validated_settings["browser_cache_settings"]}"', 2)
        write_indented(
            f, f'browser_cache_settings_maximum_ttl = {validated_settings["browser_cache_settings_maximum_ttl"]}', 2
        )
        write_indented(f, f'cdn_cache_settings = "{validated_settings["cdn_cache_settings"]}"', 2)
        write_indented(
            f, f'cdn_cache_settings_maximum_ttl = {validated_settings["cdn_cache_settings_maximum_ttl"]}', 2
        )
        write_indented(f, "}", 1)
        write_indented(f, f'edge_application_id = azion_edge_application_main_setting.{name}.edge_application.application_id', 1)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)

        logging.info(f"Cache settings block written for {name}")

    except Exception as e:
        logging.error(f"Error writing cache settings block for {name}: {e}")
        raise


def validate_cache_settings(cache_settings: dict) -> dict:
    """
    Validates and applies default values to cache settings.

    Parameters:
        cache_settings (dict): The input cache settings from Akamai configuration.

    Returns:
        dict: Validated and normalized cache settings for Azion configuration.
    """
    try:
        # Extract and validate settings with defaults
        browser_cache_settings = cache_settings.get("browser_cache_settings", "honor")
        if browser_cache_settings not in ["honor", "override"]:
            logging.warning(f"Invalid browser_cache_settings '{browser_cache_settings}', defaulting to 'honor'")
            browser_cache_settings = "honor"

        browser_cache_ttl = cache_settings.get("browser_cache_settings_maximum_ttl", 0)
        if not (0 <= browser_cache_ttl <= 31536000):
            logging.warning(
                f"Invalid browser_cache_settings_maximum_ttl '{browser_cache_ttl}', defaulting to 0"
            )
            browser_cache_ttl = 0

        cdn_cache_settings = cache_settings.get("cdn_cache_settings", "honor")
        if cdn_cache_settings not in ["honor", "override"]:
            logging.warning(f"Invalid cdn_cache_settings '{cdn_cache_settings}', defaulting to 'honor'")
            cdn_cache_settings = "honor"

        try:
            cdn_cache_ttl = int(cache_settings.get("cdn_cache_settings_maximum_ttl", 60))
        except (ValueError, TypeError):
            logging.warning("Invalid cdn_cache_settings_maximum_ttl format, defaulting to 60")
            cdn_cache_ttl = 60

        if not (0 <= cdn_cache_ttl <= 31536000):
            logging.warning(
                f"Invalid cdn_cache_settings_maximum_ttl '{cdn_cache_ttl}', defaulting to 60"
            )
            cdn_cache_ttl = 60

        # Return validated settings
        return {
            "browser_cache_settings": browser_cache_settings,
            "browser_cache_settings_maximum_ttl": browser_cache_ttl,
            "cdn_cache_settings": cdn_cache_settings,
            "cdn_cache_settings_maximum_ttl": cdn_cache_ttl,
        }

    except Exception as e:
        logging.error(f"Error validating cache settings: {e}")
        raise


def write_azion_edge_function_block(function_data: dict, resource_name: str) -> str:
    """
    Generates a Terraform block for azion_edge_function resource with proper indentation.

    Parameters:
        function_data (dict): Data for the edge function configuration.
        resource_name (str): Name of the Terraform resource.

    Returns:
        str: Terraform block as a string.
    """

    # Prepare an output buffer
    output = StringIO()

    # Extract data from the function_data dictionary
    name = function_data.get("name", "Unnamed Function")
    code = function_data.get("code", "placeholder_code")
    language = function_data.get("language", "javascript")
    initiator_type = function_data.get("initiator_type", "edge_application")
    json_args = function_data.get("json_args", "{}")
    active = function_data.get("active", True)

    # Write the Terraform block
    write_indented(f'resource "azion_edge_function" "{resource_name}" {{', 0)
    write_indented("edge_function = {", 1)
    write_indented(f'name           = "{name}"', 2)
    write_indented(f'code           = trimspace(file("{code}"))', 2)
    write_indented(f'language       = "{language}"', 2)
    write_indented(f'initiator_type = "{initiator_type}"', 2)
    write_indented(f'json_args      = jsonencode({json_args})', 2)
    write_indented(f'active         = {str(active).lower()}', 2)
    write_indented("}", 1)
    write_indented("}", 0)

    return output.getvalue()


def write_azion_edge_application_edge_functions_instance_block(f, attributes: dict, main_setting_name: str):
    """
    Writes the azion_edge_application_edge_functions_instance block.

    Parameters:
        f (file object): The file to write to.
        attributes (dict): Attributes for the azion_edge_application_edge_functions_instance resource.
    """
    results = attributes.get("results", {})
    name = results.get("name")
    edge_function_id = results.get("edge_function_id")
    args = results.get("args", None)

    # Validate edge_functions in main_setting
    if not attributes.get("edge_functions", False):
        raise ValueError(
            f"Cannot create azion_edge_application_edge_functions_instance '{name}' because 'edge_functions' "
            f"is not enabled in azion_edge_application_main_setting."
        )

    # Begin resource block
    write_indented(f, f'resource "azion_edge_application_edge_functions_instance" "{name}" {{', 0)

    # Write edge_application_id
    write_indented(f, f'edge_application_id = azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id', 1)

    # Write results block
    write_indented(f, "results = {", 1)
    write_indented(f, f'name = "{name}"', 2)
    write_indented(f, f'edge_function_id = {edge_function_id}', 2)
    if args:
        write_indented(f, f'args = jsonencode({args})', 2)
    write_indented(f, "}", 1)

    # Write depends_on using the helper function
    write_depends_on(f, attributes)

    # End resource block
    write_indented(f, "}", 0)


def write_terraform_file(filepath: str, config: Dict[str, Any]):
    """
    Writes the entire Terraform file based on the Azion configuration.

    Parameters:
        filepath (str): Path to the output Terraform file.
        config (dict): Azion configuration dictionary with resources to be written.
        main_setting_name (str): Main setting name to use as a reference in dependencies.
    """
    try:
        main_setting_name = config.get("global_settings", {}).get("main_setting_name")

        with open(filepath, "w", encoding="utf-8") as f:
            # Write variable and provider blocks
            write_variable_block(f)
            write_provider_block(f)

            # Iterate over resources and write their corresponding blocks
            for resource in config["resources"]:
                resource_type = resource.get("type", None)
                attributes = resource.get("attributes", None)
                if not resource_type or not attributes or resource_type == "global_settings":
                    continue

                if resource_type == "azion_edge_application_main_setting":
                    write_main_setting_block(f, attributes)
                elif resource_type == "azion_edge_application_origin":
                    write_origin_block(f, attributes)
                elif resource_type == "azion_edge_application_rule_engine":
                    write_rule_engine_block(f, resource)
                elif resource_type == "azion_domain":
                    write_domain_block(f, attributes)
                elif resource_type == "azion_edge_function":
                    write_azion_edge_function_block(f, attributes)
                elif resource_type == "azion_edge_application_cache_setting":
                    write_cache_setting_block(f, resource)
                else:
                    logging.warning(f"Unknown resource type '{resource_type}' encountered. Skipping.")

            logging.info(f"Terraform file successfully written to {filepath}")
    except Exception as e:
        logging.error(f"Error writing Terraform file: {e}")
        raise
