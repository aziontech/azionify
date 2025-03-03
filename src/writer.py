from typing import Dict, Any
import logging
from utils import sanitize_name, write_indented, resources_filter_by_type
from io import StringIO

logging.basicConfig(level=logging.INFO)

ALLOWED_CACHE_SETTINGS = ["honor", "override"]

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
        if browser_cache_settings not in ALLOWED_CACHE_SETTINGS:
            logging.warning(f"Invalid browser_cache_settings '{browser_cache_settings}', defaulting to 'honor'")
            browser_cache_settings = "honor"

        browser_cache_ttl = cache_settings.get("browser_cache_settings_maximum_ttl", 0)
        if not (0 <= browser_cache_ttl <= 31536000):
            logging.warning(
                f"Invalid browser_cache_settings_maximum_ttl '{browser_cache_ttl}', defaulting to 0"
            )
            browser_cache_ttl = 0

        cdn_cache_settings = cache_settings.get("cdn_cache_settings", "honor")
        if cdn_cache_settings not in ALLOWED_CACHE_SETTINGS:
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

        enable_stale_cache = cache_settings.get("enable_stale_cache", "false").lower()
        if enable_stale_cache not in ["true", "false"]:
            logging.warning(
                f"Invalid enable_stale_cache '{enable_stale_cache}', defaulting to false"
            )
            enable_stale_cache = "false"

        # Return validated settings
        return {
            "browser_cache_settings": browser_cache_settings,
            "browser_cache_settings_maximum_ttl": browser_cache_ttl,
            "cdn_cache_settings": cdn_cache_settings,
            "cdn_cache_settings_maximum_ttl": cdn_cache_ttl,
            "enable_stale_cache": enable_stale_cache,
            "cache_by_cookies": "ignore",
            "cache_by_query_string": "ignore",
            "adaptive_delivery_action": "ignore",
            "is_slice_configuration_enabled": "false",
            "is_slice_edge_caching_enabled": "false",
            "slice_configuration_range": 1024
        }

    except Exception as e:
        logging.error(f"Error validating cache settings: {e}")
        raise


def write_variable_block(f) -> None:
    """
    Writes the Terraform variable block for Azion API token.

    Parameters:
        f (file object): File object to write to.
    """
    write_indented(f, 'variable "azion_api_token" {', 0)
    write_indented(f, 'default     = null', 1)
    write_indented(f, 'type        = string', 1)
    write_indented(f, 'description = "Azion API token"', 1)
    write_indented(f, '}', 0)
    write_indented(f, '', 0)


def write_provider_block(f) -> None:
    """
    Writes the Terraform provider block for Azion.

    Parameters:
        f (file object): File object to write to.
    """
    write_indented(f, 'provider "azion" {', 0)
    write_indented(f, 'api_token = var.azion_api_token', 1)
    write_indented(f, '}', 0)
    write_indented(f, '', 0)


def write_depends_on(f, attributes: Dict[str, Any]) -> None:
    """
    Writes the depends_on block for a Terraform resource.

    Parameters:
        f (file object): File object to write to.
        attributes (dict): Attributes containing depends_on data.
    """
    depends_on = attributes.get("depends_on", [])
    if depends_on:
        write_indented(f, "depends_on = [", 1)
        for item in depends_on:
            write_indented(f, f"{item},", 2)
        write_indented(f, "]", 1)


def write_main_setting_block(f, resource: Dict[str, Any]) -> None:
    """
    Writes the Terraform block for the main Azion edge application setting.

    Parameters:
        f (file object): File object to write to.
        resource (dict): Resource containing the main setting.
    """
    try:
        # Get Edge Application from attributes
        attributes = resource.get("attributes")
        edge_application = attributes.get("edge_application")
        edge_application_name = edge_application.get("name", "Unnamed Edge Application")
        normalized_name = sanitize_name(edge_application_name)

        # Apply defaults and validate values
        delivery_protocol = edge_application.get("delivery_protocol", "http,https")
        http_port = edge_application.get("http_port", [80,8080])
        https_port = edge_application.get("https_port", [443])
        minimum_tls_version = edge_application.get("minimum_tls_version", "")
        supported_ciphers = edge_application.get("supported_ciphers", "all")

        # Default values for additional fields
        debug_rules = edge_application.get("debug_rules", False)
        caching = edge_application.get("caching", True)
        edge_functions = edge_application.get("edge_functions", False)
        image_optimization = edge_application.get("image_optimization", False)
        http3 = edge_application.get("http3", False)
        application_acceleration = edge_application.get("application_acceleration", False)
        l2_caching = edge_application.get("l2_caching", False)
        load_balancer = edge_application.get("load_balancer", False)
        device_detection = edge_application.get("device_detection", False)

        # Write block
        write_indented(f, f'resource "azion_edge_application_main_setting" "{normalized_name}" {{', 0)
        write_indented(f, "edge_application = {", 1)
        write_indented(f, f'name                     = "{edge_application_name}"', 2)
        write_indented(f, f'supported_ciphers        = "{supported_ciphers}"', 2)
        write_indented(f, f'delivery_protocol        = "{delivery_protocol}"', 2)
        write_indented(f, f'http_port                = {http_port}', 2)
        write_indented(f, f'https_port               = {https_port}', 2)
        write_indented(f, f'minimum_tls_version      = "{minimum_tls_version}"', 2)
        write_indented(f, f'debug_rules              = {str(debug_rules).lower()}', 2)
        write_indented(f, f'caching                  = {str(caching).lower()}', 2)
        write_indented(f, f'edge_functions           = {str(edge_functions).lower()}', 2)
        write_indented(f, f'image_optimization       = {str(image_optimization).lower()}', 2)
        write_indented(f, f'http3                    = {str(http3).lower()}', 2)
        write_indented(f, f'application_acceleration = {str(application_acceleration).lower()}', 2)
        write_indented(f, f'l2_caching               = {str(l2_caching).lower()}', 2)
        write_indented(f, f'load_balancer            = {str(load_balancer).lower()}', 2)
        write_indented(f, f'device_detection         = {str(device_detection).lower()}', 2)
        write_indented(f, "}", 1)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)
        logging.info(f"Main setting block written for {edge_application_name}")
    except KeyError as e:
        logging.error(f"Missing key {e} in main setting attributes")
    except ValueError as e:
        logging.error(f"Unexpected error in write_main_setting_block: {e}")


def write_origin_block(f, resource: Dict[str, Any]) -> None:
    """
    Writes the origin resource block for Azion based on its business rules.

    Parameters:
        f (file object): File object to write to.
        resource (dict): Origin resource.
    """
    try:
        attributes = resource.get("attributes")
        origin = attributes.get("origin")

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
                f'"address" : "{address["address"]}"'
                #f'"is_active" : {str(address.get("is_active", True)).lower()}',
                #f'"server_role" : "{address.get("server_role", "primary")}"',
                #f'"weight" : {address.get("weight", 0)}',
            ]
            write_indented(f, f'{{ {", ".join(address_block)} }},', 3)
        write_indented(f, "],", 2)

        # Write remaining fields
        write_indented(f, f'origin_protocol_policy = "{origin_protocol_policy}"', 2)
        write_indented(f, f'host_header = "{host_header}"', 2)
        write_indented(f, f'origin_path = "{origin_path}"', 2)
        write_indented(f, f'connection_timeout = {connection_timeout}', 2)
        write_indented(f, f'timeout_between_bytes = {timeout_between_bytes}', 2)
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


def write_domain_block(f, resource: Dict[str, Any]) -> None:
    """
    Writes the Terraform block for Azion domain configuration.

    Parameters:
        f (file object): File object to write to.
        resource (dict): Resource dictionary containing the domain attributes.
    """
    try:
        attributes = resource.get("attributes", {})
        domain = attributes.get("domain", {})
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


def write_rule_engine_block(f, resource: Dict[str, Any]) -> None:
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
        normalized_name = resource.get("name")

        if "offload_origin" in normalized_name:
            return
        # Write resource block header
        write_indented(f, f'resource "azion_edge_application_rule_engine" "{normalized_name}" {{', 0)
        write_indented(f, f'edge_application_id = {attributes.get("edge_application_id")}', 1)
        write_indented(f, "", 0)

        # Write results block
        write_indented(f, "results = {", 1)

        # Write basic attributes
        write_indented(f, f'name        = "{name}"', 2)
        write_indented(f, f'phase       = "{results.get("phase", "request")}"', 2)
        write_indented(f, f'description = "{results.get("description", "").strip()}"', 2)

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
                            elif str(value).startswith("$"):
                                write_indented(f, f'{key} = "{value}"', 5)
                            else:
                                write_indented(f, f'{key} = {value}', 5)
                    else:
                        write_indented(f, f'target = "{target}"', 5)
                    write_indented(f, "}", 4)
                else:
                    write_indented(f, "target_object = {}", 4)

                write_indented(f, "},", 3)
            write_indented(f, "]", 2)

        # Write criteria if present
        criteria = results.get("criteria", {})
        if criteria:
            write_indented(f, "criteria = [", 2)
            #for criterion in criteria:
            write_indented(f, "{", 3)
            write_indented(f, "entries = [", 4)
            for entry in criteria.get("entries", []):
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


def write_cache_setting_block(f, resource: Dict[str, Any]) -> None:
    """
    Writes the cache settings block for Azion based on validated settings.

    Parameters:
        f (file object): The file to write the Terraform block.
        resource (dict): Resource to be written.
    """
    name = resource.get("name", "unnamed_cache_settings")
    attributes = resource.get("attributes", {})
    try:
        # Validate and normalize cache settings
        validated_settings = validate_cache_settings(attributes.get("cache_settings", {}))
        main_setting_id = resource.get("attributes", {}).get("edge_application_id")

        # Write cache setting resource block
        write_indented(f, f'resource "azion_edge_application_cache_setting" "{name}" {{', 0)
        write_indented(f, f'edge_application_id = {main_setting_id}', 1)
        write_indented(f, "cache_settings = {", 1)
        write_indented(f, f'name = "{name}"', 2)
        write_indented(f, f'browser_cache_settings = "{validated_settings["browser_cache_settings"]}"', 2)
        write_indented(
            f, f'browser_cache_settings_maximum_ttl = {validated_settings["browser_cache_settings_maximum_ttl"]}', 2
        )
        write_indented(f, f'cdn_cache_settings = "{validated_settings["cdn_cache_settings"]}"', 2)
        write_indented(
            f, f'cdn_cache_settings_maximum_ttl = {validated_settings["cdn_cache_settings_maximum_ttl"]}', 2
        )
        write_indented(f, f'adaptive_delivery_action = "{validated_settings["adaptive_delivery_action"]}"', 2)
        write_indented(f, f'cache_by_query_string = "{validated_settings["cache_by_query_string"]}"', 2)
        write_indented(f, f'cache_by_cookies = "{validated_settings["cache_by_cookies"]}"', 2)
        write_indented(f, f'enable_stale_cache = {validated_settings["enable_stale_cache"]}', 2)
        write_indented(f, f'is_slice_configuration_enabled = {validated_settings["is_slice_configuration_enabled"]}', 2)
        write_indented(f, f'is_slice_edge_caching_enabled = {validated_settings["is_slice_edge_caching_enabled"]}', 2)
        write_indented(f, f'slice_configuration_range = {validated_settings["slice_configuration_range"]}', 2)
        write_indented(f, "}", 1)
        write_depends_on(f, attributes)
        write_indented(f, "}", 0)
        write_indented(f, "", 0)

        logging.info(f"Cache settings block written for {name}")

    except Exception as e:
        logging.error(f"Error writing cache settings block for {name}: {e}")
        raise


def write_azion_edge_function_block(function_data: Dict[str, Any], resource_name: str) -> str:
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


def write_azion_edge_application_edge_functions_instance_block(f, attributes: Dict[str, Any], main_setting_name: str) -> None:
    """
    Writes the azion_edge_application_edge_functions_instance block.

    Parameters:
        f (file object): The file to write to.
        attributes (dict): Attributes for the azion_edge_application_edge_functions_instance resource.
    """
    results = attributes.get("results", {})
    name = results.get("name")
    edge_function_id = results.get("edge_function_id")
    args = results.get("args")

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


def write_terraform_file(filepath: str, config: Dict[str, Any]) -> None:
    """
    Writes the entire Terraform file based on the Azion configuration.

    Parameters:
        filepath (str): Path to the output Terraform file.
        config (dict): Azion configuration dictionary with resources to be written.
    """
    try:
        resouces = config["resources"]

        with open(filepath, "w", encoding="utf-8") as f:
            # Write variable and provider blocks
            write_variable_block(f)
            write_provider_block(f)

            # Write main setting block
            main_setting = resources_filter_by_type(resouces, "azion_edge_application_main_setting")
            if main_setting:
                write_main_setting_block(f, main_setting[0])

            # Write origin block
            origins = resources_filter_by_type(resouces, "azion_edge_application_origin")
            if origins:
                for origin in origins:
                    write_origin_block(f, origin)
            
            # Write application cache block
            caches = resources_filter_by_type(resouces, "azion_edge_application_cache_setting")
            if caches:
                for cache in caches:
                    write_cache_setting_block(f, cache)

            # Write rules engine block
            rules_engines = resources_filter_by_type(resouces, "azion_edge_application_rule_engine")
            if rules_engines:
                for rule_engine in rules_engines:
                    write_rule_engine_block(f, rule_engine)

            # Write edge function block
            edge_functions = resources_filter_by_type(resouces, "azion_edge_function")
            if edge_functions:
                for edge_function in edge_functions:
                    write_azion_edge_function_block(f, edge_function)

            # Write main setting block
            domains = resources_filter_by_type(resouces, "azion_domain")
            if domains:
                for domain in domains:
                    write_domain_block(f, domain)

            logging.info(f"Terraform file successfully written to {filepath}")
    except ValueError as e:
        logging.error(f"Error writing Terraform file: {e}")
        raise
