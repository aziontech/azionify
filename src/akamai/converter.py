import logging
from typing import Dict, Any, List
from azion_resources import AzionResource
from utils import clean_and_parse_json
from akamai.converter_domain import create_domain
from akamai.converter_main_settings import create_main_setting
from akamai.converter_origin import create_origin
from akamai.converter_waf import create_waf_rule
from akamai.converter_cache_settings import create_cache_setting
from akamai.converter_rules_engine import create_rule_engine


logging.basicConfig(level=logging.DEBUG)


# Main processing and conversion logic
def process_resource(azion_resources: AzionResource, resource: Dict[str, Any]):
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
 
    # Extract edge_hostname and origin_hostname
    global_settings = azion_resources.query_azion_resource_by_type('global_settings')
    if global_settings is None:
        logging.error("Missing global_settings in resource. Conversion aborted.")
        return []

    # Extract edge_hostname and origin_hostname
    main_setting_name = global_settings.get("attributes", {}).get("main_setting_name", None)
    edge_hostname = global_settings.get("attributes", {}).get("edge_hostname", "")
    origin_hostname = global_settings.get("attributes", {}).get("origin_hostname", "")

    # Validate and process main_setting_name
    if not main_setting_name:
        logging.error("Missing main_setting_name in resource. Conversion aborted.")
        return []

    # Process Akamai properties
    for resource_name, resource_data in resource.items():
        if resource_name == "akamai_property":
            logging.info(f"Found Akamai property: {resource_name}. Processing...")
            for instance_name, instance_data in resource_data.items():
                logging.info(f"Processing Akamai instance: {instance_name}")
                try:
                    convert_akamai_to_azion(azion_resources, 
                                            instance_data,
                                            main_setting_name,
                                            edge_hostname, 
                                            origin_hostname)
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
    for resource in azion_resources.get_azion_resources():
        # Here we call the function to process the post behavior and update resources
        if resource.get("type") == "azion_edge_application_main_setting":
            process_post_behavior(azion_resources, resource, main_setting_name, origin_hostname)


    logging.info(f"Finished processing resources. Total Azion resources generated: {len(azion_resources.get_azion_resources())}")


def process_rules(azion_resources: AzionResource, rules: Any, main_setting_name: str, origin_hostname: str):
    """
    Processes Akamai rules (children or list format) and generates the corresponding Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        rules (Any): Akamai rules in string, dict, or list format.
        main_setting_name (str): The main setting name for Azion configuration.
        origin_hostname (str): The origin hostname for Azion configuration.
    """
    if isinstance(rules, str):
        logging.debug("Rules attribute is a string reference. Converting to JSON content.")
        rules = clean_and_parse_json(rules)
        if rules:
            rules = rules.get("rules", {})
        else:
            logging.error("Failed to parse rules or empty rules content.")
            rules = {}

    if isinstance(rules, dict):
        children = rules.get("children", [])
        if children:
            process_children(azion_resources, children, main_setting_name, origin_hostname)
        else:
        # Process non-children rules
            logging.info("Processing non-children rules directly.")
            # Process rules directly, without 'children'
            for rule in rules.get("behaviors", []):
                if rule.get("name") == "caching":
                    cache_setting = create_cache_setting(azion_resources, rule, main_setting_name)
                    if cache_setting:
                        azion_resources.append(cache_setting)
                # Handle other behaviors similarly
                elif rule.get("name") == "allowPost":
                    process_post_behavior(azion_resources, rule, main_setting_name, origin_hostname)
                # Add further processing for other behaviors here
            logging.warning("No children rules found in rules attribute.")
    
    elif isinstance(rules, list):
        logging.info("Rules provided as a list. Processing each rule.")
        process_children(azion_resources, rules, main_setting_name, origin_hostname)
    
    else:
        logging.warning(f"Unexpected type for rules: {type(rules)}. Skipping rule processing.")


def process_children(azion_resources: AzionResource, children: List[Dict[str, Any]], main_setting_name: str, origin_hostname: str):
    """
    Processes the list of children rules and converts them into Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        children (List[Dict[str, Any]]): The list of Akamai children rules.
        main_setting_name (str): The main setting name for Azion configuration.
    """
    # Cache Settings
    for rule in children:
        try:
            # Cache Settings processing
            if any(behavior.get("name") == "caching" for behavior in rule.get("behaviors", [])):
                cache_setting = create_cache_setting(azion_resources, rule, main_setting_name)
                if cache_setting:
                    logging.info(f"Cache setting created for rule: {rule.get('name', 'Unnamed Rule')}")
                    azion_resources.append(cache_setting)
        except ValueError as e:
            logging.error(f"Error processing cache setting for rule {rule.get('name', 'Unnamed Rule')}: {e}")

        # Post Behaviors
        if any(behavior.get("name") == "allowPost" for behavior in rule.get("behaviors", [])):
            logging.info(f"Processing post behavior for rule: {rule.get('name', 'Unnamed Rule')} with options: {rule.get('options', {})}")
            process_post_behavior(azion_resources, rule, main_setting_name, origin_hostname)

    # Rules Engine
    for index, rule in enumerate(children):
        try:
            logging.info(f"Processing rule: {rule.get('name', 'Unnamed Rule')}")
            azion_resources.extend(create_rule_engine(azion_resources, rule, main_setting_name, index))
        except ValueError as e:
            logging.error(f"Error processing rule engine for rule {rule.get('name', 'Unnamed Rule')}: {e}")

    


def create_main_resources(azion_resources: AzionResource, attributes: Dict[str, Any], main_setting_name: str, origin_hostname: str):
    """
    Creates the main setting, origin, and domain resources.
    
    Parameters:
        azion_resources (AzionResource): The Azion resources to append.
        attributes (dict): The Akamai resource attributes.
        main_setting_name (str): The main setting name for Azion.
        origin_hostname (str): The origin hostname for Azion.

    Returns:
        List[Dict[str, Any]]: A list of Azion resources.
    """
    try:
        azion_resources.append(create_main_setting(azion_resources, attributes, main_setting_name))
        azion_resources.append(create_origin(azion_resources, attributes, main_setting_name, origin_hostname))
        azion_resources.append(create_domain(azion_resources, attributes, main_setting_name))
        logging.info("Main setting, origin, and domain resources created.")
    except Exception as e:
        logging.error(f"Error creating main resources: {e}")
        raise

def add_waf_rule(azion_resources: AzionResource, attributes: Dict[str, Any]):
    """
    Adds WAF rule to Azion resources if available.

    Parameters:
        azion_resources (AzionResource): The Azion resources to append the converted WAF rule.
        attributes (dict): Akamai property attributes to extract WAF rule from.
    """
    try:
        waf_rule = create_waf_rule(azion_resources, attributes)
        if waf_rule and waf_rule not in [resource for resource in azion_resources.get_azion_resources() if resource["type"] == "waf_rule"]:
            logging.info("WAF rule detected and converted.")
            azion_resources.append(waf_rule)
    except ValueError as e:
        logging.error(f"Error processing WAF rule: {e}")


def convert_akamai_to_azion(azion_resources: AzionResource, attributes: Dict[str, Any], main_setting_name: str, edge_hostname: str, origin_hostname: str):
    """
    Converts Akamai property to Azion resources, including handling rules of different formats.

    Parameters:
        attributes (dict): Akamai property attributes.
        main_setting_name (str): Main setting name for Azion.
        edge_hostname (str): The edge hostname extracted from Akamai configuration.
        origin_hostname (str): The origin hostname for Azion configuration.

    Returns:
        List[Dict[str, Any]]: A list of Azion resources.
    """
    logging.info(f"Converting Akamai property: {attributes.get('name', 'Unknown')} to Azion format.")
    
    try:
        # Create Main Setting, Origin, and Domain resources
        create_main_resources(azion_resources, attributes, main_setting_name, origin_hostname)
        logging.info("Main setting, origin, and domain resources created.")
    except ValueError as e:
        logging.error(f"Error creating main resources: {e}")
        raise

    # Process rules
    process_rules(azion_resources, attributes.get("rules", {}), main_setting_name, origin_hostname=origin_hostname)

    # Add WAF rules if available
    add_waf_rule(azion_resources, attributes)

    logging.info(f"Completed conversion for Akamai property: {attributes.get('name', 'Unknown')}")

def process_post_behavior(azion_resources: AzionResource, resource: Dict[str, Any], main_setting_name: str, origin_hostname: str):
    """
    Process behaviors related to `allowPost` and enable relevant settings in Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        resource (Dict[str, Any]): The current Azion resource being processed.
        main_setting_name (str): The main setting name for Azion configuration.
        origin_hostname (str): The origin hostname for Azion configuration.
    """
    # Process 'allowPost' behavior and enable 'application_acceleration'
    behaviors = resource.get("behaviors", [])
    for behavior in behaviors:
        if behavior.get("name") == "allowPost":
            logging.info("Checking 'allowPost' behavior and enabling 'application_acceleration' if necessary.")
            
            # Get current 'application_acceleration' value
            main_setting_attributes = resource.get("azion_edge_application_main_setting", {})
            current_application_acceleration = main_setting_attributes.get("application_acceleration", False)

            # Only update if it's not already enabled
            if not current_application_acceleration:
                logging.info("Enabling 'application_acceleration' in azion_edge_application_main_setting.")
                main_setting_attributes["application_acceleration"] = True
                resource["azion_edge_application_main_setting"] = main_setting_attributes
                logging.info("Enabled 'application_acceleration' in azion_edge_application_main_setting.")
            else:
                logging.info("'application_acceleration' is already enabled, no changes made.")

        # Process other behaviors similarly
        if behavior.get("name") == "caching":
            logging.info("Checking 'caching' behavior and enabling 'caching' if necessary.")
            
            # Get current 'caching' value
            main_setting_attributes = resource.get("azion_edge_application_main_setting", {})
            current_caching = main_setting_attributes.get("caching", False)

            # Only update if it's not already enabled
            if not current_caching:
                logging.info("Enabling 'caching' in azion_edge_application_main_setting.")
                main_setting_attributes["caching"] = True
                resource["azion_edge_application_main_setting"] = main_setting_attributes
                logging.info("Enabled 'caching' in azion_edge_application_main_setting.")
            else:
                logging.info("'caching' is already enabled, no changes made.")

        # Add additional behavior processing as needed for other behaviors, such as 'edge_functions', etc.
    
    # Optionally, process updates to specific resource types, like 'azion_edge_application_origin'
    if resource.get("type") == "azion_edge_application_origin":
        origin = resource["attributes"].get("origin", {})
        current_address = origin.get("addresses", [{}])[0].get("address", "")
        
        if current_address == "placeholder.example.com":
            logging.info("Updating origin address with extracted origin_hostname.")
            origin["addresses"][0]["address"] = origin_hostname
            resource["attributes"]["origin"] = origin
            logging.info("Updated origin address with extracted origin_hostname.")
    
    # If additional behavior types or configurations need to be handled, add them here.
    # For example, enabling other main settings or applying other logic for behaviors.




