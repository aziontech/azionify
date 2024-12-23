import logging
from typing import Dict, Any, List
from azion_resources import AzionResource
from utils import clean_and_parse_json, sanitize_name
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
    _, global_settings = azion_resources.query_azion_resource_by_type('global_settings')
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
        behaviors = rules.get("behaviors", [])
        if behaviors:
            logging.info("Processing behaviors rules.")
            process_behaviors(azion_resources, rules, main_setting_name, origin_hostname)

        children = rules.get("children", [])
        if children:
            logging.info("Processing children rules.")
            process_children(azion_resources, children, main_setting_name, origin_hostname)
    
    elif isinstance(rules, list):
        logging.info("Rules provided as a list. Processing each rule.")
        process_children(azion_resources, rules, main_setting_name, origin_hostname)
    
    else:
        logging.warning(f"Unexpected type for rules: {type(rules)}. Skipping rule processing.")


def process_behaviors(azion_resources: AzionResource, rule: Dict[str, Any], main_setting_name: str, origin_hostname: str):
    """
    Processes the list of behaviors rules and converts them into Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        rule (Dict[str, Any]): The Akamai rule to process.
        main_setting_name (str): The main setting name for Azion configuration.
        origin_hostname (str): The origin hostname for Azion configuration.
    """
    behaviors = rule.get("behaviors", None)
    if behaviors is None:
        logging.warning("No behaviors found in rules. Skipping rule processing.")
        return

    cache_setting = []
    for behavior in behaviors:
        if behavior.get("name") == "caching":
            cache_setting.append(behavior) # Cache Settings
        elif behavior.get("name") == "cacheError":
            cache_setting.append(behavior) # Cache Settings
        elif behavior.get("name") == "webApplicationFirewall":
            process_waf_behavior(azion_resources, behavior) # WAF Settings
        elif behavior.get("name") == "allowPost":
            idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
            if main_settings:
                resources = azion_resources.get_azion_resources()
                main_settings["attributes"]["edge_application"]["application_acceleration"] = True
                resources[idx] = main_settings
        elif behavior.get("name") == "origin":
            origin = create_origin(azion_resources, behavior, main_setting_name, origin_hostname, rule.get("name"))
            if origin:
                azion_resources.append(origin)

    # Cache Settings
    cache_setting = create_cache_setting(azion_resources, cache_setting, main_setting_name, rule.get("name"))
    if cache_setting:
        azion_resources.append(cache_setting)

        idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
        if main_settings is None:
            logging.error("Missing azion_edge_application_main_setting in resource. Conversion aborted.")
            return
        main_settings["attributes"]["edge_application"]["caching"] = True
        resources = azion_resources.get_azion_resources()
        resources[idx] = main_settings


    # Post Behaviors
    #process_post_behavior(azion_resources, behavior, main_setting_name, origin_hostname)


def process_children(azion_resources: AzionResource, children: List[Dict[str, Any]], main_setting_name: str, origin_hostname: str):
    """
    Processes the list of children rules and converts them into Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        children (List[Dict[str, Any]]): The list of Akamai children rules.
        main_setting_name (str): The main setting name for Azion configuration.
    """
    # Rules Processing
    for index, rule in enumerate(children):
        rule_name = rule.get("name", "Unnamed Rule")
        #print(f'$$$-----> DEBUG: children rule {rule_name}')
        try:
            behaviors = rule.get("behaviors", [])
            for behavior in behaviors:
                #print(f'$$$-----> DEBUG: children rule {rule_name} behavior {behavior.get("name")}')
                if behavior.get("name") == "caching":
                    cache_setting = create_cache_setting(azion_resources, behaviors, main_setting_name, rule_name)
                    if cache_setting:
                        logging.info(f"Cache setting created for rule: {rule_name}")
                        azion_resources.append(cache_setting)

                if behavior.get("name") == "imageManager":
                    idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
                    if main_settings:
                        main_settings["attributes"]["edge_application"]["image_optimization"] = True
                        resources = azion_resources.get_azion_resources()
                        resources[idx] = main_settings

                if behavior.get("name") == "allowPost":
                    #print(f'$$$-----> DEBUG: behavior {behavior}')
                    idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
                    if main_settings:
                        resources = azion_resources.get_azion_resources()
                        main_settings["attributes"]["edge_application"]["application_acceleration"] = True
                        resources[idx] = main_settings

                if behavior.get("name") == "origin":
                    origin_setting = create_origin(azion_resources, behaviors[0], main_setting_name, origin_hostname, sanitize_name(rule_name))
                    if origin_setting:
                        logging.info(f"Origin setting created for rule: {rule_name}")
                        azion_resources.append(origin_setting)

                if behavior.get("name") == "webApplicationFirewall":
                    waf_rule = create_waf_rule(azion_resources, behavior)
                    if waf_rule:
                        logging.info(f"WAF rule created for rule: {rule_name}")
                        azion_resources.append(waf_rule)

                if behavior.get("name") == "baseDirectory":
                    idx, origin = azion_resources.query_azion_resource_by_type('azion_edge_application_origin', sanitize_name(rule_name))
                    if origin:
                        origin["attributes"]["origin"]["origin_path"] = behavior.get("options", {}).get("value", "")
                        resources = azion_resources.get_azion_resources()
                        resources[idx] = origin

                azion_resources.extend(create_rule_engine(azion_resources, rule, main_setting_name, index))

            

            children = rule.get("children", [])
            if children:
                logging.info(f"Rule '{rule_name}' has {len(children)} child rules. Delegating to process_children.")
                process_children(azion_resources, children, main_setting_name, origin_hostname)
                continue

        except ValueError as e:
            logging.error(f"Error processing rule engine for rule {rule_name}: {e}")


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
        azion_resources.append(create_domain(azion_resources, attributes, main_setting_name))
        logging.info("Main setting, origin, and domain resources created.")
    except Exception as e:
        logging.error(f"Error creating main resources: {e}")
        raise

def process_waf_behavior(azion_resources: AzionResource, attributes: Dict[str, Any]):
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

    logging.info(f"Completed conversion for Akamai property: {attributes.get('name', 'Unknown')}")

