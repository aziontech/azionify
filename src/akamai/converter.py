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
def process_resource(azion_resources: AzionResource, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    main_setting_name = global_settings.get("attributes", {}).get("main_setting_name")
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
                    convert_akamai_to_azion(
                        azion_resources, 
                        instance_data,
                        main_setting_name,
                        edge_hostname, 
                        origin_hostname
                    )
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


def process_rules(
        azion_resources: AzionResource,
        rules: Any,
        main_setting_name: str,
        origin_hostname: str
    ) -> List[Dict[str, Any]]:
    """
    Processes Akamai rules (children or list format) and generates the corresponding Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        rules (Any): Akamai rules in string, dict, or list format.
        main_setting_name (str): The main setting name for Azion configuration.
        origin_hostname (str): The origin hostname for Azion configuration.
    """
    context = {}
    if isinstance(rules, str):
        logging.debug("Rules attribute is a string reference. Converting to JSON content.")
        rules = clean_and_parse_json(rules)
        if rules:
            rules = rules.get("rules", {})
        else:
            logging.error("Failed to parse rules or empty rules content.")
            rules = {}

    logging.info("[Akamai Rules] Processing rules starting.")

    if isinstance(rules, dict):
        normalized_name = sanitize_name(rules.get("name", "unnamed_rule"))
        behaviors = rules.get("behaviors", [])
        children = rules.get("children", [])

        logging.info(f"[Akamai Rules] Found {len(behaviors)} behaviors and {len(children)} children for rule: '{normalized_name}'")
    
        if len(behaviors) > 0:
            context = process_rule_behaviors(azion_resources, rules, main_setting_name, origin_hostname, 0, normalized_name)   

        if len(children) > 0:
            process_rule_children(azion_resources, children, main_setting_name, origin_hostname, 0, normalized_name, context)
    
    elif isinstance(rules, list):
        logging.debug("Rules provided as a list. Processing each rule.")
        for index, rule in enumerate(rules):
            normalized_name = sanitize_name(rule.get("name", "unnamed_rule"))
            behaviors = rules.get("behaviors", [])
            children = rules.get("children", [])

            logging.info(f"[Akamai Rules] Found {len(behaviors)} behaviors and {len(children)} children for rule: '{normalized_name}'")

            if behaviors:
                context = process_rule_behaviors(azion_resources, rule, main_setting_name, origin_hostname, index, normalized_name)

            if len(children) > 0:
                process_rule_children(azion_resources, children, main_setting_name, origin_hostname, index, normalized_name, context)
    
    else:
        logging.warning(f"[Akamai Rules] Unexpected type for rules: {type(rules)}. Skipping rule processing.")

    logging.info("[Akamai Rules] Processing rules finished.")


def process_rule_behaviors(
        azion_resources: AzionResource,
        rule: Dict[str, Any],
        main_setting_name: str,
        origin_hostname: str,
        index: int,
        normalized_name: str
    ) -> Dict[str, Any]:
    """
    Processes the list of behaviors rules and converts them into Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        rule (Dict[str, Any]): The Akamai rule to process.
        main_setting_name (str): The main setting name for Azion configuration.
        origin_hostname (str): The origin hostname for Azion configuration.
    """
    behaviors = rule.get("behaviors")
    if behaviors is None:
        logging.warning("[Akamai Rules] No behaviors found in rules. Skipping rule processing.")
        return

    logging.info(f"[Akamai Rules] Processing behaviors for rule '{normalized_name}'.")

    cache_setting = []
    context = {}
    context["parent_rule_index"] = index
    context["parent_rule_name"] = normalized_name
    context["main_setting_name"] = main_setting_name
    context["rule_name"] = rule.get("name")
    context["index"] = index
    

    for behavior in behaviors:
        behavior_name = behavior.get("name")

        if behavior_name == "origin": # Origin
            origin = create_origin(azion_resources, behavior, main_setting_name, origin_hostname, context["rule_name"])
            if origin:
                azion_resources.append(origin)
                context["origin"] = origin
        elif behavior_name == "caching": # Cache Settings
            cache_setting.append(behavior) 
            cache_setting = create_cache_setting(azion_resources, cache_setting, main_setting_name, context["rule_name"], context)
            if cache_setting:
                azion_resources.append(cache_setting)
                context["cache_setting"] = cache_setting

                index_main_settings, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
                if main_settings:
                    main_settings["attributes"]["edge_application"]["caching"] = True
                    resources = azion_resources.get_azion_resources()
                    resources[index_main_settings] = main_settings
        
        elif behavior_name == "webApplicationFirewall":
            process_waf_behavior(azion_resources, behavior) # WAF Settings
        elif behavior_name == "allowPost": # Application Acceleration
            index_main_settings, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
            if main_settings:
                resources = azion_resources.get_azion_resources()
                main_settings["attributes"]["edge_application"]["application_acceleration"] = True
                resources[index_main_settings] = main_settings

    azion_resources.extend(create_rule_engine(azion_resources, rule, context, context["rule_name"]))

    logging.info(f"[Akamai Rules] Processing behaviors for rules '{normalized_name}'. Finished.")
    return context


def process_rule_children(
        azion_resources: AzionResource,
        children: List[Dict[str, Any]],
        main_setting_name: str,
        origin_hostname: str,
        parent_rule_index: int,
        parent_rule_name: str,
        parent_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
    """
    Processes the list of children rules and converts them into Azion resources.
    
    Parameters:
        azion_resources (AzionResource): The list of Azion resources to append converted resources.
        children (List[Dict[str, Any]]): The list of Akamai children rules.
        main_setting_name (str): The main setting name for Azion configuration.
        origin_hostname (str): The origin hostname for Azion configuration.
        parent_rule_index (int): The index of the parent rule.
        parent_rule_name (str): The name of the parent rule.
    """
    child_priority_multiplier = 100
    logging.info(f"[Akamai Rules] Processing {len(children)} children rules from rule '{parent_rule_name}'.")

    context = {}
    context["parent_rule_index"] = parent_rule_index
    context["parent_rule_name"] = parent_rule_name
    context["parent_context"] = parent_context
    context["main_setting_name"] = main_setting_name 

    # Rules Processing
    for index, rule in enumerate(children):
        rule_name = rule.get("name", "Unnamed Rule")
        child_index = (parent_rule_index * child_priority_multiplier) + index
        context["rule_name"] = rule_name
        context["rule_index"] = child_index

        logging.info(
            f"[Akamai Rules][Children] Rule name: '{rule_name}', "
            f"parent rule: '{parent_rule_name}', "
            f"parent_index: {parent_rule_index}, "
            f"index: {child_index}"
        )
        try:
            behaviors = rule.get("behaviors", [])
            for behavior in behaviors:
                behavior_name = behavior.get("name")
                if behavior_name == "origin":
                    origin_setting = create_origin(azion_resources, behavior, main_setting_name, origin_hostname, sanitize_name(rule_name))
                    if origin_setting:
                        logging.info(f"Origin setting created for rule: {rule_name}")
                        azion_resources.append(origin_setting)
                        context["origin"] = origin_setting

                elif behavior_name == "caching":
                    cache_setting = create_cache_setting(azion_resources, behaviors, main_setting_name, rule_name, context)
                    if cache_setting:
                        logging.info(f"[Akamai Rules][Children] Cache setting created for rule: {rule_name}")
                        azion_resources.append(cache_setting)
                        context["cache_setting"] = cache_setting

                elif behavior.get("name") == "imageManager":
                    idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
                    if main_settings:
                        main_settings["attributes"]["edge_application"]["image_optimization"] = True
                        resources = azion_resources.get_azion_resources()
                        resources[idx] = main_settings

                elif behavior.get("name") == "allowPost":
                    idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
                    if main_settings:
                        resources = azion_resources.get_azion_resources()
                        main_settings["attributes"]["edge_application"]["application_acceleration"] = True
                        resources[idx] = main_settings

                elif behavior.get("name") == "webApplicationFirewall":
                    waf_rule = create_waf_rule(azion_resources, behavior)
                    if waf_rule:
                        logging.info(f"WAF rule created for rule: {rule_name}")
                        azion_resources.append(waf_rule)
                        context["waf"] = waf_rule

                elif behavior.get("name") == "baseDirectory":
                    idx, origin = azion_resources.query_azion_resource_by_type('azion_edge_application_origin', sanitize_name(rule_name))
                    if origin:
                        origin["attributes"]["origin"]["origin_path"] = behavior.get("options", {}).get("value", "")
                        resources = azion_resources.get_azion_resources()
                        resources[idx] = origin

            azion_resources.extend(create_rule_engine(azion_resources, rule, context, rule_name))

            # Child Rules
            children = rule.get("children", [])
            if len(children) > 0:
                logging.info(f"[Akamai Rules][Children] Rule '{rule_name}' has {len(children)} inner children rules. Processing...")
                process_rule_children(azion_resources, children, main_setting_name, origin_hostname, index, rule_name, context)

        except ValueError as e:
            logging.error(f"[Akamai Rules][Children] Error processing rule engine for rule {rule_name}: {e}")

    logging.info(f"[Akamai Rules][Children] Processing children rules from rule '{parent_rule_name}'. Finished.")


def create_main_resources(
        azion_resources: AzionResource,
        attributes: Dict[str, Any],
        main_setting_name: str,
        origin_hostname: str
    ) -> List[Dict[str, Any]]:
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


def process_waf_behavior(azion_resources: AzionResource, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def convert_akamai_to_azion(
        azion_resources: AzionResource,
        attributes: Dict[str, Any],
        main_setting_name: str,
        edge_hostname: str,
        origin_hostname: str
    ) -> List[Dict[str, Any]]:
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
