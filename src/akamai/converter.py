import logging
from typing import Dict, List, Any, Optional
from azion_resources import AzionResource
from utils import clean_and_parse_json
from akamai.mapping import MAPPING
from akamai.converter_domain import create_domain
from akamai.converter_main_settings import create_main_setting
from akamai.converter_origin import create_origin
from akamai.converter_waf import create_waf_rule
from akamai.converter_cache_settings import create_cache_setting   
from akamai.converter_digital_certificate import create_digital_certificate
from akamai.converter_edge_function import create_edge_function
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
                    #azion_resources.extend(converted_resources)
                    #print(f'>>>> DEBUG: {azion_resources.get_azion_resources()}')
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
        if resource["type"] == "azion_edge_application_origin":
            origin = resource["attributes"]["origin"]
            if origin["addresses"][0]["address"] == "placeholder.example.com":
                origin["addresses"][0]["address"] = origin_hostname
                logging.info("Updated origin address with extracted edge_hostname.")

        # Enable main_settings -> edge_functions
        if resource["type"] == "edge_functions":
            logging.info(f"Enabling 'edge_functions' in azion_edge_application_main_setting")
            main_setting_attributes = resource.get("azion_edge_application_main_setting", False)
            if not main_setting_attributes:
                main_setting_attributes["edge_functions"] = True

         # Enable main_settings -> caching
        if resource["type"] == "caching":
            logging.info(f"Enabling 'caching' in azion_edge_application_main_setting")
            main_setting_attributes = resource.get("azion_edge_application_main_setting", False)
            if not main_setting_attributes:
                main_setting_attributes["caching"] = True

    logging.info(f"Finished processing resources. Total Azion resources generated: {azion_resources.len()}")


def convert_akamai_to_azion(azion_resources: AzionResource, attributes: Dict[str, Any], main_setting_name: str, edge_hostname: str, origin_hostname: str):
    """
    Converts Akamai property to Azion resources, including handling rules of different formats.

    Parameters:
        attributes (dict): Akamai property attributes.
        main_setting_name (str): Main setting name for Azion.
        edge_hostname (str): The edge hostname extracted from Akamai configuration.

    Returns:
        List[Dict[str, Any]]: A list of Azion resources.
    """
    logging.info(f"Converting Akamai property: {attributes.get('name', 'Unknown')} to Azion format.")

    try:
        # Create Main Setting, Origin, and Domain resources
        azion_resources.append(create_main_setting(azion_resources, attributes, main_setting_name))
        azion_resources.append(create_origin(azion_resources, attributes, main_setting_name, origin_hostname))
        azion_resources.append(create_domain(azion_resources, attributes, main_setting_name))

        #print(f'DEBUG: AAAA {azion_resources.get_azion_resources()}')
        logging.info("Main setting, origin, and domain resources created.")
    except Exception as e:
        logging.error(f"Error creating main resources: {e}")
        raise

    # Process rules if they exist
    rules = attributes.get("rules", {})

    if isinstance(rules, str):
        # Handle string references to rules (potential external configuration)
        logging.warning(f"Rules attribute is a string reference. Converting to JSON content.")
        rules = clean_and_parse_json(rules).get("rules", {})
    
    if isinstance(rules, dict):
        # Handle structured rule sets
        children = rules.get("children", [])
        if children:
            # Cache Settings
            for index, rule in enumerate(children):
                try:
                    cache_setting = create_cache_setting(azion_resources, rule, main_setting_name)
                    if cache_setting:
                        logging.info(f"Cache setting created for rule: {rule.get('name', 'Unnamed Rule')}")
                        azion_resources.append(cache_setting)
                    #print(f'DEBUG: BBBB {azion_resources.get_azion_resources()}')
                except KeyError as e:
                    logging.error(f"Missing expected key in rule {rule.get('name', 'Unnamed Rule')}: {e}")
                except TypeError as e:
                    logging.error(f"Type error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
                except ValueError as e:
                    logging.error(f"Error creating cache setting for rule {rule.get('name', 'Unnamed Rule')}: {e}")

            # Rules Engine
            for index, rule in enumerate(children):
                try:
                    logging.info(f"Processing rule: {rule.get('name', 'Unnamed Rule')}")
                    azion_resources.extend(create_rule_engine(azion_resources, rule, main_setting_name, index))
                    #print(f'DEBUG: CCCC {azion_resources.get_azion_resources()}')
                except KeyError as e:
                    logging.error(f"Missing expected key in rule {rule.get('name', 'Unnamed Rule')}: {e}")
                except TypeError as e:
                    logging.error(f"Type error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
                except ValueError as e:
                    logging.error(f"Value error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
        else:
            logging.warning("No children rules found in rules attribute.")
    elif isinstance(rules, list):
        # Handle cases where rules are provided as a list
        logging.info("Rules provided as a list. Processing each rule.")
        # Cache settings
        for index, rule in enumerate(rules):
            try:
                cache_setting = create_cache_setting(azion_resources, rule, main_setting_name)
                if cache_setting:
                    logging.info(f"Cache setting created for rule: {rule.get('name', 'Unnamed Rule')}")
                    azion_resources.append(cache_setting)
            except KeyError as e:
                logging.error(f"Missing expected key in rule {rule.get('name', 'Unnamed Rule')}: {e}")
            except TypeError as e:
                logging.error(f"Type error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
            except ValueError as e:
                logging.error(f"Error creating cache setting for rule {rule.get('name', 'Unnamed Rule')}: {e}")

        #Rules Engine
        for index, rule in enumerate(rules):
            try:
                logging.info(f"Processing rule: {rule.get('name', 'Unnamed Rule')}")
                azion_resources.extend(create_rule_engine(azion_resources, rule, f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id", index))
            except KeyError as e:
                logging.error(f"Missing expected key in rule {rule.get('name', 'Unnamed Rule')}: {e}")
            except TypeError as e:
                logging.error(f"Type error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
            except ValueError as e:
                logging.error(f"Value error in rule {rule.get('name', 'Unnamed Rule')}: {e}")
    else:
        logging.warning(f"Unexpected type for rules: {type(rules)}. Skipping rule processing.")

    # Add WAF rules if available
    try:
        waf_rule = create_waf_rule(azion_resources, attributes)
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

    #return azion_resources
