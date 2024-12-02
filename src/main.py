import argparse
import logging
import hcl2
from converter import process_resource
from writer import write_terraform_file
from utils import log_conversion_summary
from typing import  Optional

logging.basicConfig(level=logging.INFO)


def read_terraform_file(filepath: str) -> dict:
    """
    Reads a Terraform configuration file and parses it into a dictionary.

    Parameters:
        filepath (str): Path to the Terraform configuration file.

    Returns:
        dict: Parsed Terraform configuration.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            logging.info(f"Reading file: {filepath}")
            return hcl2.load(file)
    except FileNotFoundError as e:
        logging.error(f"File not found: {filepath}")
        raise e
    except ValueError as e:  # Capture parsing errors
        logging.error(f"Failed to parse HCL content in {filepath}: {e}")
        raise e
    except Exception as e:
        logging.error(f"Unexpected error reading Terraform file {filepath}: {e}")
        raise e


def get_main_setting_name(akamai_config: dict) -> str:
    """
    Deduces the main setting name from the Akamai configuration.
    """
    try:
        resources = akamai_config.get("resource", [])
        if not resources:
            logging.warning("No resources found in Akamai configuration.")
            return "default_main_setting"

        for resource in resources:
            if "akamai_property" in resource:
                akamai_property = resource["akamai_property"]
                for instance_name, instance_data in akamai_property.items():
                    property_name = instance_data.get("name", "default_main_setting")
                    logging.info(f"Found Akamai property: {property_name}")
                    return property_name.replace(" ", "_").lower()

        logging.warning("No Akamai property found in resources.")
        return "default_main_setting"
    except KeyError as e:
        logging.error(f"KeyError while deducing main setting name: {e}")
        return "default_main_setting"
    except TypeError as e:
        logging.error(f"TypeError while processing Akamai configuration: {e}")
        return "default_main_setting"
    except ValueError as e:
        logging.error(f"Unexpected error while deducing main setting name: {e}")
        return "default_main_setting"

def extract_edge_hostname(akamai_config: dict) -> Optional[str]:
    """
    Extracts the edge hostname from Akamai configuration.

    Parameters:
        akamai_config (dict): Parsed Akamai Terraform configuration.

    Returns:
        str: Extracted edge hostname or None if not found.
    """
    for resource in akamai_config.get("resource", []):
        if "akamai_edge_hostname" in resource:
            hostname_data = resource["akamai_edge_hostname"]
            if isinstance(hostname_data, dict):
                for instance_name, instance_data in hostname_data.items():
                    edge_hostname = instance_data.get("edge_hostname")
                    if edge_hostname:
                        logging.info(f"Extracted edge_hostname: {edge_hostname}")
                        return edge_hostname
    logging.warning("Edge hostname not found in Akamai configuration.")
    return None


def generate_azion_config(akamai_config: dict, main_setting_name: str) -> dict:
    """
    Converts Akamai configuration to Azion-compatible configuration.
    """
    azion_resources = []
    try:
        # Step 1: Extract edge_hostname
        edge_hostname = extract_edge_hostname(akamai_config)
        if not edge_hostname:
            logging.warning("Edge hostname not found. Using placeholder as fallback.")
            edge_hostname = "placeholder.example.com"

        logging.info(f"Edge hostname extracted: {edge_hostname}")
        
        # Step 2: Process resources
        for resource in akamai_config.get("resource", []):
            azion_resources.extend(process_resource(resource, main_setting_name, edge_hostname))
    except Exception as e:
        logging.error(f"Error processing resource: {e}")
        raise

    # Log a summary of the generated resources
    log_conversion_summary(azion_resources)

    return {"resources": azion_resources}


def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Convert Akamai Terraform configurations into Azion Terraform configurations."
    )
    parser.add_argument(
        "--input",
        default="akamai.tf",
        help="Path to the source Akamai Terraform configuration file (default: akamai.tf).",
    )
    parser.add_argument(
        "--output",
        default="azion.tf",
        help="Path to the output Azion Terraform configuration file (default: azion.tf).",
    )
    return parser.parse_args()


def main():
    """
    Main function to execute the conversion.
    """
    args = parse_arguments()

    try:
        # Read Akamai configuration
        akamai_config = read_terraform_file(args.input)
        logging.info("Successfully read Akamai configuration.")

        # Deduce the main setting name
        main_setting_name = get_main_setting_name(akamai_config)
        logging.info(f"Main setting name deduced: {main_setting_name}")

        # Convert Akamai configuration to Azion
        azion_config = generate_azion_config(akamai_config, main_setting_name)

        # Write Azion configuration
        if azion_config["resources"]:
            write_terraform_file(args.output, azion_config, main_setting_name)
            logging.info(f"Terraform configuration written to {args.output}")
        else:
            logging.warning("No compatible configuration found for conversion.")

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
    except ValueError as e:
        logging.error(f"Invalid configuration format: {e}")
    except KeyError as e:
        logging.error(f"Missing expected configuration key: {e}")


if __name__ == "__main__":
    main()
