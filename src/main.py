import argparse
import logging
import hcl2
import json
from writer import write_terraform_file
from akamai.akamai import akamai_converter
from typing import Optional, List, Dict, Any

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
    except OSError as e:
        logging.error(f"Error reading Terraform file {filepath}: {e}")
        raise e


def read_function_map(file_path: str) -> Optional[List[Dict[str, Any]]]:
    """
    Read and parse the function mapping file.

    Args:
        file_path (str): Path to the function mapping file.

    Returns:
        Optional[List[Dict[str, Any]]]: List of function mappings or None if file can't be read.
    """
    if not file_path:
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Try to parse as JSON first
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                logging.error(f"Error parsing function mapping file as JSON: {e}")
                return None

    except FileNotFoundError:
        logging.error(f"Function mapping file not found: {file_path}")
        return None
    except OSError as e:
        logging.error(f"Error reading function mapping file: {e}")
        return None


def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments with support for multiple input types.
    """
    parser = argparse.ArgumentParser(
        description="Convert third-party Terraform configurations into Azion Terraform configurations."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the source Terraform configuration file.",
    )
    parser.add_argument(
        "--in-type",
        choices=["akamai"], # Future options: "cloudflare", "fastly"
        default="akamai",
        help="Type of the input Terraform configuration (default: akamai).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output Azion Terraform configuration file.",
    )
    parser.add_argument(
        "--function_map",
        help="Path to the function map file for mapping provider functions to edge functions.",
    )
    return parser.parse_args()


def main():
    """
    Main function to execute the conversion for various providers.
    """
    args = parse_arguments()

    # Dispatch table for provider-specific processing
    provider_dispatch = {
        "akamai": akamai_converter
        #"cloudflare": process_cloudflare,
        #"fastly": process_fastly,
    }

    try:
        # Ensure the input type is supported
        if args.in_type not in provider_dispatch:
            logging.error(f"Unsupported input type: {args.in_type}")
            return

        # Read function mapping if provided
        if args.function_map:
            try:
                function_map = read_function_map(args.function_map)
                if not function_map:
                    logging.error("Failed to read function mapping.")
                    return

                logging.info(f"Loaded function mapping with {len(function_map)} entries")
                # Add function mapping to provider config
                provider_config["function_map"] = function_map
                # Add function mapping to context for behavior processing
                provider_config["context"] = provider_config.get("context", {})
                provider_config["context"]["function_map"] = function_map
            except (json.JSONDecodeError, OSError) as e:
                logging.error(f"Error loading function mapping: {e}")
                return

        # Process the configuration based on the provider
        logging.info(f"Processing {args.in_type} configuration.")
        azion_config = provider_dispatch[args.in_type](provider_config)

        # Write the Azion configuration
        if azion_config.get("resources"):
            logging.info(f"Writing Azion configuration to {args.output}")
            write_terraform_file(args.output, azion_config)
        else:
            logging.warning("No compatible configuration found for conversion.")

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
    except ValueError as e:
        logging.error(f"Invalid configuration format: {e}")

if __name__ == "__main__":
    main()
