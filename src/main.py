import argparse
import logging
import hcl2
from writer import write_terraform_file
from akamai.akamai import akamai_converter

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

        # Read the input configuration
        logging.info(f"Reading {args.in_type} configuration from {args.input}")
        provider_config = read_terraform_file(args.input)

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
    except KeyError as e:
        logging.error(f"Missing expected configuration key: {e}")


if __name__ == "__main__":
    main()
