import hcl2
import logging
import os

def read_terraform_file(filepath: str) -> dict:
    """
    Reads a Terraform Akamai file in HCL format.

    Parameters:
        filepath (str): Path to the Terraform file to be read.

    Returns:
        dict: Parsed Terraform configuration.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is empty, has an invalid extension, or contains invalid HCL content.
        Exception: For any other errors that occur while reading or parsing the file.
    """
    try:
        if not filepath.endswith(".tf"):
            raise ValueError(f"Invalid file extension: {filepath}. Expected a .tf file.")
        
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"The file '{filepath}' does not exist.")
        
        with open(filepath, "r", encoding="utf-8") as f:
            config = hcl2.load(f)
            if not config:
                raise ValueError(f"The file '{filepath}' is empty or does not contain valid HCL content.")
            return config
    except FileNotFoundError as fe:
        logging.error(fe)
        raise
    except ValueError as ve:
        logging.error(ve)
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading the file '{filepath}': {e}")
        raise
