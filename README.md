# Azionify

Azionify is a flexible CLI tool designed to convert Terraform configurations from various CDNs into Azion-compatible Terraform configurations. This tool helps streamline migration processes by automating the translation of CDN-specific resources into Azion's Terraform resources.

---

## Features

- Multi-CDN Support: Currently supports Akamai and allows easy extension for other CDNs in the future.
- Resource Conversion: Converts CDN-specific Terraform resources (e.g., akamai_property) into Azion-compatible resources (azion_edge_application_*).
- Dependency Management: Automatically detects and generates proper dependencies in Terraform files.
- Customizable Input: Specify input CDN type for flexibility in migrations.

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-repo/azionify.git
   ```

2. Navigate to the project directory:
   ```bash
   cd azionify
   ```

3. Install the required dependencies:
   ```bash
   python -m venv env
   source env/bin/activate
   pip install -r requirements.txt
   ```

---

## Usage

### Command Line Arguments

| Argument    | Description                                                   | Default       |
|-------------|---------------------------------------------------------------|---------------|
| `--input`   | Path to the Akamai Terraform configuration file.              | `akamai.tf`   |
| `--output`  | Path to the output Azion Terraform configuration file.        | `azion.tf`    |
| `--in-type` | Specifies the CDN type of the input file (e.g., akamai).      | `akamai`      |

### Examples

#### Default Configuration
If you have a file named `akamai.tf` in your working directory and want to generate `azion.tf`:
```bash
python src/main.py
```

#### Custom Input and Output
Specify custom input and output files:
```bash
python src/main.py --input custom_akamai.tf --output custom_azion.tf
```

#### Output
The tool will generate an Azion-compatible Terraform configuration file at the specified output path.

---

### Extending for Additional CDNs
Azionify is modular by design. You can add new CDN-specific conversion logic by following these steps:

Create a New Converter: Add a new converter module under src/<cdn>/converter.py.
Example:
```bash
src/cloudflare/converter.py
```

Implement Resource Mapping: Define the resource mappings and conversion logic similar to the existing Akamai converter.

Register the New Converter: Update main.py to include the new CDN under the `--in-type` argument.

Run the Tool: Use the `--in-type` parameter to select the new CDN.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

For questions or support, feel free to reach out:
- **Email:** support@azion.com

---

### Happy Converting with Azionify! 🎉


## PAssar a faca no xml com aspas = CONF AMAZONIA

# Substituir \. por  ^ no BLOG

# python src/main.py --input  --output

# o criteria requestHeader
# com headerName
