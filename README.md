# Azionify

Azionify is a CLI tool that converts Akamai Terraform configurations into Azion-compatible Terraform configurations. This tool helps streamline the migration process by automating the translation of Akamai's resources to Azion's resources in Terraform.

---

## Features

- Converts Akamai `akamai_property` resources to Azion `azion_edge_application_*` resources.
- Automatically detects the main setting name from the Akamai configuration.
- Outputs Azion-compatible Terraform files with proper dependencies and structure.

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
   pip install -r requirements.txt
   ```

---

## Usage

### Command Line Arguments

| Argument    | Description                                                   | Default       |
|-------------|---------------------------------------------------------------|---------------|
| `--input`   | Path to the Akamai Terraform configuration file.              | `akamai.tf`   |
| `--output`  | Path to the output Azion Terraform configuration file.        | `azion.tf`    |

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

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

For questions or support, feel free to reach out:
- **Email:** support@azion.com

---

### Happy Converting with Azionify! 🎉
