# Azionify

Azionify is a flexible CLI tool designed to convert Terraform configurations from various CDNs into Azion-compatible Terraform configurations. This tool helps streamline migration processes by automating the translation of CDN-specific resources into Azion's Terraform resources.

---

## Features

- Multi-CDN Support: Currently supports Akamai and allows easy extension for other CDNs in the future.
- Resource Conversion: Converts CDN-specific Terraform resources (e.g., akamai_property) into Azion-compatible resources (azion_edge_application_*).
- Dependency Management: Automatically detects and generates proper dependencies in Terraform files.
- Customizable Input: Specify input CDN type for flexibility in migrations.
- Function Mapping: Map provider-specific functions to Azion edge functions using a JSON configuration file.
- Environment Support: Generate configurations for different environments (production or preview).

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

| Argument         | Description                                                        | Required | Default       |
|------------------|--------------------------------------------------------------------|----------|---------------|
| `--input`        | Path to the source Terraform configuration file.                   | Yes      | -             |
| `--output`       | Path to the output Azion Terraform configuration file.             | Yes      | -             |
| `--in-type`      | Specifies the CDN type of the input file (e.g., akamai).           | No       | `akamai`      |
| `--function_map` | Path to the function map file for mapping functions to edge functions. | No    | -             |
| `--environment`  | Environment to deploy to (production or preview).                  | No       | `production`  |

### Examples

#### Basic Usage
Convert an Akamai Terraform configuration to Azion format:
```bash
python src/main.py --input akamai_config.tf --output azion_config.tf
```

#### Using Function Map
Map provider-specific functions to Azion edge functions:
```bash
python src/main.py --input akamai_config.tf --output azion_config.tf --function_map function_map.json
```

#### Specifying Environment
Generate configuration for a preview environment:
```bash
python src/main.py --input akamai_config.tf --output azion_config.tf --environment preview
```

#### Complete Example
```bash
python src/main.py --input akamai_config.tf --output azion_config.tf --function_map function_map.json --environment preview
```

### Function Map Format

The function map is a JSON file that maps provider-specific functions to Azion edge functions. This is particularly useful for converting edge behaviors and functions from the source provider to Azion.

Example function map structure:
```json
[
    {
      "policy_id": "148213",
      "behavior_name": "edgeRedirector",
      "function_id": "54321",
      "args": [
        {
          "matchURL": "https://example.com/old-path",
          "redirectURL": "https://example.com/new-path",
          "statusCode": 301
        }
      ]
    }
]
```

Key fields:
- `policy_id`: The ID of the policy in the source provider
- `behavior_name`: The name of the behavior in the source provider (e.g., "edgeRedirector")
- `function_id`: The ID of the corresponding Azion edge function
- `args`: Arguments for the function, which vary depending on the behavior type

### Environment Parameter

The `--environment` parameter affects how domains are configured in the generated Terraform:

- `production` (default): Uses the original domain names without modification
- `preview`: Appends "-preview" to domain names (e.g., "example.com" becomes "example.com-preview")

This is useful for creating separate configurations for different environments while maintaining the same basic structure.

---

### Akamai Converter Modules

Azionify includes several specialized converter modules for Akamai resources, each handling a specific aspect of the migration process:

1. **Main Settings Converter**
   - Converts Akamai property settings to Azion Edge Application main settings
   - Handles configuration for delivery protocols, TLS versions, HTTP/HTTPS ports
   - Sets up basic application features like caching, edge functions, and HTTP3 support

2. **Domain Converter**
   - Transforms Akamai hostname configurations into Azion domains
   - Supports environment-specific domain naming (production/preview)
   - Handles CNAMEs and digital certificate configurations

3. **Origin Converter**
   - Converts Akamai origin configurations to Azion origin settings
   - Handles origin hostnames, ports, and connection settings
   - Supports origin path and header configurations

4. **Cache Settings Converter**
   - Transforms Akamai caching behaviors to Azion cache policies
   - Handles browser cache settings and CDN cache settings
   - Configures TTL (Time-To-Live) values and stale cache behavior

5. **Rules Engine Converter**
   - Converts Akamai rule behaviors and conditions to Azion Rules Engine
   - Handles request and response phase rules
   - Supports complex rule conditions and criteria mapping

6. **Edge Function Instance Converter**
   - Maps Akamai Cloudlet instances to Azion Edge Function instances
   - Handles function arguments and execution triggers

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
