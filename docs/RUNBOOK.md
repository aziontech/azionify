# Runbook — Azionify

## Service Overview

- **What**: CLI tool to convert CDN Terraform configs (Akamai) to Azion Terraform resources
- **Owner**: Data Routing (`@aziontech/team-data-routing`)
- **Type**: Developer tool (not a running service)
- **License**: MIT (public repository)

## Common Scenarios

### 1. Basic conversion

```bash
# Install dependencies
pip install -r requirements.txt

# Convert Akamai config to Azion
python src/main.py \
  --input akamai_config.tf \
  --output azion_config.tf \
  --in-type akamai
```

### 2. Conversion with function map

When Akamai edge functions need to be mapped to Azion function IDs:

```bash
python src/main.py \
  --input akamai_config.tf \
  --output azion_config.tf \
  --function_map function_map.json
```

Function map format:
```json
[
  {
    "policy_id": "148213",
    "behavior_name": "edgeRedirector",
    "function_id": "54321",
    "args": [{"matchURL": "...", "redirectURL": "...", "statusCode": 301}]
  }
]
```

### 3. Preview environment conversion

```bash
python src/main.py \
  --input akamai_config.tf \
  --output azion_config_preview.tf \
  --environment preview
```

This appends `-preview` suffix to domain names for non-production deployments.

### 4. Conversion output has missing values

**Symptom**: Generated Terraform has `null` or placeholder values.

**Common causes**:
- **Digital certificates**: Currently mapped to `null` (Azion auto SAN). Manual mapping required for CPS-managed certificates.
- **Edge function code**: Shows "TBD" placeholder. Implement the function code manually.
- **Function map missing**: If Akamai uses edge functions, provide `--function_map` argument.

### 5. Rule conversion produces unexpected results

**Diagnosis**:
1. Check logs for WARNING messages about fallback values
2. Review the operator mapping in `src/akamai/utils.py`
3. Check if the Akamai behavior type is mapped in `src/akamai/mapping.py`

**Resolution**:
- Add missing behavior mappings to `mapping.py`
- Check criteria operator conversion in `OPERATOR_MAP`
- Review rule ordering (request phase vs response phase separation)

### 6. Applying converted Terraform

```bash
# After conversion
cd output_directory

# Initialize Terraform with Azion provider
terraform init

# Preview changes
terraform plan -var="azion_api_token=YOUR_TOKEN"

# Apply
terraform apply -var="azion_api_token=YOUR_TOKEN"
```

## Extending for New CDN Providers

1. Create `src/<provider>/` directory with converter modules
2. Implement the main orchestrator following `src/akamai/akamai.py` pattern
3. Add provider to dispatch dict in `src/main.py`
4. Add `--in-type` choice to argument parser

## Escalation

| Situation | Contact |
|-----------|---------|
| Conversion issues | `@aziontech/team-data-routing` |
| Azion Terraform provider | Edge team |
| Akamai-specific questions | Solutions Architecture |
