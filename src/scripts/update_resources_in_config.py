import yaml
import sys
from pathlib import Path

def load_config(yaml_file):
    """Load YAML configuration."""
    with open(yaml_file, "r") as file:
        return yaml.safe_load(file)

def save_config(yaml_file, data):
    """Save YAML configuration."""
    with open(yaml_file, "w") as file:
        yaml.dump(data, file, default_flow_style=False)

def print_changes(existing_resources, updated_resources):
    """Print the changes between existing and updated resources."""
    existing_names = {res["name"]: res for res in existing_resources}
    updated_names = {res["name"]: res for res in updated_resources}

    added = [res for name, res in updated_names.items() if name not in existing_names]
    removed = [res for name, res in existing_names.items() if name not in updated_names]
    modified = [
        {"name": name, "existing": existing_names[name], "updated": updated_names[name]}
        for name in existing_names.keys() & updated_names.keys()
        if existing_names[name] != updated_names[name]
    ]

    # Print additions
    if added:
        print("\n[ Additions: ]")
        for res in added:
            print(f"  - Added resource: {res}")

    # Print removals
    if removed:
        print("\n[ Removals: ]")
        for res in removed:
            print(f"  - Removed resource: {res}")

    # Print modifications
    if modified:
        print("\n[ Modifications: ]")
        for change in modified:
            print(f"  - Modified resource '{change['name']}':")
            print(f"    Existing: {change['existing']}")
            print(f"    Updated:  {change['updated']}")

def update_resources(base_config_path, updated_config_path):
    print("[ Loading configurations... ]")
    
    # Load both configurations
    base_config = load_config(base_config_path)
    updated_resources_config = load_config(updated_config_path)
    
    # Check if the `resources` section exists in the base config
    keycloak_config = base_config.get("keycloak", {})
    if "resources" not in keycloak_config:
        print("[ Error: 'resources' section not found in base config. Exiting. ]")
        sys.exit(1)  # Exit the script with an error status code

    # Get the existing resources
    existing_resources = keycloak_config["resources"]
    print(f"[ Info: Current number of resources in base config: {len(existing_resources)} ]")

    # Get the resources from the updated configuration
    updated_resources = updated_resources_config.get("resources", [])
    
    # Check if the updated resources config contains a resources section
    if updated_resources:
        print("[ Info: Comparing existing resources with updated resources... ]")
        print_changes(existing_resources, updated_resources)

        # Replace existing resources with updated resources
        print("[ Info: Replacing existing resources with updated resources. ]")
        keycloak_config["resources"] = updated_resources
    else:
        print("[ Info: No resources found in the updated config. Keeping existing resources. ]")

    # Save the updated configuration back to the base config file
    base_config["keycloak"] = keycloak_config
    save_config(base_config_path, base_config)
    print(f"[ Config updated successfully: {base_config_path} ]")

if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent
    CONFIG_PATH = BASE_DIR / "config.yaml"
    UPDATED_RESOURCES_PATH = BASE_DIR / "endpoints.yaml"

    update_resources(CONFIG_PATH, UPDATED_RESOURCES_PATH)