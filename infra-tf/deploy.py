import argparse

# Define the environments
environments = [
    {
        "env_type": "non-prod",
        "env_name": "dev-02",
        "account_id": "637423201724",
        "regions": ["us-west-2"]
    },
    {
        "env_type": "non-prod",
        "env_name": "stage-01",
        "account_id": "180294189461",
        "regions": ["us-west-2"]
    },
    {
        "env_type": "non-prod",
        "env_name": "research-dev-01",
        "account_id": "533267097767",
        "regions": ["us-west-2"]
    },
    {
        "env_type": "non-prod",
        "env_name": "dev-01",
        "account_id": "211125324484",
        "regions": ["us-west-2"]
    }
]

def process_environments(env_list, env_type_filter=None, env_name_filter=None, region_filter=None):
    env_details = []
    for env in env_list:
        if env_type_filter and env['env_type'] != env_type_filter:
            continue
        if env_name_filter and env['env_name'] != env_name_filter:
            continue
        for region in env['regions']:
            if region_filter and region != region_filter:
                continue
            detail = f"{env['env_type']} {env['env_name']} {env['account_id']} {region}"
            env_details.append(detail)
            print(detail)
    return env_details

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process environment details.')
    parser.add_argument('--env_type', type=str,required=True, help='Filter by environment type (e.g., non-prod, prod)')
    parser.add_argument('--env_name', type=str, help='Filter by environment name (e.g., dev)')
    parser.add_argument('--region', type=str, help='Filter by region (e.g., us-west-2)')
    args = parser.parse_args()
    
    process_environments(environments, args.env_type, args.env_name, args.region)
