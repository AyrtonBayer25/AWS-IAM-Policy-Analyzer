import json
import argparse

def parse_args():
    """Parse command-line arguments for policy file input."""
    parser = argparse.ArgumentParser(description='AWS IAM Policy Analyzer - Checks for over-privileged policies.')
    parser.add_argument('--file', type=str, default=None, help='JSON file path for policy data (default: use mock).')
    return parser.parse_args()

def load_policy(file_path):
    """Load IAM policy from file or use mock if no file provided."""
    # Check if file path is provided; if yes, load from file, else use mock
    if file_path:
        with open(file_path, 'r') as f:
            return json.load(f)
    else:
        # Use mock policy if no file
        return {
            'PolicyName': 'AdminPolicy',
            'Document': {
                'Statement': [
                    {'Effect': 'Allow', 'Action': '*', 'Resource': '*'},
                    {'Effect': 'Deny', 'Action': 's3:DeleteBucket'}
                ]
            }
        }

def analyze_policy(policy):
    """Analyze policy statements for over-privileged access (e.g., wildcards)."""
    flags = []
    try:
        for stmt in policy['Document']['Statement']:
            actions = stmt['Action'] if isinstance(stmt['Action'], list) else [stmt['Action']]
            # If effect is Allow and actions include wildcard, flag as over-privileged
            if stmt['Effect'] == 'Allow' and '*' in actions:
                flags.append(f"OVER-PRIVILEGED: {policy['PolicyName']} (Wildcard in Allow statement - Risk of excessive access)")
    except KeyError as e:
        print(f"Error: Missing key {e} in policy.")
    return flags

if __name__ == "__main__":
    args = parse_args()
    policy_data = load_policy(args.file)  # Load policy, renamed to avoid shadowing
    policy_flags = analyze_policy(policy_data)  # Analyze, renamed to avoid shadowing
    # If flags exist, print them; else, print no issues
    if policy_flags:
        for flag in policy_flags:
            print(flag)
    else:
        print("No over-privileged issues found.")