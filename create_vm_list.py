import os
import sys
from dotenv import load_dotenv
load_dotenv()  # This loads environment variables from a .env file in the current directory
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient

def print_info(msg):
    print(f"[INFO] {msg}")

def print_success(msg):
    print(f"[SUCCESS] {msg}")

def print_error(msg):
    print(f"[ERROR] {msg}")

def prompt_input(prompt, default=None):
    if default:
        prompt_full = f"{prompt} [{default}]: "
    else:
        prompt_full = f"{prompt}: "
    value = input(prompt_full)
    if not value and default:
        return default
    return value

def main():
    # Get inputs
    resource_group = prompt_input("Enter the resource group name","win10dev")
    list_vms_only_str = prompt_input("List only VMs? (yes/no)", "yes").lower()
    list_vms_only = list_vms_only_str in ['yes', 'y', '']

    # Authenticate
    try:
        credentials = ClientSecretCredential(
            client_id=os.environ['AZURE_APP_CLIENT_ID'],
            client_secret=os.environ['AZURE_APP_CLIENT_SECRET'],
            tenant_id=os.environ['AZURE_APP_TENANT_ID']
        )
    except KeyError as e:
        print_error(f"Missing environment variable: {e}")
        sys.exit(1)

    subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')
    if not subscription_id:
        print_error("AZURE_SUBSCRIPTION_ID environment variable is not set.")
        sys.exit(1)

    # Clients
    resource_client = ResourceManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)

    # Check if resource group exists
    try:
        rg = resource_client.resource_groups.get(resource_group)
        print_success(f"Resource group '{resource_group}' found.")
    except Exception as e:
        print_error(f"Resource group '{resource_group}' not found or inaccessible: {e}")
        sys.exit(1)

    if list_vms_only:
        print_info(f"Listing VMs in resource group '{resource_group}':")
        vms = compute_client.virtual_machines.list(resource_group)
        count = 0
        for vm in vms:
            print(f" - VM Name: {vm.name}, Location: {vm.location}, VM Size: {vm.hardware_profile.vm_size}")
            count += 1
        if count == 0:
            print_info("No VMs found in this resource group.")
    else:
        print_info(f"Listing all resources in resource group '{resource_group}':")
        resources = resource_client.resources.list_by_resource_group(resource_group)
        count = 0
        for res in resources:
            print(f" - Name: {res.name}, Type: {res.type}, Location: {res.location}")
            count += 1
        if count == 0:
            print_info("No resources found in this resource group.")

if __name__ == "__main__":
    main()