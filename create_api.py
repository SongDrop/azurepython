import os
import random
import string
import time
from datetime import datetime
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.dns import DnsManagementClient
from dotenv import load_dotenv

load_dotenv()

API_GITHUB = "https://github.com/SongDrop/rtxapi"

# Console colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_info(msg):
    print(f"{bcolors.OKBLUE}[INFO]{bcolors.ENDC} {msg}")

def print_success(msg):
    print(f"{bcolors.OKGREEN}[SUCCESS]{bcolors.ENDC} {msg}")

def print_warn(msg):
    print(f"{bcolors.WARNING}[WARNING]{bcolors.ENDC} {msg}")

def print_error(msg):
    print(f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} {msg}")

def get_credentials():
    return ClientSecretCredential(
        tenant_id=os.environ['AZURE_TENANT_ID'],
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET']
    )

async def create_function_app():
    credentials = get_credentials()
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    
    # Generate unique names
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    resource_group = f"funcapp-{rand_suffix}-rg"
    storage_account = f"funcstore{rand_suffix}"
    function_app = f"funcapp-{rand_suffix}"
    location = os.getenv('AZURE_LOCATION', 'uksouth')
    
    # Domain configuration
    domain = os.getenv('DOMAIN_NAME', 'yourdomain.com')
    subdomain = os.getenv('SUBDOMAIN', 'api')
    fqdn = f"{subdomain}.{domain}"

    resource_client = ResourceManagementClient(credentials, subscription_id)
    web_client = WebSiteManagementClient(credentials, subscription_id)
    storage_client = StorageManagementClient(credentials, subscription_id)
    dns_client = DnsManagementClient(credentials, subscription_id)

    try:
        # Create resource group
        print_info(f"Creating resource group: {resource_group}")
        resource_client.resource_groups.create_or_update(
            resource_group,
            {"location": location}
        )

        # Create storage account
        print_info(f"Creating storage account: {storage_account}")
        storage_async = storage_client.storage_accounts.begin_create(
            resource_group,
            storage_account,
            {
                "sku": {"name": "Standard_LRS"},
                "kind": "StorageV2",
                "location": location,
                "enable_https_traffic_only": True
            }
        )
        storage = storage_async.result()

        # Create App Service plan
        plan_name = f"{function_app}-plan"
        print_info(f"Creating App Service plan: {plan_name}")
        web_client.app_service_plans.begin_create_or_update(
            resource_group,
            plan_name,
            {
                "location": location,
                "sku": {"name": "B1", "tier": "Basic"},
                "reserved": True  # For Linux
            }
        ).result()

        # Create Function App
        print_info(f"Creating Function App: {function_app}")
        site_config = {
            "app_settings": [
                {"name": "FUNCTIONS_WORKER_RUNTIME", "value": "python"},
                {"name": "FUNCTIONS_EXTENSION_VERSION", "value": "~4"},
                {"name": "WEBSITE_RUN_FROM_PACKAGE", "value": "1"},
                {"name": "MSCMDLEAK_DETECTION", "value": "full"}
            ],
            "linux_fx_version": "PYTHON|3.9",
            "http20_enabled": True
        }

        function_app = web_client.web_apps.begin_create_or_update(
            resource_group,
            function_app,
            {
                "location": location,
                "server_farm_id": f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Web/serverfarms/{plan_name}",
                "reserved": True,
                "site_config": site_config,
                "https_only": True,
                "host_name_ssl_states": [{
                    "name": fqdn,
                    "ssl_state": "SniEnabled",
                    "host_type": "Standard"
                }]
            }
        ).result()

        print_success(f"Function App created: {function_app.default_host_name}")

        # Configure deployment from GitHub
        print_info("Configuring GitHub deployment")
        source_control = web_client.web_apps.begin_create_or_update_source_control(
            resource_group,
            function_app.name,
            {
                "repo_url": "https://github.com/SongDrop/createvm",
                "branch": "master",
                "is_manual_integration": True,
                "is_mercurial": False
            }
        ).result()

        # Configure custom domain
        print_info(f"Configuring custom domain: {fqdn}")
        hostname_binding = web_client.web_apps.create_or_update_host_name_binding(
            resource_group,
            function_app.name,
            fqdn,
            {
                "site_name": function_app.name,
                "host_name_binding_name": fqdn,
                "ssl_state": "SniEnabled"
            }
        )

        # Get public IP for DNS configuration
        public_ip = web_client.web_apps.get(resource_group, function_app.name).outbound_ip_addresses.split(',')[0]
        
        # Configure DNS
        print_info(f"Creating DNS record: {fqdn} → {public_ip}")
        dns_client.record_sets.create_or_update(
            resource_group,
            domain,
            subdomain,
            "A",
            {
                "ttl": 300,
                "a_records": [{"ipv4_address": public_ip}]
            }
        )

        # Get function keys for authentication
        keys = web_client.web_apps.list_host_keys(resource_group, function_app.name)
        master_key = keys.master_key
        
        print_success("\n" + "="*50)
        print_success("AZURE FUNCTION APP CREATION COMPLETE")
        print_success("="*50)
        print_success(f"Function App Name: {function_app.name}")
        print_success(f"Resource Group: {resource_group}")
        print_success(f"Default URL: https://{function_app.default_host_name}")
        print_success(f"Custom Domain: https://{fqdn}")
        print_success(f"Master Key: {master_key}")
        print_success("Deployment Source: https://github.com/SongDrop/createvm")
        print_success("="*50)

        return {
            "function_app_name": function_app.name,
            "resource_group": resource_group,
            "default_url": function_app.default_host_name,
            "custom_domain": fqdn,
            "master_key": master_key
        }

    except Exception as e:
        print_error(f"Error creating Function App: {str(e)}")
        # Cleanup partially created resources
        try:
            resource_client.resource_groups.begin_delete(resource_group)
            print_warn(f"Deleted resource group: {resource_group}")
        except:
            pass
        raise

if __name__ == "__main__":
    import asyncio
    asyncio.run(create_function_app())