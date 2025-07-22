
import os
import sys
import time
import webbrowser
from packaging import version  # For semantic version comparison
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute.models import (
    Snapshot,
    Gallery,
    GalleryImage,
    GalleryImageVersion,
    OperatingSystemStateTypes,
    SecurityProfile
)

def print_info(msg):
    print(f"[INFO] {msg}")

def print_success(msg):
    print(f"[SUCCESS] {msg}")

def print_error(msg):
    print(f"[ERROR] {msg}")

def get_next_version(existing_versions):
    """
    Given a list of existing version names, return the next patch version.
    If no valid versions found, return '1.0.0'
    """
    valid_versions = []
    for ver in existing_versions:
        try:
            # Normalize and parse version strings
            ver_obj = version.parse(ver.name)
            if isinstance(ver_obj, version.Version):
                valid_versions.append(ver_obj)
        except Exception:
            pass

    if not valid_versions:
        return "1.0.0"

    latest_version = max(valid_versions)
    # Increment patch number
    next_version = version.Version(
        f"{latest_version.major}.{latest_version.minor}.{latest_version.micro + 1}"
    )
    return str(next_version)

def main():
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_APP_CLIENT_ID")
    client_secret = os.environ.get("AZURE_APP_CLIENT_SECRET")

    if not all([subscription_id, tenant_id, client_id, client_secret]):
        print_error("Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_APP_CLIENT_ID, AZURE_APP_CLIENT_SECRET environment variables")
        sys.exit(1)

    credentials = ClientSecretCredential(client_id=client_id, client_secret=client_secret, tenant_id=tenant_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    resource_client = ResourceManagementClient(credentials, subscription_id)

    # Inputs
    resource_group = input("Enter the resource group of the VM: ","win10dev").strip()
    vm_name = input("Enter the VM name to clone: ","").strip()
    gallery_resource_group = input("Enter resource group for the Compute Gallery: ","win10dev").strip()
    gallery_name = input("Enter Compute Gallery name: ","rtx2udk").strip()
    image_definition_name = input("Enter VM Image Definition name: ","idtech4rtx").strip()
    image_offer = input("Enter image offer (e.g., Windows-10): ","Windows-10").strip()
    image_sku = input("Enter image SKU (must be unique, e.g., win10-22h2-pro-g2-custom-image): ").strip()
    image_publisher = input("Enter image publisher (e.g., MicrosoftWindowsDesktop):","MicrosoftWindowsDesktop").strip()

    # Get the VM to snapshot its OS disk
    print_info(f"Getting VM '{vm_name}' in resource group '{resource_group}'...")
    try:
        vm = compute_client.virtual_machines.get(resource_group, vm_name)
    except Exception as e:
        print_error(f"Failed to get VM: {e}")
        sys.exit(1)

    os_disk_name = vm.storage_profile.os_disk.name
    os_disk_id = vm.storage_profile.os_disk.managed_disk.id
    vm_location = vm.location
    print_info(f"OS Disk name: {os_disk_name}")

    # Create snapshot name
    snapshot_name = f"{vm_name}-osdisk-snapshot"
    print_info(f"Creating snapshot '{snapshot_name}' from OS disk...")

    snapshot_params = Snapshot(
        location=vm_location,
        creation_data={
            'create_option': 'Copy',
            'source_resource_id': os_disk_id
        }
    )

    try:
        snapshot = compute_client.snapshots.begin_create_or_update(
            resource_group_name=resource_group,
            snapshot_name=snapshot_name,
            snapshot=snapshot_params
        ).result()
        print_success(f"Snapshot '{snapshot_name}' created.")
    except Exception as e:
        print_error(f"Failed to create snapshot: {e}")
        sys.exit(1)

    # Create or get Compute Gallery
    try:
        gallery = compute_client.galleries.get(gallery_resource_group, gallery_name)
        print_info(f"Compute Gallery '{gallery_name}' found.")
    except Exception:
        print_info(f"Creating Compute Gallery '{gallery_name}'...")
        gallery_params = Gallery(location=vm_location)
        gallery = compute_client.galleries.begin_create_or_update(gallery_resource_group, gallery_name, gallery_params).result()
        print_success(f"Compute Gallery '{gallery_name}' created.")

    # Create or get VM Image Definition
    try:
        image_def = compute_client.gallery_images.get(gallery_resource_group, gallery_name, image_definition_name)
        print_info(f"Gallery Image Definition '{image_definition_name}' found.")
    except Exception:
        print_info(f"Creating Gallery Image Definition '{image_definition_name}'...")
        image_def_params = GalleryImage(
            location=vm_location,
            os_type=vm.storage_profile.os_disk.os_type,
            os_state=OperatingSystemStateTypes.SPECIALIZED,  # Important!
            publisher=image_publisher,
            offer=image_offer,
            sku=image_sku,
            hyper_v_generation='V2',  # Assuming Gen2 VM; adjust if needed
            security_profile=SecurityProfile(security_type="TrustedLaunch")  # Must match snapshot's security type
        )
        image_def = compute_client.gallery_images.begin_create_or_update(
            gallery_resource_group,
            gallery_name,
            image_definition_name,
            image_def_params
        ).result()
        print_success(f"Gallery Image Definition '{image_definition_name}' created.")

    # List existing image versions
    print_info(f"Listing existing image versions for definition '{image_definition_name}':")
    existing_versions = list(compute_client.gallery_image_versions.list_by_gallery_image(
        gallery_resource_group,
        gallery_name,
        image_definition_name
    ))

    if existing_versions:
        print_info("Existing image versions:")
        for ver in existing_versions:
            print(f" - {ver.name} (Location: {ver.location})")
    else:
        print_info("No existing image versions found.")

    # Determine next version automatically
    next_version = get_next_version(existing_versions)
    print_info(f"Next available image version will be: {next_version}")

    # Next version if 1.0.0 is taken
    image_version_name = next_version

    # Create VM Image Version from snapshot
    print_info(f"Creating VM Image Version '{image_version_name}' from snapshot...")
    image_version_params = GalleryImageVersion(
        location=vm_location,
        publishing_profile={
            'target_regions': [{'name': vm_location}],
            'replica_count': 1,
            'storage_account_type': 'Standard_LRS'
        },
        storage_profile={
            'os_disk': {
                'os_type': vm.storage_profile.os_disk.os_type,
                'snapshot': {
                    'id': snapshot.id
                },
                'os_state': OperatingSystemStateTypes.SPECIALIZED
            }
        }
    )

    try:
        image_version = compute_client.gallery_image_versions.begin_create_or_update(
            gallery_resource_group,
            gallery_name,
            image_definition_name,
            image_version_name,
            image_version_params
        ).result()
        print_success(f"Gallery Image Version '{image_version_name}' created successfully.")
    except Exception as e:
        print_error(f"Failed to create Gallery Image Version: {e}")
        sys.exit(1)

    print_success("Clonable VM Image creation completed!")
    
    print_success("-----------------------------------------------------")
    print_success("Azure Windows VM cloning completed successfully!")
    print_success("-----------------------------------------------------")
    print_success("Gallery Image Resource group:-----------------------------")
    print_success(gallery_resource_group)
    print_success("Gallery Name:-----------------------------")
    print_success(gallery_name)
    print_success("Gallery Image Definition Name:-----------------------------")
    print_success(image_definition_name)
    print_success("Gallery Image Version:-----------------------------")
    print_success(image_version_name)
    print_success("-----------------------------------------------------")

    # Construct the Azure Portal URL to the image version overview
    portal_url = (
        f"https://portal.azure.com/#@{tenant_id}/resource/subscriptions/{subscription_id}"
        f"/resourceGroups/{gallery_resource_group}/providers/Microsoft.Compute/galleries/"
        f"{gallery_name}/images/{image_definition_name}/versions/{image_version_name}/overview"
    )

    print_success(f"Azure Portal URL to the image version:")
    print_success(portal_url)
    print_success("-----------------------------------------------------")

    # Open the default browser with the URL
    webbrowser.open(portal_url)
        
if __name__ == "__main__":
    main()