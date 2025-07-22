import requests
import json

# Replace with your actual Function App URL and function key
FUNCTION_URL = "https://createvm-aqg2b8f8c0fmevb0.uksouth-01.azurewebsites.net/createvm"

headers = {
    "Content-Type": "application/json",
}

# Example JSON payload
payload = {
    "domain": "win10dev.xyz",
    "resource_group": "win10dev",
    "location": "uksouth",               
    "vm_size": "Standard_NV6ads_A10_v5",
}

response = requests.post(FUNCTION_URL, headers=headers, json=payload)

print("Status Code:", response.status_code)
try:
    print("Response JSON:", response.json())
except Exception:
    print("Raw Response:", response.text)
