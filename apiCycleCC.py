#!/usr/bin/env python3

import time
import requests
import json
import boto3
from boto3 import Session
import urllib3
import getpass
import sys
import ast

cloudName = input("Cloud Name (e.g. zscloud.net): ")
username = input("Username: ")
password = getpass.getpass("Password: ")
apiKey = input("Current APIKey: ")

# Confirm Intentions
confirm = input("Are you sure you want to regenerate the API Key? This will invalidate the existing API Key and may cause network disruption.\nPlease answer YES or NO (case sensitive): ")

# Construct base URL
base_url = "https://connector." + cloudName + "/api/v1/"

def obfuscateApiKey (apiKey):
    seed = apiKey
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(0, len(str(n)), 1):
        key += seed[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += seed[int(str(r)[j])+2]
 
    return key

headers = {'Content-Type':'application/json'}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def createSessionCC(username, password, apiKey):
    auth_url = base_url + 'auth'
    now = int(time.time() * 1000)
    payload = {'apiKey': obfuscateApiKey(apiKey), 'username': username, 'password':password, 'timestamp': now  }
    s = requests.Session()
    # Added verify=False to bypass ZCC certificate otherwise call may fail with unable to verify SSL cert for certain cloud
    r = s.post(auth_url,data=json.dumps(payload),headers=headers, verify=False)
    return s

# Get Existing API Key ID
def getAPI(s):
    api_url = base_url + 'apiKeys'
    list_of_apikeys = s.get(api_url, headers=headers)
    return list_of_apikeys.json()

# Get Updated API Key ID
def updatedAPI(s):
    updated_api_url = base_url + 'apiKeys'
    list_of_updatedkeys = s.get(updated_api_url, headers=headers)
    return list_of_updatedkeys.json()

# Regenerate API Key
def regenAPI(s,keyid):
    regen_api_url = base_url + 'apiKeys/' + str(keyid) + '/regenerate'
    regen_status = s.post(regen_api_url, headers=headers)
    return regen_status

# Activate Changes
def forcedActivate(s):
    forced_activation_url = base_url + 'ecAdminActivateStatus/forcedActivate'
    activation_status = s.put(forced_activation_url, headers=headers)
    return activation_status

f = createSessionCC(username, password, apiKey)
api = getAPI(f)
updated_api = updatedAPI(f)

if confirm == "NO":
    print("Aborted")
    sys.exit()
else:
    for id in api:
        print("Regenerating the following API Key:")
        keyid = id['id']
        print(id['keyValue'])
        regen_api = regenAPI(f,keyid=keyid)
        # Successful regeneration should return 204 otherwise 400/405
        print(regen_api)

# Force activate after changes
print("Activating Changes")
print(forcedActivate(f).text)

# Display updated API Key
print("Your new CC API Key is:")
json_str = str(getAPI(f))
json_parsed = ast.literal_eval(json_str)
for new_id in json_parsed:
    print(new_id['keyValue'])
    keyValue = new_id['keyValue']

# Update AWS Secrets Manager with new API Key
confirmSecretsUpdate = input("Would you like to update AWS Secrets Manager with the new value? Please answer YES or NO (case sensitive): ")
if confirmSecretsUpdate == "NO":
    print("Aborted")
    sys.exit()
else:
    # Initialize session client
    aws_region_name = input("Enter the AWS Region where Secrets Manager exists (e.g. us-west-2): ")
    aws_access_id = input("Enter your AWS Access Key: ")
    aws_secret_key = input("Enter your AWS Secret Key: ")
    aws_secret_name = input("Enter your AWS Secrets Manager Object Name (e.g. ZS/CC/credentials/yourSecretName): ")
    session = Session(
        aws_access_key_id=aws_access_id,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region_name
    )

    client = session.client(service_name="secretsmanager")

    # Get original Secrets Object
    original_secret = client.get_secret_value(SecretId=aws_secret_name)

    # Convert SecretString to dictionary
    updated_secret = json.loads(original_secret['SecretString'])

    # Update the dictionary with new value
    updated_secret.update({"api_key": keyValue})

    # Update the secret key
    client.update_secret(SecretId=aws_secret_name, SecretString=str(json.dumps(updated_secret)))
