#!/usr/bin/env python3

import time, requests, json, sys, urllib3, argparse, getpass

cloudName = input("Cloud Name (e.g. zscloud.net): ")
username = input("Username: ")
password = getpass.getpass("Password: ")
apiKey = input("APIKey: ")

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

def createSession(username, password, apiKey):
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

f = createSession(username, password, apiKey)
api = getAPI(f)

for id in api:
    print("Regenerating the following API Key:")
    print(id['id'], end=' ')
    keyid = id['id']
    print(id['keyValue'])
    regen_api = regenAPI(f,keyid=keyid)
    # Successful regeneration should return 204 otherwise 400/405
    print(regen_api)

# Force activate after changes
print("Activating Changes")
print(forcedActivate(f).text)

# Display new API Key
print("Your new API Key is:")
print(str(getAPI(f)))