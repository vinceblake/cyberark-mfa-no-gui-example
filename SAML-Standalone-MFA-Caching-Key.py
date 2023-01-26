import requests
import json
import getpass
import re
import os

### SET THESE VARIABLES ###
identity_subdomain = "example" # e.g https://EXAMPLE.id.cyberark.cloud
pvwa_saml_app_key = os.getenv("pvwa_saml_app_key") # Retrieved from the SAML web app in Identity.
pvwa_url = "example.privilegecloud.cyberark.cloud" # Do not include https://
username = "paul@example.com"
key_path = "C:/Users/Paul/Desktop" # Directory to store the SSH key. No trailing /.
key_format = "PPK" # PEM, PPK or OPENSSH
require_ssl_verify = True # Set to False for self-signed certs (but use at your own risk)

# Ignore SSL cert warnings from requests module?
if require_ssl_verify is False:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


### MFA MECHANISM OBJECT ###
class Mechanism():
    def __init__(self, name, id):
        self.name = name
        self.id = id


### STEP 1: START AUTH WITH CYBERARK IDENTITY ###
password = getpass.getpass(f"Enter the password for {username}:\n")
url = f"https://{identity_subdomain}.id.cyberark.cloud/Security/StartAuthentication"

payload = json.dumps({
  "User": username,
  "Version": "1.0"
})
headers = {
  'Content-Type': 'application/json',
  'X-IDAP-NATIVE-CLIENT': 'true'
}
response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
json_object = json.loads(response.text)

# Parse response for important variables 
session_id = json_object['Result']['SessionId']
tenant_id = json_object['Result']['TenantId']
pwd_mechanism_id = json_object['Result']['Challenges'][0]['Mechanisms'][0]['MechanismId']
mechanisms = json_object['Result']['Challenges'][1]['Mechanisms']

# Create list of MFA Mechanisms 
options = []
for mechanism in mechanisms:
    name = mechanism['Name']
    id = mechanism['MechanismId']
    obj = Mechanism(name,id)
    options.append(obj)

# Print list of MFA mechanisms available to user (if there's more than one option)
if len(options) > 1:
  i = 0
  for option in options:
      i = i + 1
      print(f"{i}. {option.name}")

# Allow user to choose their MFA modality
choice = 0
while True:
    if len(options) == 1:
        break # No need to bother here if we only have one choice.
    if len(options) < 1:
        print(f"Doesn't look like any MFA options are configured for {username}. Exiting.")
        exit()
    choice = input("\nPlease choose an MFA mechanism: ")
    error = f"ERROR: Your response must be an integer between 1 and {len(options)}."
    try:
        choice = int(choice)
    except:
        print(error)
        continue
    if 0 < choice <= len(options):
        choice = choice - 1
        break
    print(error)

mfa_mechanism_name = options[choice].name
mfa_mechanism_id = options[choice].id


### STEP 2: ADVANCE AUTH WITH USERNAME AND PASSWORD ###
url = f"https://{identity_subdomain}.id.cyberark.cloud/Security/AdvanceAuthentication"

payload = json.dumps({
  "SessionId": session_id,
  "MechanismId": pwd_mechanism_id,
  "Action": "Answer",
  "Answer": password
})
headers = {
  'X-IDAP-NATIVE-CLIENT': 'true',
  'Content-Type': 'application/json'
}
response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)


### STEP 3: ADVANCE AUTH WITH SELECTED MFA MODALITY ###
payload = json.dumps({
  "SessionId": session_id,
  "MechanismId": mfa_mechanism_id,
  "Action": "StartOOB"
})
headers = {
  'X-IDAP-NATIVE-CLIENT': 'true',
  'Content-Type': 'application/json'
}

# Give user a chance to respond to their MFA challenge.
print(f"Requesting {mfa_mechanism_name} challenge...\n")
response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
if response:
    input(f"{mfa_mechanism_name} challenge sent. Press enter once you have completed it.\n")


### STEP 4: POLL FOR TOKEN ONCE MFA CHALLENGE HAS BEEN COMPLETED ###
payload = json.dumps({
  "TenantId": tenant_id,
  "SessionId": session_id,
  "MechanismId": mfa_mechanism_id,
  "Action": "Poll"
})
headers = {
  'X-IDAP-NATIVE-CLIENT': 'true',
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
json_object = json.loads(response.text)
token = json_object['Result']['Auth']


### STEP 5: GET SAMLRESPONSE FROM HANDLEAPPCLICK ENDPOINT ###
url = f'https://{identity_subdomain}.id.cyberark.cloud/uprest/HandleAppClick'
payload = json.dumps({
  'appkey': pvwa_saml_app_key,
  'antixss': 'AOk1nyB5OyLW0ovo_iiyZw__',
  'markAppVisited': 'true'
})
headers = {
  'Authorization': f'Bearer {token}',
  'Content-Type': 'application/json'
}
response = requests.request("GET", url, headers=headers, data=payload, verify=require_ssl_verify)
response = re.search(r'value=\"(.*)\"', response.text)
samlresponse = response.group(1)


### STEP 6: AUTH TO PVWA WITH SAMLRESPONSE TO GET SESSION TOKEN ###
url = f"https://{pvwa_url}/PasswordVault/API/auth/SAML/Logon"
payload = {
    'concurrentSession': 'true',
    'apiUse': 'true',
    'SAMLResponse': samlresponse
}
headers = {
  'Content-Type': 'application/x-www-form-urlencoded'
}

response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
token = response.text.replace('"',"") # token gets returned inside quotemarks


### STEP 7: GENERATE MFA CACHING KEY USING TOKEN ###
key_path = key_path.replace('//','/') # In case of a trailing slash in the path
url = f"https://{pvwa_url}/passwordvault/api/users/secret/sshkeys/cache"
payload = json.dumps({
  "formats": [f"{key_format}"]
})
headers = {
  'Authorization': f'{token}',
  'Content-Type': 'application/json'
}
response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
json_object = json.loads(response.text)

try:
    key = json_object['value'][0]['privateKey']
    key = re.sub("\r","",key)
    file = f"{key_path}/mfa_caching_key.{key_format.lower()}"
    with open(file, "w") as f:
        f.write(key)
        
    print(f"Key successfully downloaded to {key_path}/mfa_caching_key.{key_format.lower()}.")

except:
    print("Sorry, an error occurred. Please check your settings and try again.")
