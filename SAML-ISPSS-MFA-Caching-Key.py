import requests
import json
import getpass
import re

### SET THESE VARIABLES ###
ispss_subdomain = "example"
username = "vince.blake@example.com"
key_path = "/Users/Vince.Blake/Downloads" # Directory to store SSH key. No trailing /.
key_format = "PPK" # PEM, PPK or OPENSSH (or comma-separated list)
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


### STEP 1: START AUTH ###
password = getpass.getpass(f"Enter the password for {username}:\n")
url = f"https://{ispss_subdomain}.cyberark.cloud/api/idadmin/Security/StartAuthentication"

payload = json.dumps({
  "User": username,
  "Version": "1.0"
})
headers = {
  'Content-Type': 'application/json'
}
response = requests.request("POST", url, headers=headers, data=payload)
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

# Print list of MFA mechanisms available to user (if multiple available)
i = 0
if len(options) > 1:
  for option in options:
      i = i + 1
      print(f"{i}. {option.name}")

choice = 0
while True:
  if len(options) == 1:
      break
  if len(options) < 1:
      print(f"Doesn't look like any MFA options are available for {username}. Exiting.")
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
url = f"https://{ispss_subdomain}.cyberark.cloud/api/idadmin/Security/AdvanceAuthentication"

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
response = requests.request("POST", url, headers=headers, data=payload)


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
print(f"Please wait for {mfa_mechanism_name} challenge...\n")
response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
if response:
    input("MFA challenge sent. Press enter once you have completed it.\n")


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

response = requests.request("POST", url, headers=headers, data=payload)
json_object = json.loads(response.text)
token = json_object['Result']['Token']


### STEP 5: GENERATE MFA CACHING KEY HAVING SUCCESSFULLY AUTHENTICATED ###
url = f"https://{ispss_subdomain}.privilegecloud.cyberark.cloud/passwordvault/api/users/secret/sshkeys/cache"
key_path = key_path.replace('//','/') # In case of a trailing slash in the path
payload = json.dumps({
  "formats": [f"{key_format}"]
})
headers = {
  'Authorization': f'Bearer {token}',
  'Content-Type': 'application/json'
}
response = requests.request("POST", url, headers=headers, data=payload, verify=require_ssl_verify)
json_object = json.loads(response.text)

try:
    key = json_object['value'][0]['privateKey']
    key = re.sub("\r","",key) # .PPK won't work without this line. Untested with PEM/OPENSSH.
    file = f"{key_path}/mfa_caching_key.{key_format.lower()}"
    with open(file, "w") as f:
        f.write(key)
        
    print(f"Key successfully downloaded to {key_path}/mfa_caching_key.{key_format.lower()}.")

except:
    print("Sorry, an error occurred. Please check your settings and try again.")
