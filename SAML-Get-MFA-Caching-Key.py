import requests
import json
import getpass

### SET THESE VARIABLES ###
ispss_subdomain = "example"
username = "vince.blake@example.com"
key_path = "/Users/Vince.Blake/Downloads"
key_format = "PPK" # PEM, PPK or OPENSSH


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

# Let user choose their MFA modality 
i = 0
for option in options:
    i = i + 1
    print(f"{i}. {option.name}")

while True:
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
print("Please wait...\n")
response = requests.request("POST", url, headers=headers, data=payload)
input("Press enter once you have completed your MFA challenge.\n")


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
payload = json.dumps({
  "formats": [f"{key_format}"]
})
headers = {
  'Authorization': f'Bearer {token}',
  'Content-Type': 'application/json'
}
response = requests.request("POST", url, headers=headers, data=payload)
json_object = json.loads(response.text)

try:
    key = json_object['value'][0]['privateKey']
    file = f"{key_path}/mfa_caching_key.{key_format}"
    with open(file, "w") as f:
        f.write(key)
    print(f"Key successfully downloaded to {key_path}.")

except:
    print("Sorry, an error occurred. Please check your settings and try again.")
