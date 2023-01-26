# cyberark-mfa-no-gui-example
This sample script performs MFA for a CyberArk Cloud Directory user on the Shared Services platform. It is used (in this case) to download an MFA Caching SSH key.

This is intended for a human user who will be present to interact with the script. The authentication process takes place in three stages and this script assumes that username/password is the first challenge issued by CyberArk Identity. 

## Notes on ISPSS
This is primarily meant to serve as example code. It performs multifactor authentication to CyberArk Identity without requring a GUI-based, interactive browser. It will work exclusively for CyberArk Cloud Directory users on Shared Services (ISPSS) tenants. Federated users from outside sources should instead consult the relevant documentation for their respective identity providers (as this method **will not** work for them).

## Notes on Standalone
The authentication flow is different (and slightly more complex) for Standalone integrations. For starters, you will need to retrieve your PVWA's app key from CyberArk Identity Administration. It is visible beneath the "Advanced" section of the app's Settings panel. In addition to Privilege Cloud, this script will also work for self-hosted environments. I have therefore included the ability to handle self-signed certificates in this script. You disable this verification at your own risk. 

## Limitations
Although these scripts will allow a user to select their desired MFA challenge, it is not equipped to handle OTP or subsequent data entry beyond the initial submission of username and password. That is, the script expects MFA verification to be completed "out of band" (e.g. the user clicking a link in an email/SMS or responding to a push notification).

The error handling here ranges from weak to nonexistent. Double check the values of your variables before running the script, make sure you type your password correctly and wait till you see the "Authentication Successful" message from your MFA challenge before hitting enter to advance.


## Instructions
1. Update the variables near the top of the script you plan to run.
2. `pip install -r requirements.txt`
3. `python SAML-[Architecture]-MFA-Caching-Key.py`
4. Enter your user's password.
5. Choose your desired MFA modality (if more than one is available)
6. Respond to the MFA challenge and wait to see "Authentication Successful."
7. Press enter to advance the script so that it can retrieve the token you just generated.