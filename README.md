# cyberark-mfa-no-gui-example
This sample script performs MFA for a CyberArk Cloud Directory user on the Shared Services platform. It is used to download an MFA Caching SSH key.

This is intended for a human user who will be present to interact with the script. The authentication process takes place in three stages and this script assumes that username/password is the first challenge issued by CyberArk Identity. 

## Limitations
This is primarily meant to serve as example code. It performs multifactor authentication to CyberArk Identity without requring a GUI-based, interactive browser. It will work exclusively for CyberArk Cloud Directory users on Shared Services (ISPSS) tenants. Federated users from outside sources should instead consult the relevant documentation for their respective identity providers (as this method **will not** work for them).

Although the script will allow a user to select their desired MFA challenge, it is not equipped to handle OTP or subsequent data entry beyond the initial submission of username and password. That is, the script expects MFA verification to be completed "out of band" (e.g. the user clicking a link in an email/SMS or responding to a push notification).

The error handling here ranges from weak to nonexistent. Double check the values of your variables before running the script, make sure you type your password correctly and wait till you see the "Authentication Successful" message from your MFA challenge before hitting enter to advance.

## Instructions
1. Update the variables in lines 6-9 with your own data.
2. `pip install -r requirements.txt`
3. `python SAML-Get-MFA-Caching-Key.py`
4. Enter your user's password.
5. Choose your desired MFA modality.
6. Respond to the MFA challenge and wait to see "Authentication Successful."
7. Press enter to advance the script so that it can retrieve the token you just generated.
