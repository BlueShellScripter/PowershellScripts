# CheckOutlookPermissions-OU

## Purpose
This script is created to combat a known security threat where attackers modify the Default user's permissions on the Root and Inbox folders in Outlook. This unauthorized change allows attackers to access emails of any user within the tenant using any account. 

## Functionality
- **Target Selection**: The script targets all users within a specified Organizational Unit (OU). Before execution, ensure you modify the script to specify the correct OU.
- **Permission Checks**: It verifies the permissions on the Root and Inbox folders of each user's Outlook mailbox, ensuring they are set to 'None' for 'DefaultUser'.
- **Reporting**: For any mailbox found with permissions other than 'None', the script generates CSV reports. These reports are crucial for identifying and rectifying potential security breaches.
- **Language Support**: Recognizes and accommodates users with Outlook set to languages other than English, which may affect the name of the Inbox folder.

## Execution Instructions
1. Prior to running the script, modify it to target the specific OU of interest.
2. The script will iterate through each user in the selected OU, checking for and reporting on any deviations in the expected permission settings.

## Output
- The script produces CSV reports for mailboxes with unexpected permission settings for 'DefaultUser', facilitating quick identification and action on potential security issues.

## Note on Language Compatibility
- This script includes support for various language settings, ensuring accurate checks across mailboxes with non-English configurations.
