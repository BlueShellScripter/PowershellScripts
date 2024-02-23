# CheckOutlookPermissions-Selection

## Purpose
This script is designed to enhance security within Outlook by addressing a common attack vector. Attackers often attempt to modify the Default user's permissions on the Root and Inbox folders. Such modifications can allow attackers to access a person's email using any account within the tenant. To counter this, the script performs the following actions:

- **Target**: Utilizes a list of users from `targetMailboxes.txt`, which contains usernames in a single-column format.
- **Checks**: Verifies the permissions on the Root and Inbox folders, specifically looking for 'None' permissions for the 'DefaultUser'.
- **Reporting**: Generates CSV files to flag any mailboxes with permissions deviating from the expected 'None' setting.
- **Language Support**: Accounts for users with non-English language settings, which may alter the name of their Inbox folder.

## Execution
To run the script, ensure `targetMailboxes.txt` is populated with the relevant usernames, one per line. The script then iterates through each mailbox, checking permissions and compiling a report on any anomalies found.

## Output
- CSV reports are generated for any mailbox found with permissions other than 'None' for 'DefaultUser'.
- These reports are critical for identifying potential security risks and taking corrective action.

## Language Compatibility
The script includes functionality to handle mailboxes set to languages other than English, ensuring comprehensive coverage across diverse organizational settings.
