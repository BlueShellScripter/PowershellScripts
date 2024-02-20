# BlueShellScripter Jan 2024
#
# Why does this script exist?
# It is a common tactic for attackers to modify the Default user's
# persmissions on users' Root and Inbox folders in Outlook.
# Once that change is made, the attacker can use ANY account in the tenant
# to access that persons email.
# This script pulls all users in the OU you select
# then checks the permissions on their root and inbox folders to ensure
# they are 'None' for 'DefaultUser'.
# csv's are created to flag any mailboxes found any other permission setting.
# This script accounts for those that have other languages than english
# set, which would change the name of thier Inbox.

$date = Get-Date -Format "yyyyMMdd"

# Connect to Exchange
write-host "Ensure your account is PIM'd before logging in."
Connect-ExchangeOnline

# Initialize an array to store users with permissions different from 'None'
$usersWithRootPermissions = @()
$usersWithInboxPermissions = @()
$usersWithoutInbox = @()

# all staff is :
Write-Host "Pulling all staff email to process."
#pull in only enabled staff accounts
$usersToCheck = Get-ADUser -Filter 'Enabled -eq $true' -SearchBase "OU=EXAMPLE, OU=EXAMPLE,OU=EXAMPLE,DC=EXAMPLE,DC=EXAMPLE,DC=EXAMPLE" -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName

write-host "$($usersToCheck.count) Accounts have been collected.`n`n"
Write-Host "Processing email permissions now. You will see:"
Write-Host "Green . for each record processed." -ForegroundColor Green
Write-Host "Yellow - if an inbox isn't found" -foregroundcolor Yellow
Write-Host "Red * if there is a permission issue." -ForegroundColor Red
Write-Host "Grey x if a mailbox isn't found at all."

#loop through the users, checking permissions
foreach ($username in $usersToCheck){ 
    # Check if the user exists in Active Directory
    if (Get-ADUser -Filter "Name -eq '$username'"){
        #process user
        write-host "." -nonewline -foregroundcolor Green # loading bar of sorts
        
        #get user info
        $uniqueID = Get-ADUser -Filter "Name -eq '$username'" -Properties UserPrincipalName, EmailAddress | Select-Object -Property UserPrincipalName, EmailAddress -ErrorAction Stop
        
        #Process Root Permissions
        try {
            $rootPermissions = Get-MailboxFolderPermission -Identity "$($uniqueID.UserPrincipalName):\" -User Default -ErrorAction Stop
            if ($rootPermissions.AccessRights -ne "None" ) {
                $usersWithRootPermissions += $username 
                # method to flag as asterix on a finding, a red asterix will show up in the 'loading bar' of .'s from above
                write-host "*" -nonewline -foregroundcolor Red 
            }
            
            # Get the Inbox folder statistics for the user - this finds inbox folder regardless of how it's named
            $inboxStats = Get-MailboxFolderStatistics -Identity $uniqueID.UserPrincipalName | Where-Object {$username.FolderType -eq "Inbox"} -ErrorAction Stop -verbose -debug
            
            if ($inboxStats) {
                $inboxFolderId = $inboxStats.FolderPath.TrimStart("/")
                # Replace backslashes with slashes for the folder path
                $inboxFolderId = $inboxFolderId -replace '\\','/'
                $folderIdentity = "$($username):\${inboxFolderId}"
                #write-host "$folderIdentity"
                
                try {
                    $inboxPermissions = Get-MailboxFolderPermission -Identity $folderIdentity -User Default -ErrorAction Stop
                    if ($inboxPermissions.AccessRights -ne "None" ) {
                        $usersWithInboxPermissions += $username
                        # method to flag as asterix on a finding, a red asterix will show up in the 'loading bar' of .'s from above
                        write-host "*" -nonewline -foregroundcolor Red
                    }
                    $inboxPermissions | Format-List
                } catch {#if there's an error, IE the inbox doesn't exist
                    $usersWithoutInbox += $username
                    write-host "-" -nonewline -foregroundcolor Yellow
                }
            }
        } catch {
            write-host "x" -nonewline #mailbox doesn't exist
        }
    }
    else {
        write-host "$username not found. Skipping."
    }
}

write-host "" #undo the nonewline from above

# If ROOT permissions are set to anything but None on ANY user
if ($usersWithRootPermissions -ne @()){
    # Display the users with different permissions
    Write-Host "The following users were found to have access rights different than None on their Root:" -ForegroundColor Red
    # Iterate through each user and print their name
    $usersWithRootPermissions | ForEach-Object { Write-Host $username }
    # Convert each user to a custom object and export to CSV
    $usersWithRootPermissions | ForEach-Object {
        [PSCustomObject]@{UserPrincipalName = $username}
    } | Export-Csv -Path "$date-anomolousRootPermissions.csv" -NoTypeInformation
    Write-Host "Also written to $date-anomolousRootPermissions.csv"
    
    # optional section to auto fix root permissions
    <#$response = Read-Host "Would you like to change the permissions back to 'None' for these users? (y/n)"
    if ($response -eq 'y') {
        foreach ($user in $usersWithRootPermissions) {
             Set-MailboxFolderPermission -Identity "${user}:\" -User Default -AccessRights None
        }   
    } #>
} 
# If INBOX permissions are set to anything but None on ANY user
if ($usersWithInboxPermissions -ne @()){
    # Display the users with different permissions
    Write-Host "The following users were found to have access rights different than None on their Inbox:" -ForegroundColor Red
    # Iterate through each user and print their name
    $usersWithInboxPermissions | ForEach-Object { Write-Host $username }
    # Convert each user to a custom object and export to CSV
    $usersWithInboxPermissions | ForEach-Object {
        [PSCustomObject]@{UserPrincipalName = $username}
    }  | Export-Csv -Path "$date-anomolousInboxPermissions.csv" -NoTypeInformation
    Write-Host "Also written to $date-anomolousInboxPermissions.csv"

    # optional fix currently only works on inboxes named 'inbox', this part hasn't been updated to catch other languages
    <#
    $response = Read-Host "Would you like to change the permissions back to 'None' for these users? (y/n)"
    if ($response -eq 'y') {
        foreach ($user in $usersWithInboxPermissions) {
            # Set-MailboxFolderPermission -Identity "${user}:\Inbox" -User Default -AccessRights None
        }
    }#>
}

# Output users without an inbox - in these cases they're probably using a different language and they have an inbox named something else
if ($usersWithoutInbox -ne @()) {
    Write-Host "The following users do not have a standard Inbox. Investigate further. This shouldn't ever happen as diffently named inboxes are caught with this code.:" -ForegroundColor Yellow
    # Iterate through each user and print their name
    $usersWithoutInbox | ForEach-Object { Write-Host $username }
    # Convert each user to a custom object and export to CSV
    $usersWithoutInbox | ForEach-Object {
        [PSCustomObject]@{UserPrincipalName = $username}
    } | Export-Csv -Path "$date-manualInvestigateInbox.csv" -NoTypeInformation
    Write-Host "Also written to $date-manualInvestigateInbox.csv"    
}

# if there are no findings on root or inbox
if ($usersWithRootPermissions.Count -eq 0 -and $usersWithInboxPermissions.Count -eq 0 ) {
    write-host "All mailboxes have Default User Access Rights set to 'None' on their root and Inboxes." -foregroundcolor Green
}

if ($usersWithoutInbox.Count -ne 0 ) {
    write-host "Mailboxes requiring manual checks: $($usersWithoutInbox.Count)" -ForegroundColor Yellow
}

# write out to file
Write-host "Script complete." -foregroundcolor Green
