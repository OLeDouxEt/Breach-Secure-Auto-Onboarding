$IDS = @("")
$DEFAULT_GROUPS = @{
    "BSN-Employees" = "PII/PHI Protect Standard Users";
    "BSN-Managers" = "PII/PHI Protect Manager Role";
    "BSN-ManagerAdmins" = "PII/PHI Protect Manager Admin Role"
}
$DEFAULT_SUPERADMINS = @("")
$ADMINS = @("")

# Folling few lines for log validation or creation
$CURDIR = Get-Location
$LOG_FILE = "BreachSecAutoOnboard.txt"
$LOG_PATH = "$($CURDIR.Path)\$LOG_FILE"
$logFound = Test-Path -Path $LOG_PATH -PathType Leaf
if(!$logFound){
    New-Item -ItemType File -Path $LOG_PATH
}

# Meant to check if the AzureAD module is installed. Will try to
# install the module if it is not already.
Function Test-Modules {
    $azInstalled = $false
    $allMods = Get-InstalledModule
    for($i=0;$i -lt $allMods.Count;$i++){
        if($allMods[$i].Name -eq "AzureAD"){
            $azInstalled = $true
            break
        }
    }
    if($azInstalled){
        return $azInstalled
    }else{
        try{
            Install-Module -Name azuread -Force -AllowClobber
            $azInstalled = $true
            return $azInstalled
        }catch{
            Write-Error "Unable to install necessary AzureAD module! Exiting..."
            Add-Content -Path $LOG_PATH -Value "Attempted to install AzureAD module, but failed. $(Get-Date -Format "MM/dd/yy HH:mm")"
            Exit 1
        }
    }
}

Function Connect-ToAD {
    #$cred = Get-Credential -Message "Credential are required to connect to AzureAD."
    #Write-Host $cred.Password
    #Connect-AzureAD -Credential $cred
}

Function Confirm-Groups {
    # Creating the form with the Windows forms namespace
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Confirm or Change Groups'
    $form.Size = New-Object System.Drawing.Size(300,300)
    $form.StartPosition = 'CenterScreen'
    #Prevents resize of the window
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $form.Topmost = $true
    $form.ShowDialog()
}

Function Set-UserGroups {
    $allUsers = Get-AzureADUser -All $true
    $allGroups = Get-AzureADMSGroup -All $true
    # If any Breach Secure groups already exist for any reason, their value will be increased and excluded
    # when creating the other groups.
    $oldBSNGroups = @{
        "BSN-Employees" = 0;
        "BSN-Managers" = 0;
        "BSN-ManagerAdmins" = 0
    }
    # If no groups exists, it is safe to create the Breach Secure related groups.
    if($allGroups -eq 0){
        foreach ($group in $DEFAULT_GROUPS.Keys) {
            New-AzureADGroup -DisplayName $group -Description $($DEFAULT_GROUPS[$group]) -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet"
            Add-Content -Path $LOG_PATH -Value "Created $group in AzureAD for tenant. $(Get-Date -Format "MM/dd/yy HH:mm")"
        }
    }else{
        # Looking for any existing Breach Secure groups in the AzureAD tenant and incrementing to their key to exclude
        $gpKeys = $DEFAULT_GROUPS.Keys.ForEach('ToString')
        for($i=0;$i -lt $allGroups.Count;$i++){
            switch ($allGroups[$i].DisplayName) {
                $gpKeys[0]{
                    $oldBSNGroups[$gpKeys[0]] += 1
                    break;
                }
                $gpKeys[1]{
                    $oldBSNGroups[$gpKeys[1]] += 1
                    break;
                }
                $gpKeys[2]{
                    $oldBSNGroups[$gpKeys[2]] += 1
                    break;
                }
                Default{
                    continue
                }
            }
        }
        foreach ($group in $DEFAULT_GROUPS.Keys) {
            if($oldBSNGroups[$group] -le 0){
                New-AzureADGroup -DisplayName $group -Description $($DEFAULT_GROUPS[$group]) -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet"
                Add-Content -Path $LOG_PATH -Value "Created $group security group in AzureAD for tenant. $(Get-Date -Format "MM/dd/yy HH:mm")"
            }else{
                Add-Content -Path $LOG_PATH -Value "Security group: $group already exists in AzureAD for tenant. Skipping... $(Get-Date -Format "MM/dd/yy HH:mm")"
            }
        }
    }
}

Function Clean-Up {
    #Remove-Variable IDS
    Disconnect-AzureAD
}

$adMod = Test-Modules
if($adMod){
    Connect-AzureAD -TenantId $IDS[0]
    Set-UserGroups
    <#
    $popShell = New-Object -ComObject Wscript.Shell
    $popShell.Popup("The file '$($fileResults.Keys)' has been labeled as MALWARE by: $($fileResults.Values)!",0,"Malicious File Detected!",0x30)
    #>
}