#
# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================
#
#
# COMMENT: delegate AD object on OU or group.
#          executing user must be Domain Admin
#          script needs to run elevated
#
#
# USAGE:
#	.\Delegate-AdPermissions.ps1 -AdObject <AdDn> -Target <DN> -PermissionSet [-AddLapsPermissions] [-AddBitLockerPermissions]
#
#     The flags '-AddLapsPermissions' and 'AddBitLockerPermissions' can only be used together with permission set 'ManageComputersOU'
#     Both permissions are already included in permission set 'T2RestrictedDeviceOperators'
#
#	.\Delegate-AdPermissions.ps1 -Target <DN> -BreakInheritance
#     'BreakInheritance' flag will disable inheritance on the target OU
#
#	.\Delegate-AdPermissions.ps1 -Target <DN> [-ReportOnly] [-Export2Csv]
#     Reports the current ACEs either into csv or display as GridView
#     The guid of object classes and attributes have been translated to the proper class or attribute names
#
#
####### PERMISSIONSETS
#
# delegation is based on DSACLS tool
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)
#
### ManageOU
# full control all objects in OU --> "GA" /I:T
# 
#
### T2AccountOperator role permissions
# full control all objects in OU --> "GA;;user"  /I:S
#                                --> "CCDC;user" /I:T
# 
#
### T2HelpdeskUser role permissions
# reset pwd       --> "CA;Reset Password;user" /I:T
#                 --> "RPWP;pwdLastSet;user" /I:T
# unlock account  --> "RPWP;lockoutTime;user" /I:T
# disable account --> "RPWP;userAccountControl;user" /I:T
#
#
### ManageUserOU
# reset pwd       --> "CA;Reset Password;user" /I:T
#                 --> "RPWP;pwdLastSet;user" /I:T
# unlock account  --> "RPWP;lockoutTime;user" /I:T
# disable account --> "RPWP;userAccountControl;user" /I:T
# create user     --> "CC;user" /I:T
# delete user     --> "DC;user" /I:T
#
#
### ManageGroupsOU
# create group         --> "CC;group" /I:T
# delete group         --> "DC;group" /I:T
# manage group members --> "RPWP;member" /I:T
#
#
### T2RestrictedDeviceOperators - manage computers OU + LAPS + BitLocker
# reset pwd                --> "CA;Reset Password;computer" /I:T
#                          --> "RPWP;pwdLastSet;computer" /I:T
# Disable computer account --> "RPWP;userAccountControl;computer" /I:T
# delete computer objects  --> "DC;computer" /I:T
# Join/create computer objects  --> "CC;computer" /I:T
#
# AddLapsPermissions
# Read Laps Pwd            --> "CA;ms-Mcs-AdmPwd" /I:T 
# Reset Laps Pwd           --> "WP;ms-Mcs-AdmPwd" /I:T
#
# Bitlocker                --> "CCDC;msFVE-REcoveryInformation;" /I:T 
#
#
### ManageComputersOU
# reset pwd                --> "CA;Reset Password;computer" /I:T
#                          --> "RPWP;pwdLastSet;computer" /I:T
# Disable computer account --> "RPWP;userAccountControl;computer" /I:T
#
#
### ManageGroup
# full control on group --> "GA;group" /I:T
#
#
# ==============================================================================================
# requires PowerShell 5.1
# version 1.1 / 05.02.2026
#      Initial version
# version 2.1 / 18.02.2026
#      added reporting mode and guid translation
# version 2.2 / 19.02.2026
#      added ACE exports to CSV
#      fixed run directory location
#      added BitLocker information explicitely to the permission sets
#      added posibility to disable inheritance for a target
#      code cleaned up
#
# dev'd by andreas.luy@microsoft.com
# 
#
[CmdletBinding(DefaultParameterSetName = 'SetPerms')]
param(
    [Parameter(Mandatory=$true, ParameterSetName="SetPerms")]
    [string]$AdObject,

    [Parameter(Mandatory=$true)]
    [string]$Target,

    [Parameter(Mandatory=$true, ParameterSetName="SetPerms")]
    [ValidateSet('T2HelpdeskUser','T2AccountOperator', 'ManageOU','ManageUserOU', 'ManageGroupOU', 'ManageComputersOU', 'ManageGroup', 'T2RestrictedDeviceOperators')]
    [string]$PermissionSet,

    [Parameter(Mandatory=$false, ParameterSetName="SetPerms")]
    [switch]$AddLapsPermissions,

    [Parameter(Mandatory=$false, ParameterSetName="SetPerms")]
    [switch]$AddBitLockerPermissions,

    [Parameter(Mandatory=$false, ParameterSetName="DisableInheritance")]
    [switch]$BreakInheritance,

    [Parameter(Mandatory=$false, ParameterSetName="ViewPerms")]
    [switch]$ReportOnly,

    [Parameter(Mandatory=$false, ParameterSetName="ViewPerms")]
    [switch]$Export2Csv
)



Function Write-Line
{
    param (
        [Parameter(Mandatory=$false) ]
        [Alias("Message")]
        [string]$Text = "",
        [Parameter(Mandatory=$False) ]
        [string]$Type
    )

    $SuccessFontColor = "Green"
    $WarningFontColor = "Yellow"
    $FailureFontColor = "Red"

    $SuccessBackColor = "Black"
    $WarningBackColor = "Black"
    $FailureBackColor = "Black"
    
    switch ($Type) {
        "Success" {
            $FontColor = $SuccessFontColor
            $BackColor = $SuccessBackColor
            }
        "Warning" {
            $FontColor = $WarningFontColor
            $BackColor = $WarningBackColor
            }
        "Error" {
            $FontColor = $FailureFontColor
            $BackColor = $FailureBackColor
            }
        default {
            $FontColor = "White"
            $BackColor = $SuccessBackColor
            }
    }
    if (!$Text) {$Text = " "}
    Write-Host -ForegroundColor $FontColor -BackgroundColor $BackColor $Text
    Write-Output $Text|Out-File -FilePath $Script:LogfileName -Append -Force
}

Function Check-AdminPrivileges
{

	$HasSeBackupPriv=$false

	Write-Line "Checking if user has SeSecurityPrivilege assigned ..."
    $WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent()
    $HasSeSecurityPriv = (whoami /priv |findstr SeSecurityPrivilege)

	if ($HasSeSecurityPriv){
        Write-Line ("User " + $WindowsIdentity.name + " has SeSecurityPrivilege") "Success"
	} else {
		$WarningMsg = "The user $($WindowsIdentity.name) has not SeSecurityPrivilege assigned - script might not run correctly!"
		Write-Line $WarningMsg "Warning"
		Return $false
	}
    return $True
}

Function Check-ScriptRequirements
{
    $ret = $true
    Write-Line "Verifying that script is running in FullLanguage mode"
    if ($ExecutionContext.SessionState.LanguageMode -ne [System.Management.Automation.PSLanguageMode]::FullLanguage) {
        $errMsg = "This script must run in FullLanguage mode, but is running in " + $ExecutionContext.SessionState.LanguageMode.ToString()
        Write-Line $errMsg "Error"
        $ret = $false
    }
    try {
        import-module activedirectory
    } catch {
        Write-Line "Cannot load ActiveDirectory PowerShell module..." "Error"
        $ret = $false
    }

    Return $ret
}

function Validate-DN
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$DN
    )

    $ret = ""
    $result = Get-ADObject -Filter 'distinguishedName -eq $DN' -Properties *
    if ($result) {
        $ret = $result.ObjectClass
    }
    return $ret
}

function Dump-Permissions
{
    param(
        [Parameter(Mandatory=$true)]
        $ACL
    )
    
    $NewAcl = @()
    $NewAce = [PSCustomObject]@{}
    foreach ($ace in $ACL) {
        $NewAce = [PSCustomObject]@{
            'IdentityReference' = $ace.IdentityReference
            'ActiveDirectoryRights' = $ace.ActiveDirectoryRights
            'ObjectType' = ""
            'InheritedObjectType' = ""
            'ObjectFlags' = $ace.ObjectFlags
            'AccessControlType' = $ace.AccessControlType
            'IsInherited' = $ace.IsInherited
            'InheritanceType' = $ace.InheritanceType
            'InheritanceFlags' = $ace.InheritanceFlags
            'PropagationFlags' = $ace.PropagationFlags
        }

        $ObjGuid = $ace.ObjectType.Guid
        $match = $Guidmap.Keys.Where({$Guidmap[$_] -eq $ObjGuid})
        if (!$match) {
            $match = $ExtendedRightsMap.Keys.Where({$ExtendedRightsMap[$_] -eq $ObjGuid})
        }
        if ($match) {
            $NewAce.'ObjectType' = $match
        } else {
            $NewAce.'ObjectType' = $ace.ObjectType.Guid
        }
        
        $InheritedObjectType = $ace.InheritedObjectType.Guid
        $match = $Guidmap.Keys.Where({$Guidmap[$_] -eq $InheritedObjectType})
        if (!$match) {
            $match = $ExtendedRightsMap.Keys.Where({$ExtendedRightsMap[$_] -eq $InheritedObjectType})
        }

        if ($match) {
            $NewAce.'InheritedObjectType' = $match
        } else {
            $NewAce.'InheritedObjectType' = $ace.InheritedObjectType.Guid
        }
        $NewAcl += $NewAce
    }

    return $NewAcl
}

function Delegate-Permissions
{
    $success = $true
    $SourceName = $((Get-ADObject -Identity $Script:AdObject).name)
    if ($Script:SourceClass -ieq "group") {
        Write-Line "Granting permissions on $Script:Target for group: $SourceName..." 

    } else {
        Write-Line "Granting permissions on $Script:Target for account: $SourceName..." 
    }

    Write-Line "Permission set: $($Script:PermissionSet)..." 


    switch ($Script:PermissionSet) {
        "T2AccountOperator" {
            Write-Line "--> Full control on user class ..." 
            $res = dsacls "$Script:Target" /G "$($Script:AdObject):GA;;user" /I:S # full control on OU and all sub OUs for user objects only
            if (!$?) {$success = $false; break}
            $res = dsacls "$Script:Target" /G "$($Script:AdObject):CCDC;user" /I:T # full control on OU and all sub OUs for user objects only
            if (!$?) {$success = $false; break}
        }

        "T2HelpdeskUser" {
            Write-Line "--> Reset Password ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CA;Reset Password;user" /I:T       # reset pwd
            if (!$?) {$success = $false; break}
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;pwdLastSet;user" /I:T         # reset pwd
            if (!$?) {$success = $false; break}
            Write-Line "--> Unlock Account ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;lockoutTime;user" /I:T        # unlock account
            if (!$?) {$success = $false; break}
            Write-Line "--> Disable Account ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;userAccountControl;user" /I:T # disable account
            if (!$?) {$success = $false; break}
            Write-Line "--> LAPS permissions needs to be set separately ..." -Type "Warning"
        }

        "ManageOU" {
            Write-Line "--> Full control ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:GA" /I:T # full control on OU and all sub OUs
            if (!$?) {$success = $false; break}
        }

        "ManageUserOU" {
            Write-Line "--> Reset Password ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CA;Reset Password;user" /I:T       # reset pwd
            if (!$?) {$success = $false; break}
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;pwdLastSet;user" /I:T         # reset pwd
            if (!$?) {$success = $false; break}
            Write-Line "--> Unlock Account ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;lockoutTime;user" /I:T        # unlock account
            if (!$?) {$success = $false; break}
            Write-Line "--> Disable Account ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;userAccountControl;user" /I:T # disable account
            if (!$?) {$success = $false; break}
            Write-Line "--> Create User ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CC;user" /I:T                      # create user
            if (!$?) {$success = $false; break}
            Write-Line "--> Delete User ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:DC;user" /I:T                      # delete user
            if (!$?) {$success = $false; break}
        }

        "ManageGroupOU" {
            Write-Line "--> Create Group ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CC;group" /I:T    # create group
            if (!$?) {$success = $false; break}
            Write-Line "--> Delete Group ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:DC;group" /I:T    # delete group
            if (!$?) {$success = $false; break}
            Write-Line "--> Manage Group Members ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;member" /I:T # manage group members
            if (!$?) {$success = $false; break}
        }

        "ManageComputersOU" {
            Write-Line "--> Reset Password ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CA;Reset Password;computer" /I:T       # reset pwd
            if (!$?) {$success = $false; break}
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;pwdLastSet;computer" /I:T         # reset pwd
            if (!$?) {$success = $false; break}
            Write-Line "--> Disable Account ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;userAccountControl;computer" /I:T # Disable computer account
            if (!$?) {$success = $false; break}
            if ($AddLapsPermissions) {
                Write-Line "--> Read LAPS Password ..." 
                $res = dsacls "$Script:Target" /G "$Script:AdObject`:CA;ms-Mcs-AdmPwd" /I:T             # read laps password
                if (!$?) {$success = $false; break}
                Write-Line "--> Reset LAPS Password ..." 
                $res = dsacls "$Script:Target" /G "$Script:AdObject`:WP;ms-Mcs-AdmPwd" /I:T             # reset laps password
                if (!$?) {$success = $false; break}
            }
            if ($AddBitLockerPermissions) {
                Write-Line "--> Read BitLocker Information ..." 
                $res = dsacls "$Script:Target" /G "$Script:AdObject`:CCDC;msFVE-REcoveryInformation" /I:T # read BitLocker Information
                if (!$?) {$success = $false; break}
                $res = dsacls "$Script:Target" /G "$Script:AdObject`:GA;;msFVE-REcoveryInformation" /I:T  #  read BitLocker Information
                if (!$?) {$success = $false; break}
            }
        }
        "T2RestrictedDeviceOperators" {
            Write-Line "--> Reset Password ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CA;Reset Password;computer" /I:T       # reset pwd
            if (!$?) {$success = $false; break}
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;pwdLastSet;computer" /I:T         # reset pwd
            if (!$?) {$success = $false; break}
            Write-Line "--> Disable Account ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:RPWP;userAccountControl;computer" /I:T # Disable computer account
            if (!$?) {$success = $false; break}
            Write-Line "--> Create Computer ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CC;computer" /I:T                      # create computer
            if (!$?) {$success = $false; break}
            Write-Line "--> Delete Computer ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:DC;computer" /I:T                      # delete computer
            if (!$?) {$success = $false; break}
            Write-Line "--> Read LAPS Password ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CA;ms-Mcs-AdmPwd" /I:T             # read laps password
            if (!$?) {$success = $false; break}
            Write-Line "--> Reset LAPS Password ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:WP;ms-Mcs-AdmPwd" /I:T             # reset laps password
            if (!$?) {$success = $false; break}
            Write-Line "--> Read BitLocker Information ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:CCDC;msFVE-REcoveryInformation" /I:T # read BitLocker Information
            if (!$?) {$success = $false; break}
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:GA;;msFVE-REcoveryInformation" /I:T  #  read BitLocker Information
            if (!$?) {$success = $false; break}
        }
        "ManageGroup" {
            Write-Line "--> Full control ..." 
            $res = dsacls "$Script:Target" /G "$Script:AdObject`:GA" /I:T # full control on group
            if (!$?) {$success = $false; break}
        }
    }
    if ($success) {
        try {
            $result = (get-acl "AD:$($Script:Target)").Access|Where-Object {$_.IdentityReference -like "*$($SourceName)*"}

            Write-Line -Message " "
            Write-Line "------------- Result/Success -------------" -Type "Success"
        } catch {
            Write-Line "Cannot enumerate ACE's...`r`n`r`n$($_.Exception.Message)`r`n`r`n aborting ..." "Error"
            Write-Line -Message "aborting ..." "Error"
            $success = $false
        }
        if ($success) {
            #converting ACLobject into string
            $strResult = @()
            if ($result.Count -gt 1) {
                $result = $result.getenumerator()
            }

            $result | Foreach-Object {
                $strResult += ($_ |Out-String).Split([Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)
                $strResult += "`r`n`r`n"
            }
            foreach ($line in $strResult) {
                if (($line -match "ObjectType") -or ( $line -match "InheritedObjectType")) {
                    $ObjGuid = $line.Split(":")[1].trim()
                    $match = $Guidmap.Keys.Where({$Guidmap[$_] -eq $ObjGuid})
                    if (!$match) {
                        $match = $ExtendedRightsMap.Keys.Where({$ExtendedRightsMap[$_] -eq $ObjGuid})
                    }
                    if ($match) {
                        $line = $line + " --> " + $match
                    }
                }
                Write-Line $line -Type "Success" 
            }
        }

        Write-Line -Message " "
    } else {
        Write-Line -Message " "
        Write-Line "------------- Result/ERROR -------------" -Type "Warning"
        $res | Foreach-Object { Write-Line ($_ |Out-String) -Type "Error" }
        Write-Line -Message " "
    }
    return $success
}

#region definitions
$DateStr = (Get-Date).ToString("yyyyMMddHHmm")
$BaseDirectory = If($PSISE){split-path $psise.CurrentFile.FullPath}else{Split-Path $MyInvocation.MyCommand.Definition -Parent}
$LogfileName = "$($BaseDirectory)\SetPermissions-$($PermissionSet)-$($DateStr).txt"
$rootdse = Get-ADRootDSE
$DomainDN = (Get-ADDomain).DistinguishedName
#$ExportFilename = "$($BaseDirectory)\PermissionSet-$($Target.Split(",")[0].split("=")[1].replace(" ","-"))-$($DateStr).csv"
$ExportFilename = "$($BaseDirectory)\PermissionSet-$($Target.Split(",")[0].replace(" ","-"))-$($DateStr).csv"
$PreReqCheckFailed = $false

##object guids
#hashtable for GUID values of each schema class and attribute
$Guidmap = @{}
Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter `
    "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | 
    % {$Guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}

#hashtable for GUID value of each extended right in the forest
$ExtendedRightsMap = @{}
Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter `
    "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | 
    % {$ExtendedRightsMap[$_.displayName]=[System.GUID]$_.rightsGuid}

#endregion

if (!(Check-ScriptRequirements) -or !(Check-AdminPrivileges)){
    Write-Line "Script requirements not met - aborting..." -Type "Error"
    Exit 0x1
}

#region causality check
#used in both permissions sets
$TargetClass = Validate-DN -DN $Target

if ($PSCmdlet.ParameterSetName -eq "SetPerms") {
    $SourceClass = Validate-DN -DN $AdObject

    #verify if adobject is of type user or group
    if (!$SourceClass -or !$TargetClass) {
        exit 0x2
    }

    if (($TargetClass -ieq "organizationalUnit") -and ($PermissionSet -ieq "ManageGroup")) {
        Write-Line -Message " "
        Write-Line -Message "Wrong PermissionSet chosen: '$($PermissionSet)' while targeting '$($TargetClass)'!" -Type "Warning"
        Write-Line -Message "Script cannot continue..." -Type "Error"
        Write-Line -Message "Aborting!" -Type "Error"
        exit 0x3
    }

    if ($SourceClass -ieq "user") {
        Write-Line -Message " "
        Write-Line -Message "A user object has been specified for delegation!" -Type "Warning"
        Write-Line -Message "It is strongly recommended to only delegate groups!" -Type "Warning"

        $options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
        [int]$defaultchoice = 1
        $exitLoop = $false
        $cont = $false
        do {
            $choice = $host.UI.PromptForChoice("", "Delegate user object instead of a group?", $Options, $defaultchoice)

            switch($choice)
            {
                0 { #yes
                    $exitLoop = $true
                    $cont = $true
                }
                1 { #no
                    $exitLoop = $true
                }
            }

        } while (!$exitLoop)
        Write-Line -Message " "

        if (!$cont) {
            Write-Line -Message "Aborted by user!" -Type "Error"
            exit 0x4
        }
    } elseif ($SourceClass -ine "group") {
        Write-Line -Message " "
        Write-Line -Message "Delegation must be based on user or group!" -Type "Error"
        Write-Line -Message "Current object is of type '$($SourceClass)'" -Type "Error"
        Write-Line -Message "Aborting!" -Type "Error"
        exit 0x5
    }

    #verify if target is of type group or OU
    if (($TargetClass -ine "group") -and ($TargetClass -ine "organizationalUnit")) {
        Write-Line -Message " "
        Write-Line -Message "Permissions can only be set on groups or OUs!" -Type "Warning"
        Write-Line -Message "Current permission target is of type '$($TargetClass)'" -Type "Error"
        Write-Line -Message "Aborting!" -Type "Error"
        exit 0x6
    }

    if ($AddLapsPermissions -and ($PermissionSet -ine "ManageComputersOU")) {
        Write-Line -Message " "
        Write-Line -Message "'AddLapsPermissions' can only be used together with permission set 'ManageComputersOU'!" -Type "Warning"
        Write-Line -Message "ignoring ... " -Type "Warning"
        Write-Line -Message " "
    }
    if ($AddBitLockerPermissions -and ($PermissionSet -ine "ManageComputersOU")) {
        Write-Line -Message " "
        Write-Line -Message "'AddBitLockerPermissions' can only be used together with permission set 'ManageComputersOU'!" -Type "Warning"
        Write-Line -Message "ignoring ... " -Type "Warning"
        Write-Line -Message " "
    }
}
#endregion


if ($PSCmdlet.ParameterSetName -eq "SetPerms") {

    If (!(Delegate-Permissions)) {
        Write-Line -Message " "
        Write-Line -Message "Setting permissions for $($AdObject) failed!" -Type "Error"
        Write-Line -Message "Please correct the issue and run the script again ..." -Type "Error"
    }

} elseif ($PSCmdlet.ParameterSetName -eq "DisableInheritance") {
    Write-Line -Message "Disabling inheritance for $($Script:Target) ... "
    Write-Line -Message " "
    $res = dsacls "$Script:Target" /P:Y       # disable inheritance ('protected object = yes')
    if ($?) {
        Write-Line -Message " --> Success " -Type "Success"
        Write-Line -Message " "
    } else {
        Write-Line -Message " "
        Write-Line -Message "Disabling inheritance for $($Script:Target) failed!" -Type "Error"
        Write-Line -Message "Please correct the issue and run the script again ..." -Type "Error"
    }
} else {
    try {
        Write-Line -Message "Dumping ACEs ... "
        $Acl = (get-acl "AD:$($Script:Target)").Access #|Where-Object {$_.IdentityReference -like "*$($SourceName)*"}
        $result = Dump-Permissions -ACL $Acl 
        if ($Export2Csv) {
            $result | Export-Csv -Path $ExportFilename -Force
            Write-Line -Message "Output written into $($ExportFilename) ..." -Type "Success"
        } else {
            $result | Out-GridView
        }
        Write-Line -Message " "
        #Write-Line "------------- Result/Success -------------" -Type "Success"
    } catch {
        Write-Line "Cannot enumerate ACE's...`r`n`r`n$($_.Exception.Message)`r`n`r`n aborting ..." "Error"
        Write-Line -Message "aborting ..." "Error"
    }
}

