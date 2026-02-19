AD-PermissionDelegation
Delegate permissions in AD for least privileges based on pre-defined permission sets

COMMENT: delegate AD object on OU or group.
          executing user must be Domain Admin
          script needs to run elevated


USAGE:
	.\Delegate-AdPermissions.ps1 -AdObject <AdDn> -Target <DN> -PermissionSet [-AddLapsPermissions] [-AddBitLockerPermissions]

     The flags '-AddLapsPermissions' and 'AddBitLockerPermissions' can only be used together with permission set 'ManageComputersOU'
     Both permissions are already included in permission set 'T2RestrictedDeviceOperators'

	.\Delegate-AdPermissions.ps1 -Target <DN> -BreakInheritance
     'BreakInheritance' flag will disable inheritance on the target OU

	.\Delegate-AdPermissions.ps1 -Target <DN> [-ReportOnly] [-Export2Csv]
     Reports the current ACEs either into csv or display as GridView
     The guid of object classes and attributes have been translated to the proper class or attribute names


####### PERMISSIONSETS

# delegation is based on DSACLS tool
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)

### ManageOU
 full control all objects in OU --> "GA" /I:T
 

### T2AccountOperator role permissions
 full control all objects in OU --> "GA;;user"  /I:S
                                --> "CCDC;user" /I:T
 

### T2HelpdeskUser role permissions
 reset pwd       --> "CA;Reset Password;user" /I:T
                 --> "RPWP;pwdLastSet;user" /I:T
 unlock account  --> "RPWP;lockoutTime;user" /I:T
 disable account --> "RPWP;userAccountControl;user" /I:T


### ManageUserOU
 reset pwd       --> "CA;Reset Password;user" /I:T
                 --> "RPWP;pwdLastSet;user" /I:T
 unlock account  --> "RPWP;lockoutTime;user" /I:T
 disable account --> "RPWP;userAccountControl;user" /I:T
 create user     --> "CC;user" /I:T
 delete user     --> "DC;user" /I:T


### ManageGroupsOU
 create group         --> "CC;group" /I:T
 delete group         --> "DC;group" /I:T
 manage group members --> "RPWP;member" /I:T


### T2RestrictedDeviceOperators - manage computers OU + LAPS + BitLocker
 reset pwd                --> "CA;Reset Password;computer" /I:T
                          --> "RPWP;pwdLastSet;computer" /I:T
 Disable computer account --> "RPWP;userAccountControl;computer" /I:T
 delete computer objects  --> "DC;computer" /I:T
 Join/create computer objects  --> "CC;computer" /I:T

# AddLapsPermissions
 Read Laps Pwd            --> "CA;ms-Mcs-AdmPwd" /I:T 
 Reset Laps Pwd           --> "WP;ms-Mcs-AdmPwd" /I:T

# Bitlocker                --> "CCDC;msFVE-REcoveryInformation;" /I:T 


### ManageComputersOU
 reset pwd                --> "CA;Reset Password;computer" /I:T
                          --> "RPWP;pwdLastSet;computer" /I:T
 Disable computer account --> "RPWP;userAccountControl;computer" /I:T


### ManageGroup
 full control on group --> "GA;group" /I:T

