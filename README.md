AD-PermissionDelegation
Delegate permissions in AD for least privileges based on pre-defined permission sets

COMMENT: delegate AD object on OU or group.
          executing user must be Domain Admin
          script needs to run elevated


USAGE:
	.\Delegate-AdPermissions.ps1 -AdObject <AdDn> -Target <DN> -PermissionSet [-AddLapsPermissions] [-AddBitLockerPermissions]

     The flags '-AddLapsPermissions' and 'AddBitLockerPermissions' can only be used together with permission set 'ManageComputersOU'
     Both permissions are already included in permission set 'RestrictedDeviceOperators'

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
 full control all user objects in OU --> "GA;;user"  /I:S
                                     --> "CCDC;user" /I:T
 

### T2HelpdeskUser role permissions
# manage user passwords
 reset pwd       --> "CA;Reset Password;user" /I:S
                 --> "RPWP;pwdLastSet;user" /I:S
 unlock account  --> "RPWP;lockoutTime;user" /I:S
 disable account --> "RPWP;userAccountControl;user" /I:S


### ManageUserOU
# manage user objects
 reset pwd       --> "CA;Reset Password;user" /I:S
                 --> "RPWP;pwdLastSet;user" /I:S
 unlock account  --> "RPWP;lockoutTime;user" /I:S
 disable account --> "RPWP;userAccountControl;user" /I:S
 create user     --> "CC;user" /I:T
 delete user     --> "DC;user" /I:T


### ManageGroupsOU
# manage groups objects
 create group         --> "CC;group" /I:T
 delete group         --> "DC;group" /I:T
 manage group members --> "RPWP;member" /I:T


### RestrictedDeviceOperators
# no phsical access to computer object
# manage computers OU + LAPS + BitLocker in AD
 reset pwd                --> "CA;Reset Password;computer" /I:S
                          --> "RPWP;pwdLastSet;computer" /I:S
 Disable computer account --> "RPWP;userAccountControl;computer" /I:S
 delete computer objects  --> "DC;computer" /I:T
 Join/create computer objects  --> "CC;computer" /I:T
 move computer objects    --> "RPWP;;computer" /I:S

# AddLapsPermissions
 Read Lapsv1 Pwd            --> "CA;ms-Mcs-AdmPwd" /I:T 
 Reset Lapsv1 Pwd           --> "WP;ms-Mcs-AdmPwd" /I:T

trying to use LAPSv2 PoS cmdlets to assign LAPS permissions
in case the module is not available fall back to DSACLS will be used
--> result might not be sufficient

 Read Lapsv2 Pwd            --> ":CA;msLAPS-Password" /I:T                  # read lapsv2 password
 Read encrypted Lapsv2 Pwd  --> ":CA;msLAPS-EncryptedPassword" /I:T         # read lapsv2 password
 Read Lapsv2 Pwd History    --> ":CA;msLAPS-EncryptedPasswordHistory" /I:T  # read lapsv2 password history
 Read Lapsv2 Pwd expiry     --> ":CA;msLAPS-PasswordExpirationTime" /I:T    # reset lapsv2 password
 Reset Lapsv2 Pwd           --> ":RPWP;msLAPS-PasswordExpirationTime" /I:T  # reset lapsv2 password

 Bitlocker                --> "CCDC;msFVE-REcoveryInformation;" /I:T 


### ManageComputersOU
# manage computer objects
# BitLocker & LAPS are optional permissions
# which can be enabled
 reset pwd                --> "CA;Reset Password;computer" /I:S
                          --> "RPWP;pwdLastSet;computer" /I:S
 Disable computer account --> "RPWP;userAccountControl;computer" /I:S
 move computers           --> "RPWP;;computer" /I:S



### ManageGroup
 full control on group --> "GA;group" /I:T

