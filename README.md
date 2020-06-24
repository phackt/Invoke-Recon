# Invoke-Recon
Powershell script for the very first domain enumeration.  
Just because i'm tired to type the same AD / PowerView commands over and over.  
  
# First import the right modules
```
git clone --recurse-submodules git@github.com:phackt/Invoke-Recon.git
Import-Module .\PowerSploit\Recon\PowerView.ps1
Import-Module .\PowerUpSQL\PowerUpSQL.psd1
Import-Module .\ADModule\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ADModule\ActiveDirectory\ActiveDirectory.psd1
```

# Run
```
.\Invoke-Recon.ps1 -Domain us.funcorp.local | Tee-Object -FilePath .\invoke-recon.txt

################################################################
################################################################
| Starting enumeration of domain us.funcorp.local
################################################################
################################################################

+------+------------------------------------------------+------+
| Searching PDC
+------+------------------------------------------------+------+

Name                                     Type   TTL   Section    NameTarget                     Priority Weight Port
----                                     ----   ---   -------    ----------                     -------- ------ ----
_ldap._tcp.pdc._msdcs.us.funcorp.local   SRV    600   Answer     UFC-DC1.us.funcorp.local       0        100    389

Name       : UFC-DC1.us.funcorp.local
QueryType  : A
TTL        : 600
Section    : Additional
IP4Address : 192.168.2.1



+------+------------------------------------------------+------+
| Searching all DCs
+------+------------------------------------------------+------+
_ldap._tcp.dc._msdcs.us.funcorp.local    SRV    600   Answer     UFC-DC1.us.funcorp.local       0        100    389

Name       : UFC-DC1.us.funcorp.local
QueryType  : A
TTL        : 600
Section    : Additional
IP4Address : 192.168.2.1



+------+------------------------------------------------+------+
| Checking spooler service is up on DCs
+------+------------------------------------------------+------+
...


+------+------------------------------------------------+------+
| Members of the DCs 'Domain Local' group Administrators
+------+------------------------------------------------+------+
[+] Digging into 192.168.2.1

ComputerName : 192.168.2.1
GroupName    : Administrators
MemberName   : USFUN\Administrator
SID          : S-1-5-21-3965405831-1015596948-2589850225-500
IsGroup      : False
IsDomain     : False
...


+------+------------------------------------------------+------+
| Nested privileged users (RID >= 1000)
+------+------------------------------------------------+------+

GroupDomain             : us.funcorp.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=us,DC=funcorp,DC=local
MemberDomain            : us.funcorp.local
MemberName              : servicesadmin
MemberDistinguishedName : CN=services admin,CN=Users,DC=us,DC=funcorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-3965405831-1015596948-2589850225-1122

------+------------------------------------------------+------+
| Computers with constrained delegation and protocol transition
+------+------------------------------------------------+------+
...


+------+------------------------------------------------+------+
| Users with constrained delegation and protocol transition
+------+------------------------------------------------+------+
...


+------+------------------------------------------------+------+
| Managed Service Accounts with constrained delegation and protocol transition
+------+------------------------------------------------+------+
...


+------+------------------------------------------------+------+
| Finding principals with replicating permissions
+------+------------------------------------------------+------+
...

[more]
```

# Todo
- Resolving https://github.com/NetSPI/PowerUpSQL/issues/61 for querying specific domain thanks to PowerUpSQL (any idea?)
- list OWA / Exchange server (members of Exchange Trusted Subsystem)
- Cross the results
