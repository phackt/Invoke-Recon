# Invoke-Recon
Powershell script as a first big step for AD enumeration. Quickwins focused.  
Because typing the same Powershell commands over and over is tedious.  

# Prerequisites  
Git clone and run:    
```
git clone --recurse-submodules https://github.com/phackt/Invoke-Recon.git && cd .\Invoke-Recon
.\Invoke-Recon.ps1 -Domain us.funcorp.local | Tee-Object -FilePath .\us.funcorp.local.txt
```  

# What we are looking for ?  

## Domain Enumeration  

- Find all DCs
	- check if ADWS are accessible in order to be able to use the Active Directory powershell module
	- check if gap between findings with DNS (SRV) enumeration and members of 'Domain Controllers' group
- Password domain policy
- Domains / forests trusts
- All domain users / groups / computers
- Privileged users with RID >= 1000 (recursive lookups for nested members of privileged groups, not AdminCount = 1 to avoid orphans)
- DNSAdmins group members
- Principals with :
	- unconstrained delegation
		- looking for dangerous rights on computers with unconstrained delegation, see [https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
	- constrained delegation (also resource based - msDS-AllowedToActOnBehalfOfOtherIdentity)
- Exchange servers
	- confirm WriteDAC on root domain without InheritOnly
	- list users with mailboxes  


## But also...  

- Exchange vulnerable to :
	- PrivExchange (CVE-2018-8581)
	- CVE-2020-0688  
- Computers with deprecated OS
- Users with Kerberos PreAuth disables (AS_REP Roasting)
- Kerberoastable users
- Principals (RID >= 1000) with the following rights on the **root domain**, **Users**, **Computers** and **Domain Controllers** containers:
	- DS-Replication-Get-Changes-All|WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner|User-Change-Password|User-Force-Change-Password


## And MSSQL Enumeration  

- Enumerates MSSQL instances (looking for SPN service class MSSQL)
- Find MSSQL instances accessible within current security context and get their versions
- Find linked servers from each accessible MSSQL instances
- Bruteforce common credentials
- Look for xp_cmdshell enabled through linked servers of each accessible instances
- Audit each accessible MSSQL Instances for common high impact vulnerabilities and weak configurations

# Run  
Parameters:
- ```-Domain```: domain to enumerate
- ```-TargetDC```: specify target DC IP
- ```-Quick```: skip raw enumeration for users, groups and computers (time consuming on large domains)
  
Example:  
```
.\Invoke-Recon.ps1 -Domain us.funcorp.local | Tee-Object -FilePath .\invoke-recon.txt

[+] PowerSploit module not found. Importing ...
[+] Microsoft.ActiveDirectory.Management.dll not found. Importing ...
[+] ActiveDirectory module not found. Importing ...
[+] PowerUpSQL module not found. Importing ...

################################################################
################################################################
| Starting enumeration of domain us.funcorp.local
################################################################
################################################################

+------+------------------------------------------------+------+
| Searching PDC (DNS enum)
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
| Searching all DCs (DNS enum)
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


+------+------------------------------------------------+------+
| Looking for Exchange servers
+------+------------------------------------------------+------+

Version       : 15.1.1531
FQDN          : MAIL01.us.funcorp.local
Roles         : UM CAS MB HT
Class         : top server msExchExchangeServer
PrivExchange  : True
CVE-2020-0688 : True

[!] Exchange server MAIL01.us.funcorp.local vulnerable to PrivExchange
[!] Exchange server MAIL01.us.funcorp.local vulnerable to CVE-2020-0688

[!] At least one WriteDacl right without InheritOnly on 'DC=us,DC=funcorp,DC=local' has been found (confirming privexchange attack)

------+------------------------------------------------+------+
| Computers with constrained delegation
+------+------------------------------------------------+------+
...


------+------------------------------------------------+------+
| Computers with constrained delegation and protocol transition
+------+------------------------------------------------+------+
...


+------+------------------------------------------------+------+
| Finding principals (RID > 1000) with permissive rights on 'CN=Users,DC=us,DC=funcorp,DC=local' (DS-Replication-Get-Changes-All|WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner)
+------+------------------------------------------------+------+
[!] Filtering out 'OU=Microsoft Exchange Security Groups'

AceType               : AccessAllowed
ObjectDN              : CN=Users,DC=us,DC=funcorp,DC=local
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             :
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3965405831-1015596948-2589850225-1602
AccessMask            : 131132
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
PrincipalDN           : CN=user01,CN=Users,DC=us,DC=funcorp,DC=local


+------+------------------------------------------------+------+
| Auditing each accessible MSSQL Instances
+------+------------------------------------------------+------+
...


[much more]
```

# Support

Thanks a lot for supporting me [here](https://www.buymeacoffee.com/phackt)

# Todo
- check the [issues](https://github.com/phackt/Invoke-Recon/issues)
