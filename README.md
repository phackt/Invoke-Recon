# Invoke-Recon
Powershell script for the very first domain enumeration

# First import the right modules
```
git clone --recurse-submodules git@github.com:phackt/Invoke-Recon.git
Import-Module .\PowerSploit\Recon\PowerView.ps1
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
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
| Checking spooler service up on DCs
+------+------------------------------------------------+------+
...
```

# Todo
- PowerUpSQL
- Cross the results
