# Command Injection Vulnerability in TP-Link TL-MR3420 v1 PPTP Configuration via `PPTPServerName` Parameter

## Overview

  * Vendor: TP-Link
  * Product: TL-MR3420
  * Hardware Version: MR3420 v1
  * Tested Firmware Version: `3.12.3 Build 110222 Rel.34500n Beta`
  * Vulnerability Type: Authenticated Command Injection
  * Affected Component: `httpd` Web Management Interface
  * Affected Page: `/userRpm/PPTPCfgRpm.htm`
  * Trigger Parameter: `PPTPServerName`
  * Default Web Credential Used in Testing: `admin / admin`
  * Impact: Remote command execution with the privilege of the `httpd` process, which is typically root on this device.

## Vulnerability Basic Information

  * URL Registration Function: `httpWanPptpRpmInit` at `0x47AFEC`
  * Web Request Handler: `pptpCfgRpmHtm` at `0x479F00`
  * Validation Functions: `swChkPptpDomain` at `0x4A366C`, `swChkPptpCfg` at `0x4A3480`
  * Connection Trigger Function: `swPptpLinkUpReq` at `0x4A2CD8`
  * Command Execution Function: `pptpCmdReq` at `0x4D2CE4`
  * Vulnerable Command Construction Function: `pptpFormatCmd` at `0x4D2A80`
  * Vulnerability Point: `sprintf(command, "pppd pptp pptp_server %s ", (const char *)(a1 + 28));`
  * Prerequisites:
    * The attacker has valid access to the router Web management interface.
    * The router accepts a PPTP configuration request containing the `PPTPServerName` parameter.
    * The PPTP connection path is triggered, for example by submitting the page with the `Connect` parameter.

## Vulnerability Description

The PPTP WAN configuration page reads the user-controlled `PPTPServerName` parameter from the HTTP request and stores it into the PPTP configuration structure at offset `+28`. The validation logic treats non-IP strings as domain names and returns success without filtering shell metacharacters such as `;`, `>`, and `#`.

When a PPTP connection is started, the saved configuration is loaded and passed to `pptpFormatCmd`. This function directly inserts the `PPTPServerName` value into a shell command using a bare `%s` format specifier. The final command string is then executed through `system()`. Because the server name is not quoted or sanitized, an authenticated attacker can inject shell commands through the `PPTPServerName` field.

## URL Registration and Handler Mapping

The `/userRpm/PPTPCfgRpm.htm` endpoint is registered in `httpWanPptpRpmInit`. The third argument of `httpRpmConfAdd` is the handler function `pptpCfgRpmHtm`, which proves that this URL is processed by `pptpCfgRpmHtm`.

```c
int httpWanPptpRpmInit()
{
  httpRpmConfAdd(2, "/userRpm/PPTPCfgRpm.htm", pptpCfgRpmHtm);
  webWanTypeAdd(7, "PPTPCfgRpm.htm");
  return wanStatusPptpApiInit();
}
```

<img width="839" height="185" alt="image" src="https://github.com/user-attachments/assets/f00f7891-459c-4490-96f3-648b18efa098" />


In IDA, this can be found by opening the Strings window, searching for `PPTPCfgRpm`, selecting `/userRpm/PPTPCfgRpm.htm`, and checking its cross references. The relevant cross reference points to `httpWanPptpRpmInit`.

## Parameter Input and Storage

Inside `pptpCfgRpmHtm`, the handler retrieves the `PPTPServerName` parameter by calling `httpGetEnv`. After trimming leading spaces, it copies the value into `&s[7]` with `strncpy`.

```c
src_3 = (const char *)httpGetEnv(a1, "PPTPServerName");
src_2 = src_3;
if ( src_3 )
{
  if ( *src_3 == 32 )
  {
    do
      ++src_2;
    while ( *src_2 == 32 );
  }
  LOBYTE(s[22]) = 0;
  strncpy((char *)&s[7], src_2, 0x3Fu);
}
```

Since `s` is declared as `_DWORD s[92]`, the expression `&s[7]` is equivalent to `s + 28`. This field is later used as `(a1 + 28)` in `pptpFormatCmd`.

<img width="825" height="303" alt="image" src="https://github.com/user-attachments/assets/534772ec-9e79-4f43-a7d3-d3854b1084b9" />


Insufficient Validation

The validation logic in `swChkPptpDomain` checks whether the value at `a1 + 28` is a dotted IP address. If the value is not an IP address, the function immediately returns `0`, which means validation success in this code path. As a result, arbitrary domain-like strings containing shell metacharacters can pass validation.

```c
int __fastcall swChkPptpDomain(int a1)
{
  int n5032;
  int v2;
  const char *cp;
  int v4;
  in_addr_t v5;
  int v6;

  n5032 = -1;
  if ( a1 )
  {
    n5032 = 5032;
    if ( a1 != -28 )
    {
      v2 = *(unsigned __int8 *)(a1 + 28);
      cp = (const char *)(a1 + 28);
      v4 = a1 + 28;
      if ( v2 )
      {
        if ( swChkDotIpAddr(v4) != 1 )
          return 0;
        v5 = inet_addr(cp);
        v6 = swChkLegalIpAddr(v5);
        n5032 = 5032;
        if ( v6 )
          return 0;
      }
    }
  }
  return n5032;
}
```

For example, the following payload is not a dotted IP address, so it is accepted as a domain value:

```sh
;echo test>/tmp/pptp;#
```

<img width="690" height="750" alt="image" src="https://github.com/user-attachments/assets/5a94fd1f-0545-4e0e-af89-1d6f1dac15b0" />


## Configuration Save and Connection Trigger

After validation, `pptpCfgRpmHtm` saves the configuration. If the request contains the `Connect` parameter, it starts the PPTP connection process by calling `swPptpLinkUpReq`.

```c
swSetPptpCfg(s);
if ( httpGetEnv(a1, "Connect") )
{
  swPptpLinkUpReq();
  taskDelay(60);
}
```

The connection function loads the saved PPTP configuration and calls `pptpCmdReq`.

```c
int swPptpLinkUpReq()
{
  _BYTE v1[4];
  int v2;
  _BYTE *v3;
  _BYTE v4[368];

  swGetPptpCfg(v4);
  v2 = 1;
  v3 = v4;
  msglogd(5, 1, "PPTP start connecting...");
  pptpCmdReq((int)v1);
  pppUserStart();
  return 0;
}
```

## Command Construction and Execution

In the static IP branch of `pptpCmdReq`, the firmware builds the PPTP command and executes it through `system()`.

```c
pppSetWanParameter(
  *(struct in_addr *)(v1 + 12),
  *(struct in_addr *)(v1 + 16),
  *(struct in_addr *)(v1 + 20),
  *(struct in_addr *)(v1 + 24));
pptpFormatCmd(v1, command__0);
return system(command__0);
```

The vulnerable command is constructed in `pptpFormatCmd`. The value at `a1 + 28`, which comes from `PPTPServerName`, is inserted into the command without quotes or shell escaping.

```c
int __fastcall pptpFormatCmd(int a1, char *command)
{
  sprintf(command, "pppd pptp pptp_server %s ", (const char *)(a1 + 28));
  ...
  sprintf(&command[v4], " user \"%s\" password \"%s\" ",
          (const char *)(a1 + 92),
          (const char *)(a1 + 212));
  ...
  return 0;
}
```

## The complete data flow is:

```text
/userRpm/PPTPCfgRpm.htm
  -> pptpCfgRpmHtm @ 0x479F00
     -> httpGetEnv("PPTPServerName")
     -> strncpy(s + 28, PPTPServerName, 0x3f)
     -> swChkPptpDomain / swChkPptpCfg insufficient validation
     -> swSetPptpCfg(s)
     -> swPptpLinkUpReq()
  -> swPptpLinkUpReq @ 0x4A2CD8
     -> swGetPptpCfg(v4)
     -> pptpCmdReq(...)
  -> pptpCmdReq @ 0x4D2CE4
     -> pptpFormatCmd(v1, command__0)
     -> system(command__0)
  -> pptpFormatCmd @ 0x4D2A80
     -> sprintf(command, "pppd pptp pptp_server %s ", PPTPServerName)
```

## Verification Notes

The issue was verified on a physical TL-MR3420 v1 device at `192.168.1.1`. Two Web endpoints were used during verification:

```text
PPTP configuration page:
http://192.168.1.1/userRpm/PPTPCfgRpm.htm

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

During manual verification, the vulnerable field is the `Server IP / Domain` input on the PPTP configuration page. The hidden debug shell was used only to confirm command execution and inspect temporary runtime state.

<img width="876" height="987" alt="image" src="https://github.com/user-attachments/assets/1f8a07ce-8c07-4410-b9cb-356b3c776d66" />



<img width="2141" height="591" alt="image" src="https://github.com/user-attachments/assets/5290d0bf-4285-4a67-9635-bce4c6c6d5c6" />



Conclusion

The TP-Link TL-MR3420 v1 firmware `3.12.3 Build 110222 Rel.34500n Beta` contains an authenticated command injection vulnerability in the PPTP configuration handler. The `PPTPServerName` parameter is accepted as a domain string without filtering shell metacharacters and is later inserted into a shell command using an unquoted `%s` before being executed by `system()`. An authenticated attacker can use this flaw to execute arbitrary commands on the router.
