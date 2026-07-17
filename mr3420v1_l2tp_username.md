# Command Injection Vulnerability in TP-Link TL-MR3420 v1 L2TP Configuration via `L2TPName` Parameter

## Overview

  * Vendor: TP-Link
  * Product: TL-MR3420
  * Hardware Version: MR3420 v1
  * Tested Firmware Version: `3.12.3 Build 110222 Rel.34500n Beta`
  * Vulnerability Type: Authenticated Command Injection
  * Affected Component: `httpd` Web Management Interface
  * Affected Page: `/userRpm/L2TPCfgRpm.htm`
  * Trigger Parameter: `L2TPName`
  * Default Web Credential Used in Testing: `admin / admin`
  * Impact: Remote command execution with the privilege of the `httpd` process, which is typically root on this device.

## Vulnerability Basic Information

  * URL Registration Function: `httpWanL2tpRpmInit` at `0x47C13C`
  * Web Request Handler: `l2tpCfgRpmHtm` at `0x47B050`
  * Connection Trigger Function: `swL2tpLinkUpReq` at `0x4A3C4C`
  * Command Execution Function: `l2tpCmdReq` at `0x4D37CC`
  * Vulnerable Command Construction Function: `l2tpFormatCmd` at `0x4D342C`
  * Vulnerability Point: `sprintf(&command[v4], " user \"%s\" password \"%s\" ", (const char *)(a1 + 92), (const char *)(a1 + 212));`
  * Prerequisites:
    * The attacker has valid access to the router Web management interface.
    * The router accepts an L2TP configuration request containing the `L2TPName` parameter.
    * The L2TP connection path is triggered, for example by submitting the page with the `Connect` parameter.

## Vulnerability Description

The L2TP WAN configuration page reads the user-controlled `L2TPName` parameter from the HTTP request and stores it into the L2TP configuration structure at offset `+92`. The value is later loaded by the connection logic and passed to `l2tpFormatCmd`.

In `l2tpFormatCmd`, the saved L2TP username is inserted into a shell command inside double quotes and the final command is executed with `system()`. Double quotes do not prevent shell command substitution. Therefore, a username containing backtick command substitution can be evaluated by the shell when `system()` executes the constructed command.

## URL Registration and Handler Mapping

The `/userRpm/L2TPCfgRpm.htm` endpoint is registered in `httpWanL2tpRpmInit`. The third argument of `httpRpmConfAdd` is the handler function `l2tpCfgRpmHtm`, which proves that this URL is processed by `l2tpCfgRpmHtm`.

```c
int httpWanL2tpRpmInit()
{
  httpRpmConfAdd(2, "/userRpm/L2TPCfgRpm.htm", l2tpCfgRpmHtm);
  webWanTypeAdd(6, "L2TPCfgRpm.htm");
  return wanStatusL2tpApiInit();
}
```
<img width="717" height="270" alt="image" src="https://github.com/user-attachments/assets/f99f080a-c817-4613-80fb-1cbb917dbbda" />

<img width="966" height="282" alt="image" src="https://github.com/user-attachments/assets/a5b4eb6e-ba8c-4e9a-bf9c-1572264d1b0c" />

<img width="888" height="192" alt="image" src="https://github.com/user-attachments/assets/ec9adcdb-b391-4fff-9a91-a3df7bbf8a43" />


In IDA, this can be found by opening the Strings window, searching for `L2TPCfgRpm`, selecting `/userRpm/L2TPCfgRpm.htm`, and checking its cross references. The relevant cross reference points to `httpWanL2tpRpmInit`.

## Parameter Input and Storage

Inside `l2tpCfgRpmHtm`, the handler retrieves the `L2TPName` parameter by calling `httpGetEnv`. This parameter corresponds to the `Username` field in the L2TP WAN configuration page. The value is copied into `&s[23]` with `strncpy`.

```c
if ( httpGetEnv(a1, "Connect") || httpGetEnv(a1, "Save") )
{
  src = (const char *)httpGetEnv(a1, "L2TPName");
  if ( src )
  {
    LOBYTE(s[52]) = 0;
    strncpy((char *)&s[23], src, 0x77u);
  }
  else
  {
    memset(&s[23], 0, 0x78u);
  }

  src_1 = (const char *)httpGetEnv(a1, "L2TPPwd");
  if ( src_1 )
  {
    LOBYTE(s[82]) = 0;
    strncpy((char *)&s[53], src_1, 0x77u);
  }
}
```

Since `s` is declared as `_DWORD s[92]`, the expression `&s[23]` is equivalent to byte offset `23 * 4 = 92`. This field is later used as `(a1 + 92)` in `l2tpFormatCmd`.

## Configuration Save and Connection Trigger

After the request parameters are copied and validated, `l2tpCfgRpmHtm` saves the configuration. If the request contains the `Connect` parameter, it starts the L2TP connection process by calling `swL2tpLinkUpReq`.

```c
swSetL2tpCfg(s);
if ( httpGetEnv(a1, "Connect") )
{
  swL2tpLinkUpReq();
  taskDelay(60);
}
```

The connection function loads the saved L2TP configuration and calls `l2tpCmdReq`.

```c
int swL2tpLinkUpReq()
{
  _BYTE v1[4];
  int v2;
  _BYTE *v3;
  _BYTE v4[368];

  swGetL2tpCfg(v4);
  v2 = 1;
  v3 = v4;
  msglogd(5, 1, "L2TP start connecting...");
  l2tpCmdReq((int)v1);
  pppUserStart();
  return 0;
}
```

<img width="552" height="423" alt="image" src="https://github.com/user-attachments/assets/334c8b54-086e-4e38-b863-0c27c2e4ce62" />


## Command Construction and Execution

In the static IP branch of `l2tpCmdReq`, the firmware builds the L2TP command and executes it through `system()`.

```c
else
{
  pppSetWanParameter(v3[3], v3[4], v3[5], v3[6]);
  l2tpFormatCmd((int)v3, command__1);
  system(command__1);
  sleep(2u);
  sprintf(command__1, "echo \"c %s\" > %s", "TP_L2TP", "/var/run/xl2tpd/l2tp-control");
  return system(command__1);
}
```
<img width="1071" height="1071" alt="image" src="https://github.com/user-attachments/assets/f06c1e96-98cd-4ed0-a267-4398365e5211" />


The vulnerable command is constructed in `l2tpFormatCmd`. The value at `a1 + 92`, which comes from `L2TPName`, is inserted into the command inside double quotes.

```c
int __fastcall l2tpFormatCmd(int a1, char *command)
{
  sprintf(command, "xl2tpd -c %s", "/tmp/l2tpd.conf");

  sprintf(
    &command[strlen(command)],
    " user \"%s\" password \"%s\" ",
    (const char *)(a1 + 92),
    (const char *)(a1 + 212)
  );

  sprintf(&command[strlen(command)], " httpd-pid %d", linkModeThreadPid);
  ...
  return 0;
}
```

<img width="1287" height="507" alt="image" src="https://github.com/user-attachments/assets/b27fecc9-59e6-4272-ac38-65118016cf59" />


Although the username is wrapped in double quotes, command substitution is still interpreted by the shell. As a result, the user-controlled `L2TPName` value can affect the shell command executed by `system()`.

## The complete data flow is:

```text
/userRpm/L2TPCfgRpm.htm
  -> l2tpCfgRpmHtm @ 0x47B050
     -> httpGetEnv("L2TPName")
     -> strncpy((char *)&s[23], L2TPName, 0x77)
     -> swSetL2tpCfg(s)
     -> swL2tpLinkUpReq()
  -> swL2tpLinkUpReq @ 0x4A3C4C
     -> swGetL2tpCfg(v4)
     -> l2tpCmdReq(...)
  -> l2tpCmdReq @ 0x4D37CC
     -> l2tpFormatCmd((int)v3, command__1)
     -> system(command__1)
  -> l2tpFormatCmd @ 0x4D342C
     -> sprintf(..., " user \"%s\" password \"%s\" ", L2TPName, L2TPPwd)
```

## Verification Notes

The issue was verified on a physical TL-MR3420 v1 device at `192.168.1.1`. Two Web endpoints were used during verification:

```text
L2TP configuration page:
http://192.168.1.1/userRpm/L2TPCfgRpm.htm

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

During manual verification, the vulnerable field is the `Username` input on the L2TP configuration page. The hidden debug shell was used only to confirm command execution and inspect temporary runtime state.

<img width="927" height="993" alt="image" src="https://github.com/user-attachments/assets/0b701c4b-f132-422d-af3b-46c35f8f3e50" />


<img width="2067" height="405" alt="image" src="https://github.com/user-attachments/assets/dc674c7f-76ce-4d46-9192-3b28029e6552" />


Conclusion

The TP-Link TL-MR3420 v1 firmware `3.12.3 Build 110222 Rel.34500n Beta` contains an authenticated command injection vulnerability in the L2TP configuration handler. The `L2TPName` parameter is copied into the L2TP configuration structure and later inserted into a shell command before being executed by `system()`. Because the value is only wrapped in double quotes and is not shell-escaped, command substitution can be interpreted by the shell. An authenticated attacker can use this flaw to execute arbitrary commands on the router.
