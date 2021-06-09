@echo off
set WIRESHARK_PATH="C:\Program Files\Wireshark\Wireshark.exe"
set PLINK_PATH="C:\Program Files\PuTTY\plink.exe"

if NOT EXIST %WIRESHARK_PATH% (
	echo Cannot find Wireshark
	goto :depsFailed
)

if NOT EXIST %PLINK_PATH% (
	echo Cannot find plink
	goto :depsFailed
)

if "%1" == "" (
	goto :usage
) else (
	set REMOTE_HOST="%1"
)

if "%2" == "" (
	set INTERFACE=any
) else (
	set INTERFACE="%2"
)

if "%~3" == "" (
	set FILTER="not port 22"
) else (
	set FILTER=%~3
)

%PLINK_PATH% -batch -ssh root@%REMOTE_HOST% "echo All good" | findstr "All good"

if NOT "%errorlevel%" == "0" (
	echo "This script will automatically add the host key to the cache."
	echo "Press Ctrl+C to interrupt that"
	pause
	%PLINK_PATH% -ssh root@%REMOTE_HOST% "echo 'Host key added'"
)

%PLINK_PATH% -batch -ssh root@%REMOTE_HOST% "tcpdump -U -ni %INTERFACE% -s 0 -q -w - %FILTER% 2>/dev/null" | %WIRESHARK_PATH% -k -i -

goto :exit

:usage

echo Usage %0 HOST [IFACE] ["BPF FILTER"]
echo Example %0 172.16.0.1
echo Example %0 172.16.0.1 eth1
echo Example %0 172.16.0.1 eth1 "port 80 or 443"
echo Example %0 172.16.0.1 any "host 192.168.0.3 and port 443"
goto :exit

:depsFailed
@echo off

echo This script requires Wireshark and plink (part of PuTTy package)
echo Current paths: 
echo WIRESHARK_PATH =^> %WIRESHARK_PATH%
echo PLINK_PATH     =^> %PLINK_PATH%
goto :exit

:exit