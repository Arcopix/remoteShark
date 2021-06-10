@echo off

SETLOCAL

set WIRESHARK_PATH="%ProgramFiles%\Wireshark\Wireshark.exe"
set PLINK_PATH="%ProgramFiles%\PuTTY\plink.exe"

if "%1" == "/?" goto :usage
if "%1" == "/h" goto :usage
if "%1" == "-h" goto :usage
if "%1" == "--help" goto :usage

:: Check for Wireshark bin
if NOT EXIST %WIRESHARK_PATH% (
	echo Cannot find Wireshark
	goto :depsFailed
)

:: Check for plink bin
if NOT EXIST %PLINK_PATH% (
	echo Cannot find plink
	goto :depsFailed
)

if "%1" == "" (
	goto :usage
) else (
	set REMOTE_HOST="%1"
)

:: Try to ping the host to verify capability to connect
ping -w 2 -n 1 %REMOTE_HOST% >NUL 2>&1
if NOT "%errorlevel%" == "0" (
	echo Cannot ping/resolve the remote host
	goto :exit
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

:: Try to login and generate output of "All good" to check for connection issues
%PLINK_PATH% -batch -ssh root@%REMOTE_HOST% "echo All good" 2>NUL | findstr "All good" >NUL

if NOT "%errorlevel%" == "0" (
	goto :addHostKey
)

:run

:: Login and run tcpdump
:: Redirect STDERR to NULL - otherwize it may corrupt the wireshark input
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

echo This script requires Wireshark and plink (part of PuTTy package)
echo Current paths: 
echo WIRESHARK_PATH =^> %WIRESHARK_PATH%
echo PLINK_PATH     =^> %PLINK_PATH%
goto :exit

:addHostKey

echo This script will automatically add the host key to the cache.
echo Press Ctrl+C to interrupt that
timeout /t 5 >NUL

echo y | %PLINK_PATH% -ssh root@%REMOTE_HOST% "echo 'Host key added'" 2>NUL | findstr "Host key added"

if NOT "%errorlevel%" == "0" (
	echo Connection failed
	goto :exit
)

goto :run

:exit

ENDLOCAL