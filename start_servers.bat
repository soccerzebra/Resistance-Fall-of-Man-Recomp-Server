@echo off
rem ---------------------------------------------------------------------------
rem Start the Resistance: Fall of Man multiplayer server bundle:
rem   medius_server  lobby          TCP 10071-10076
rem   svo_http       SVO pages      TCP 10080
rem   svo_tls        ticket login   TCP 10443
rem   dme_server     game relay     TCP+UDP 10079
rem Logs: data\*.log. Stop with stop_servers.bat.
rem
rem Remote play: set MP_PUBLIC_HOST to this machine's public IP or domain first, e.g.
rem   set MP_PUBLIC_HOST=r1.rfom.online & start_servers.bat
rem (the public server is the Linux one: start_servers.sh, deploy\README.md)
rem and forward TCP 10071-10080, 10443 and UDP 10079 to it.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"
if not defined MP_PUBLIC_HOST set "MP_PUBLIC_HOST=127.0.0.1"
set "MEDIUS_RESPOND=1"
set "SWEEP_PACED=reply_0x1F_e.bin"
call "%~dp0stop_servers.bat" >nul 2>&1
echo Starting servers for clients connecting to %MP_PUBLIC_HOST% ...
start "" /b pythonw -u medius_server.py --sweep
start "" /b pythonw -u svo_http.py 10080
start "" /b pythonw -u svo_tls.py 10443
start "" /b pythonw -u dme\dme_server.py
echo Started. Logs in data\.
echo Clients need data\svo_root.der (created on the first start of svo_tls).
