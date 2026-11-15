@echo off
rem Multiplayer: launch the Medius capture server in its own minimised window.
rem Lives here so a WSL shell can start it without quoting -- `cmd /c start
rem "title" ...` mangles the title through the WSL -> cmd.exe translation.
start "mp-server" /min cmd /c "cd /d G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling && python -u tools\mp\medius_server.py --sweep > logs\mp\server_run.out 2>&1"
