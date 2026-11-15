@echo off
rem Multiplayer: start the Medius capture server from WSL (avoids quote mangling).
cd /d "%~dp0..\.."
python -u tools\mp\medius_server.py %*
