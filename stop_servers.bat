@echo off
rem Stop the server bundle started by start_servers.bat.
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -match '(medius_server|svo_http|svo_tls|dme_server)\.py' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; 'stopped ' + $_.ProcessId }"
