@echo off
cd /d G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling
set "SWEEP_PACED=reply_0x1F_e.bin"
set "SWEEP_LIST=reply_0x1C_c0.bin,reply_0x1C_c1.bin,reply_0x1C_c2.bin,reply_0x1C_c3.bin,reply_0x1C_c4.bin,reply_0x1C_c5.bin,reply_0x1C_c6.bin,reply_0x1C_c7.bin"
start "" /b "C:\Users\joshu\AppData\Local\Programs\Python\Python312\pythonw.exe" -u tools\mp\medius_server.py --sweep > logs\mp\server_run.out 2>&1
