$env:SWEEP_PACED='reply_0x1F_e.bin'
$env:SWEEP_LIST='reply_0x1C_c0.bin,reply_0x1C_c1.bin,reply_0x1C_c2.bin,reply_0x1C_c3.bin,reply_0x1C_c4.bin,reply_0x1C_c5.bin,reply_0x1C_c6.bin,reply_0x1C_c7.bin'
Start-Process -FilePath python -ArgumentList '-u','tools\mp\medius_server.py','--sweep' -WorkingDirectory 'G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling' -WindowStyle Hidden -RedirectStandardOutput 'logs\mp\server_run.out' -RedirectStandardError 'logs\mp\server_run.err'
Start-Sleep -Seconds 2
'started'
