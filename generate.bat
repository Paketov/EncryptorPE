
FOR /L %%G IN (1,1,100) DO ( 
 call "%~dp0encrypt_pe.bat" "%~dp0_programm_for_encrypt.exe" "%~dp0bin\%%G.exe"
)