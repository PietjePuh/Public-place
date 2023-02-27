@echo off
cd\
md %temp%

rem Get the public IP address using nslookup
nslookup myip.opendns.com resolver1.opendns.com | find "Address:" > %temp%\ip_address.txt
for /f "tokens=2" %%a in (%temp%\ip_address.txt) do set public_ip=%%a

echo Laptop Name: %computername%>%temp%\info_output.txt
echo User Name: %username%>>%temp%\info_output.txt
echo Your public IP address is %public_ip%>>%temp%\info_output.txt
ipconfig /all>>%temp%\info_output.txt
route print>>%temp%\info_output.txt
tracert 8.8.8.8>>%temp%\info_output.txt
nslookup google.com>>%temp%\info_output.txt
netsh lan show interfaces>>%temp%\info_output.txt
netsh wlan show all>>%temp%\info_output.txt
echo === Done gathering system information ===>>%temp%\info_output.txt
notepad %temp%\info_output.txt
pause>nul
