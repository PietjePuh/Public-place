#this file saves on a 
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$output_file = "$env:TEMP\info_output.txt"

"Current time: $timestamp" | Out-File $output_file
"Computer name: $env:COMPUTERNAME" | Out-File $output_file -Append
"User name: $env:USERNAME" | Out-File $output_file -Append
"Public IP address: $(Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing).Content" | Out-File $output_file -Append
ipconfig /all | Out-File $output_file -Append
route print | Out-File $output_file -Append
tracert 8.8.8.8 | Out-File $output_file -Append
nslookup google.com | Out-File $output_file -Append
netsh lan show interfaces | Out-File $output_file -Append
netsh wlan show all | Out-File $output_file -Append
Write-Host "=== Done gathering system information ==="
notepad $output_file
