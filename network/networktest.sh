#!/bin/sh
timestamp=$(date "+%Y-%m-%d %H:%M:%S")
output_file="$HOME/info_output.txt"
echo "Current time: $timestamp" > "$output_file"
echo "Computer name: $(hostname)" >> "$output_file"
echo "User name: $(whoami)" >> "$output_file"
echo "Public IP address: $(curl -s https://api.ipify.org)" >> "$output_file"
ifconfig >> "$output_file"
route -n >> "$output_file"
traceroute 8.8.8.8 >> "$output_file"
nslookup google.com >> "$output_file"
echo "=== Done gathering system information ==="
open -a TextEdit "$output_file"
