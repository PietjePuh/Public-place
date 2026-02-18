#!/bin/bash

# linux-aliases.sh
# This script defines and tests a comprehensive set of aliases for Linux system management.

# Alias Definitions

# A: Update and upgrade the system
alias A='sudo apt update -y && sudo apt upgrade -y'

# B: Remove unnecessary packages and clean the local cache
alias B='sudo apt autoremove -y && sudo apt clean'

# C: Ensure system integrity by fixing broken packages and cleaning outdated files
alias C='sudo apt autoclean && sudo dpkg --configure -a && sudo apt-get check'

# D: Display disk usage and folder sizes
alias D='df -h && du -sh /*'

# E: Edit the hosts file
alias E='sudo nano /etc/hosts'

# F: Check the firewall status
alias F='sudo ufw status'

# G: Show the current Git status for repositories
alias G='git status'

# H: Display a summary of hardware information
alias H='lshw -short'

# I: Install a package quickly
alias I='sudo apt install -y'

# J: View system logs in an extended format
alias J='sudo journalctl -xe'

# K: Kill a process by its name
alias K='pkill -f'

# L: List all open network ports
alias L='sudo netstat -tuln'

# M: Monitor system resource usage interactively
alias M='htop'

# N: Display network configuration details
alias N='ifconfig'

# O: Open the current directory in a graphical file manager
alias O='xdg-open .'

# P: Ping a host to test network connectivity
alias P='ping -c 4'

# Q: Terminate all background jobs
alias Q='kill $(jobs -p)'

# R: Reboot the system
alias R='sudo reboot'

# S: Shut down the system immediately
alias S='sudo shutdown -h now'

# T: Test the speed of your internet connection
alias T='speedtest-cli'

# U: Update the GRUB bootloader configuration
alias U='sudo update-grub'

# V: View a list of currently active services
alias V='systemctl list-units --type=service --state=running'

# W: Display logged-in users and their activity
alias W='w'

# X: Show the type of X-session currently in use
alias X='echo $XDG_SESSION_TYPE'

# Y: Search for process details by name
alias Y='ps aux | grep'

# Z: Compress a folder into a zip archive
alias Z='zip -r'

# Export all aliases for the current session
export -p

# Test and debug each alias
echo "Testing aliases..."
echo "Testing alias A (Update and Upgrade):"; A
echo "Testing alias B (Clean Up):"; B
echo "Testing alias C (Integrity Check):"; C
echo "Testing alias D (Disk Usage):"; D
echo "Testing alias E (Edit Hosts File):"; echo "Edit skipped for automation."
echo "Testing alias F (Firewall Status):"; F
echo "Testing alias G (Git Status):"; echo "Run in a Git repo to test."
echo "Testing alias H (Hardware Info):"; H
echo "Testing alias I (Install Package):"; echo "Skipping installation for automation."
echo "Testing alias J (System Logs):"; echo "Run manually to avoid verbose logs."
echo "Testing alias K (Kill Process):"; echo "Requires a process to kill."
echo "Testing alias L (Open Ports):"; L
echo "Testing alias M (Monitor Resources):"; echo "Run interactively to test."
echo "Testing alias N (Network Config):"; N
echo "Testing alias O (Open Directory):"; echo "Run in a GUI environment to test."
echo "Testing alias P (Ping):"; P google.com
echo "Testing alias Q (Terminate Jobs):"; echo "Run with background jobs."
echo "Testing alias R (Reboot):"; echo "Reboot test skipped."
echo "Testing alias S (Shutdown):"; echo "Shutdown test skipped."
echo "Testing alias T (Internet Speed):"; T
echo "Testing alias U (Update GRUB):"; U
echo "Testing alias V (Active Services):"; V
echo "Testing alias W (Logged-in Users):"; W
echo "Testing alias X (Session Type):"; X
echo "Testing alias Y (Search Process):"; Y bash
echo "Testing alias Z (Zip Folder):"; echo "Run with a folder to zip."

echo "All tests completed. Review outputs for any errors."