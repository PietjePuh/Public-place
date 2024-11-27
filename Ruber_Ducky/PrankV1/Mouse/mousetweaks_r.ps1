$pathMouse = "HKCU:\Control Panel\Mouse"
$pathCursors = "HKCU:\Control Panel\Cursors"

# Reset mouse settings to defaults
$mouseProperties = @{
    MouseTrails = "0"             # Disable mouse trails
    SwapMouseButtons = "0"        # Restore default button layout
    MouseSpeed = "1"              # Set default speed
    DoubleClickSpeed = "500"      # Restore double-click speed
    DoubleClickHeight = "4"       # Default height
    DoubleClickWidth = "4"        # Default width
    MouseSensitivity = "10"       # Restore pointer precision
    MouseHoverTime = "400"        # Default hover time
    Beep = "No"                   # Disable beep sound
}

# Apply default settings
$mouseProperties.GetEnumerator() | ForEach-Object {
    Set-ItemProperty -Path $pathMouse -Name $_.Key -Value $_.Value
}

# Restore default cursor size
$cursorSizePath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $cursorSizePath -Name "CursorSize" -Value "1" # Default size is 1

# Restart Explorer to apply changes
Stop-Process -Name "explorer" -Force
Start-Process -FilePath "explorer.exe"
