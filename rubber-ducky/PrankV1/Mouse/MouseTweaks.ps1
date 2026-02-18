$pathMouse = "HKCU:\Control Panel\Mouse"
$pathCursors = "HKCU:\Control Panel\Cursors"

# Mouse settings
$mouseProperties = @{
    MouseTrails = "9"
    SwapMouseButtons = "1"
    MouseSpeed = "0"
    DoubleClickSpeed = "10000"
    DoubleClickHeight = "1"
    DoubleClickWidth = "1"
    MouseSensitivity = "1"
    MouseHoverTime = "5000"
    Beep = "Yes" # Enable the beep sound
}

# Loop through and apply mouse settings
$mouseProperties.GetEnumerator() | ForEach-Object { 
    Set-ItemProperty -Path $pathMouse -Name $_.Key -Value $_.Value 
}

# Cursor size adjustment
$cursorSizePath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $cursorSizePath -Name "CursorSize" -Value "32" # Example: Set size to 32 (default is 1–32)

# Restart Explorer to apply changes
Stop-Process -Name "explorer" -Force
Start-Process -FilePath "explorer.exe"