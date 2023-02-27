# install the console to your deafult powershell 
$sourcePath = $MyInvocation.MyCommand.Path
$destinationPath = "$env:UserProfile\Documents\WindowsPowerShell\profile.ps1"
Copy-Item $sourcePath $destinationPath

# Set console background color to black
$host.ui.RawUI.BackgroundColor = "Black"

# Set console foreground color
$host.ui.RawUI.ForegroundColor = "White"

# Set console window title
$host.ui.RawUI.WindowTitle = "The Code Cave"

# Set cursor position to (10, 10)
$host.ui.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates(10, 10)

# Set console buffer size to 120 columns by 1000 rows
$host.ui.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(120, 1000)

# Set PSReadLine options for syntax highlighting
Set-PSReadLineOption -Colors @{
    Command = [ConsoleColor]::Green
    Parameter = [ConsoleColor]::Cyan
    Operator = [ConsoleColor]::Magenta
    Variable = [ConsoleColor]::Yellow
    String = [ConsoleColor]::DarkCyan
    Number = [ConsoleColor]::DarkYellow
    Member = [ConsoleColor]::Gray
    Type = [ConsoleColor]::White
    Keyword = [ConsoleColor]::Red
}


# Set custom prompt settings
function prompt {
    Write-Host -NoNewline "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') " -ForegroundColor Red
    Write-Host -NoNewline "$($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) " -ForegroundColor Green
    return " "
}


#alias
Set-Alias edit notepad
set-Alias np++ "C:\Program Files\Notepad++\notepad++.exe"
set-Alias VSC "C:\Users\%username%\AppData\Local\Programs\Microsoft VS Code\Code.exe"
set-alias c clear # use CTRL + L
function Get-ProcessOwner {
    Get-Process | Select-Object *,@{Name='Owner';Expression={$_.GetOwner().User}} | Sort-Object Owner
}

Set-Alias -Name gpo -Value Get-ProcessOwner

##Get-help  -full | more
##get-command   *user* or *-aduser