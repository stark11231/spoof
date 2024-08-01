@echo off
title Building System : user
color a

:: Making System Restore point
cls
echo Making System Restore point just incase you forgot
echo.
wmic /namespace:\\root\default path systemrestore call createrestorepoint "Clarity Tweak", 100, 12 >nul 2>&1

@echo off

:: Making Registry Backup

if not exist "%UserProfile%\desktop\Clarity Registry Backup" mkdir "%UserProfile%\desktop\Clarity Registry Backup"

if exist "%UserProfile%\desktop\Clarity Registry Backup\HKEY_LOCAL_MACHINE_backup.reg" goto skip_local
echo Exporting HKEY_LOCAL_MACHINE registry hive...
reg export HKEY_LOCAL_MACHINE "%UserProfile%\desktop\Clarity Registry Backup\HKEY_LOCAL_MACHINE_backup.reg"

:skip_local

if exist "%UserProfile%\desktop\Clarity Registry Backup\HKEY_CURRENT_USER_backup.reg" goto skip_current
echo Exporting HKEY_CURRENT_USER registry hive...
reg export HKEY_CURRENT_USER "%UserProfile%\desktopClarity Registry Backup\HKEY_CURRENT_USER_backup.reg"

:skip_current

:runfps

::Disable Preemption
cls
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t Reg_DWORD /d "0" /f

::Improve microstuttering
cls
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t Reg_DWORD /d "1" /f

::Startup Optimizer
cls
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f

::Remove Windows Ads
cls
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f 

::Remove Windows Game Recording
cls
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f 

::Disk Optimizer
cls
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0" /f 

::Cache Menagement
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "180" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "fa00" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "12d" /f

::Disable Windows Notifications
cls
echo Disabling Windows notifications...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
echo Windows notifications disabled.

::Disable Transparency Effect
cls
echo Disabling transparency effect
powershell -c "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Type DWord -Value 0"
powershell -c "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'DisableAcrylicBackgroundOnLogon' -Type DWord -Value 1"

::Disable Windows background apps
cls
echo Disable Windows background apps
Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f

::Set System Responsiveness
cls
echo Setting System Responsiveness...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 00000000 /f
echo System Responsiveness set.

::Enable Game Mode
cls
echo Enabling Game Mode...
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 1 /f
echo Game Mode enabled.

::Disable Hibernate
cls
echo disable hibernate
echo.
echo disable hibernate
powercfg -h off

::Setting number of processors
cls
@echo off
echo Setting number of processors in boot advanced options...
bcdedit /set {current} numproc %NUMBER_OF_PROCESSORS%
echo Number of processors set to %NUMBER_OF_PROCESSORS%.

:: DisablePowerThrottling
cls
@echo DisablePowerThrottling
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

:: Apply BCD Tweaks for lower Input Delay
cls
@echo Applying BCD Tweaks for lower Input Delay
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes

:: Game Optimizations
cls
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

:: Debloat Windows & Remove Preinstalled Programs
cls
PowerShell -command "Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.GetHelp | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.3DBuilder | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.Print3D | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage EclipseManager | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage ActiproSoftwareLLC | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage AdobeSystemsIncorporated.AdobePhotoshopExpress | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage 'D5EA27B7.Duolingo-LearnLanguagesforFree' | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage PandoraMediaInc | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage CandyCrush | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage *Wunderlist* | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage *Flipboard* | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage *Twitter* | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage *Sway* | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage *disney* | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingTravel | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingHealthAndFitness | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingFoodAndDrink | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage Microsoft.BioEnrollment | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage ContentDeliveryManager | Remove-AppxPackage"
PowerShell -command "Get-AppxPackage 'Microsoft.Advertising.Xaml' | Remove-AppxPackage"

:: Disable services listed in the provided gist
cls
sc config AdobeARMservice start=disabled
sc config CDPSvc start=disabled
sc config DiagTrack start=disabled
sc config dmwappushservice start=disabled
sc config MessagingService_22551 start=disabled
sc config PrintNotify start=disabled
sc config RetailDemo start=disabled
sc config WMPNetworkSvc start=disabled
sc config SysMain start=disabled
sc config Spooler start=disabled
sc config WerSvc start=disabled

::Windows VisualEffects Tweaks
cls
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f

::Restore Health your PC
cls
echo Running SFC scan...
sfc /scannow

:: Disable Windows Game Mode
cls
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\GameBar" /v AllowGameMode /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f

:: Disable Nagle's algorithm
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpAckFrequency /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TCPNoDelay /t REG_DWORD /d 1 /f

:: Set Ultimate Performance
cls
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61

echo The Ultimate Performance power plan has been set.


:: Clear temp files
cls
echo Clearing temp files...
del /f /q %temp%\*.*
del /f /q %systemroot%\temp\*.*

:: Clear Internet Explorer cache
cls
echo Clearing Internet Explorer cache...
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8

:: Clear Windows Update cache
cls
echo Clearing Windows Update cache...
net stop wuauserv
del /f /q %systemroot%\SoftwareDistribution\*.*
net start wuauserv

:: Clear various cache and temp folders
cls
echo Clearing other cache and temp folders...
del /f /q %localappdata%\Microsoft\DirectX Shader Cache\*.*
del /f /q %localappdata%\Microsoft\Windows\INetCache\*.*
del /f /q %localappdata%\Microsoft\Windows\INetCookies\*.*
del /f /q %localappdata%\Microsoft\Windows\Explorer\thumbcache_*.db
del /f /q %ProgramData%\Microsoft\Windows Defender\Scans\History\*.*
del /f /q %windir%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\DeliveryOptimization\*.*

:: Delete previous Windows installations
cls
echo Deleting previous Windows installations...
dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase

:: Clear other cache and log folders
cls
echo Clearing other cache and log folders...
rd /s /q %SystemRoot%\system32\wer\Reports\
rd /s /q %SystemRoot%\Feedback\
del /q /f /s %SystemRoot%\Prefetch\*.*
del "%LocalAppData%\Microsoft\Windows\INetCache\." /s /f /q
del "%AppData%\Local\Microsoft\Windows\INetCookies\." /s /f /q
del "%temp%" /s /f /q
taskkill /IM "Discord.exe" /F
del "%AppData%\Discord\Cache\." /s /f /q
del "%AppData%\Discord\Code Cache\." /s /f /q
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
del "C:\Windows\System32\SleepStudy" /s /f /q
rd "%AppData%\Local\Microsoft\Windows\INetCache" /s /q
rd "%AppData%\Local\Microsoft\Windows\INetCookies" /s /q
rd "%LocalAppData%\Microsoft\Windows\WebCache" /s /q
rd "%AppData%\Local\Temp\" /s /q
rd "%SystemDrive%\$GetCurrent" /s /q
rd "%SystemDrive%\$SysReset" /s /q
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q
rd "%SystemDrive%\$WinREAgent" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
rd %LocalAppData%\Temp /s /q
rd %LocalAppData%\Temp\mozilla-temp-files /s /q
rd "%SystemRoot%\System32\SleepStudy" /s /q

:: Set the VALORANT AppData folder path
cls
set VALORANT_PATH=%LocalAppData%\VALORANT\Saved

echo Clearing Crashes folder...
del /f /q /s "%VALORANT_PATH%\Crashes\*.*"
rd /s /q "%VALORANT_PATH%\Crashes"
del /f /q /s "%VALORANT_PATH%\Logs\*.*"
rd /s /q "%VALORANT_PATH%\Logs"
del /f /q /s "%VALORANT_PATH%\WebCache\*.*"
rd /s /q "%VALORANT_PATH%\WebCache"


:: Clear the Windows temp, Prefetch, and dllcache folders
cls
echo Clearing Windows temp, Prefetch, and dllcache folders...
for %%F in (temp, Prefetch, system32\dllcache) do (
  rd /s /q "%windir%\%%F"
  md "%windir%\%%F"
)

:: Clear the System Drive Temp folder
cls
echo Clearing System Drive Temp folder...
rd /s /q "%SystemDrive%\Temp"
md "%SystemDrive%\Temp"

:: Clear the user's History, Temporary Internet Files, Temp, Recent, and Cookies folders
cls
echo Clearing user-specific folders...
for %%F in ("Local Settings\History", "Local Settings\Temporary Internet Files", "Local Settings\Temp", Recent, Cookies) do (
  rd /s /q "%USERPROFILE%\%%F"
  md "%USERPROFILE%\%%F"
)


:: Delete log files
cls
echo Deleting log files...
cd /
del *.log /a /s /q /f


:: Adjust visual settings for performance
cls
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 90 12 03 80 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f

:: Disable Windows Game DVR
cls
echo Disabling Windows Game DVR...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f

:: Optimize system performance for best performance
cls
echo Optimizing system performance for best performance...
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f

:: Reduce Foreground Lock Timeout
cls
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f

:: Disable Startup Delay
cls
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f

:: Disable Prefetch
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f

:: Disable Superfetch
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f

:: Disable Last Access Update
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f

:: Optimize System Responsiveness
cls
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f

:: Reset Network Stack
cls
echo Resetting Network Stack...
ipconfig /flushdns
netsh int ip reset
netsh winsock reset
netsh winhttp reset proxy
netsh winsock reset
netsh int ip reset
netsh int ipv4 reset
netsh int ipv6 reset

echo all reset continue to tweaks

:: Valorant ports
cls
echo Adding Valorant ports...
netsh advfirewall firewall add rule name="Valorant - UDP" dir=in action=allow protocol=UDP localport=7000-9000

:: Steam ports
cls
echo Adding Steam game download ports...
netsh advfirewall firewall add rule name="Steam - TCP" dir=in action=allow protocol=TCP localport=27015-27050

:: Set Google DNS as the primary DNS
cls
echo Setting Cloudflare DNS as the secondary DNS server for Wi-Fi and Ethernet connections...
netsh interface ip set dns "Wi-Fi" static 1.1.1.1
netsh interface ip add dns "Wi-Fi" 1.0.0.1 index=2
netsh interface ip set dns "Ethernet" static 1.1.1.1
netsh interface ip add dns "Ethernet" 1.0.0.1 index=2

:: Disable Network Throttling
cls
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "FFFFFFFF" /f

:: Optimize System Responsiveness for Network Performance
cls
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f

:: Increase TCP Connections
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "00fffffe" /f

:: Disable Nagle's Algorithm
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /v "TCPNoDelay" /t REG_DWORD /d "1" /f

:: Apply Network Tweaks
cls
netsh int tcp set global autotuninglevel=normal
netsh interface 6to4 set state disabled
netsh int isatap set state disable
netsh int tcp set global timestamps=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global chimney=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
netsh int ip set global icmpredirects=disabled
netsh int tcp set security mpp=disabled profiles=disabled
netsh int ip set global multicastforwarding=disabled
netsh int tcp set supplemental internet congestionprovider=ctcp
netsh interface teredo set state disabled
netsh winsock reset
netsh int isatap set state disable
netsh int ip set global taskoffload=disabled
netsh int ip set global neighborcachelimit=4096
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f

exit

