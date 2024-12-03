@echo off
title WELCOOME PROJECT  

::Blank/Color Character
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (set "DEL=%%a" & set "COL=%%b")

:main
mode 69,11
chcp 65001
cls                                
echo.                                                                                      
echo.%col%[38;5;118m  ██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗
echo.%col%[38;5;118m  ██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝
echo.%col%[38;5;118m  ██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗  
echo.%col%[38;5;118m  ██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  
echo.%col%[38;5;118m  ╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗
echo.%col%[38;5;118m   ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝                                                                                      
pause >nul
goto :home


:home
cls
title CONFIG
mode 50,8
echo.
echo.%col%[38;5;160m   ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ 
echo.%col%[38;5;160m  ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ 
echo.%col%[38;5;160m  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗
echo.%col%[38;5;160m  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║
echo.%col%[38;5;160m  ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝
echo.%col%[38;5;160m   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝ 
pause >nul
goto :WE                                               
 
:WE
cls
title PROJECT WORKING BUYS ARZEN>ARZEN.RDCW
mode 85,8
echo.
echo.%col%[38;5;220m               ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗██╗███╗   ██╗ ██████╗ 
echo.%col%[38;5;220m               ██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝██║████╗  ██║██╔════╝ 
echo.%col%[38;5;220m               ██║ █╗ ██║██║   ██║██║  ██║█████╔╝ ██║██╔██╗ ██║██║  ███╗
echo.%col%[38;5;220m               ██║███╗██║██║   ██║██║  ██║██╔═██╗ ██║██║╚██╗██║██║   ██║
echo.%col%[38;5;220m               ╚███╔███╔╝╚██████╔╝██████╔╝██║  ██╗██║██║ ╚████║╚██████╔╝
echo.%col%[38;5;220m               ╚══╝╚══╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
pause >nul
cls    
:Undergroud1
chcp 65001
mode 40,10
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
cls
netsh interface ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent
cls
netsh int tcp set global maxsynretransmissions=8
cls
netsh int tcp set global rss=enabled
cls
netsh interface ipv4 set subinterface "Ethernet" mtu=1640 store=persistent
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global netdma=enabled
cls
netsh int tcp set global dca=enabled
cls
netsh int tcp set global nonsackrttresiliency=disabled
cls
netsh int tcp set global ecncapability=disabled
cls
ping -n 3 localhost>nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "200" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "20000" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "100" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
cls

netsh int tcp set global rsc=enabled
cls
netsh int tcp set global ecncapability=disabled
cls
netsh int tcp set global autotuninglevel=disabled
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global chimney=disabled
cls
netsh int tcp set global dca=enabled
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global netdma=enabled
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global timestamps=disabled
cls
netsh int tcp set global nonsackrttresiliency=disabled
cls
netsh int tcp set supplemental template=custom icw=10
cls 
netsh int tcp set heuristics disabled
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global chimney=enabled
cls
netsh int tcp set global autotuninglevel=normal
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global ecncapability=disabled
cls
netsh int tcp set global timestamps=disabled
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global autotuninglevel=disabled
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global chimney=enabled
cls
netsh int tcp set global dca=enabled
cls
netsh interface ipv4 set subinterface "Wireless Network Connection" mtu=1500 store=persistent
cls
netsh int tcp set global netdma=enabled
cls
netsh int tcp set global timestamps=disabled
cls
netsh int tcp set global nonsackrttresiliency=disabled
cls
netsh int tcp set supplemental template=custom icw=10
cls
netsh int tcp set global fastopen=enabled
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global chimney=enabled
cls
netsh int tcp set global autotuninglevel=normal
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global ecncapability=disabled
cls
netsh int tcp set global timestamps=disabledstart cmd.exe /k ping  127.0.0.1  -t -l-n 65000
cls
netsh int tcp set global congestionprovider=none
cls
netsh int tcp set global autotuninglevel=high
cls
netsh int tcp set global chimney=disabled
cls
netsh int tcp set global dca=enable
cls
netsh int tcp set global netdma=enable
cls
netsh int tcp set heuristics enable
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global timestamps=enable
cls
netsh interface tcp set global rss=enabled chimney=automatic netdma=disabled dca=disabled autotuninglevel=normal
cls
netsh interface tcp set global congestionprovider=none ecncapability=disabled timestamps=disabled 
cls
netsh interface tcp set global initialrto=3000
cls
netsh interface ipv4 set subinterface "Internet" mtu=80 store=persistent
cls
netsh interface ipv4 set subinterface "Ethernet" mtu=80 store=persistent
cls
netsh interface tcp set global autotuning=normal
cls
netsh int tcp set global congestionprovider=none
cls
netsh int tcp set global autotuninglevel=high
cls
netsh int tcp set global chimney=disabled
cls
netsh interface ipv4 set subinterface "Local Area Connection" mtu=150 store=persistent
cls
netsh int tcp set global rss=default
cls
netsh int tcp set heuristics disabled
cls
netsh interface ipv4 set subinterface "Local Area Connection" mtu=4000 store=persistent
cls
netsh interface ipv4 set subinterface "Internet" mtu=4000 store=persistent
cls
netsh interface ipv4 set subinterface "Ethernet" mtu=5000 store=persistent
cls
netsh int tcp set global congestionprovider=none
cls
netsh int tcp set global autotuninglevel=high
cls	
netsh int tcp set global chimney=disabled
cls
netsh int tcp set global dca=enable
cls
netsh int tcp set global netdma=enable
cls
netsh int tcp set heuristics enable
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global timestamps=enable
cls
ping -n 3 localhost>nul
cls
sc config WSearch start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config SNMPTRAP start= disabled
cls
sc config SCPolicySvc start= disabled
cls
sc config SCardSvr start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config RpcLocator start= disabled
cls
sc config WPCSvc start= disabled
cls
sc config CscService start= disabled
cls
sc config napagent start= disabled
cls
sc config Netlogon start= disabled
cls
sc config MSiSCSI start= disabled
cls
sc config iphlpsvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config CertPropSvc start= disabled
cls
sc config PeerDistSvc start= disabled
cls
sc config bthserv start= disabled
cls
sc config WSearch start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config SNMPTRAP start= disabled
cls
sc config SCPolicySvc start= disabled
cls
sc config SCardSvr start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config RpcLocator start= disabled
cls
sc config WPCSvc start= disabled
cls
sc config CscService start= disabled
cls
sc config napagent start= disabled
cls
sc config Netlogon start= disabled
cls
sc config MSiSCSI start= disabled
cls
sc config iphlpsvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config CertPropSvc start= disabled
cls
sc config PeerDistSvc start= disabled
cls
sc config bthserv start= disabled
cls
sc config WSearch start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config SNMPTRAP start= disabled
cls
sc config SCPolicySvc start= disabled
cls
sc config SCardSvr start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config RpcLocator start= disabled
cls
sc config WPCSvc start= disabled
cls
sc config CscService start= disabled
cls
sc config napagent start= disabled
cls
sc config Netlogon start= disabled
cls
sc config MSiSCSI start= disabled
cls
sc config iphlpsvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config CertPropSvc start= disabled
cls
sc config PeerDistSvc start= disabled
cls
sc config bthserv start= disabled
cls
sc config SensrSvc start= disabled
cls
sc config WinHttpAutoProxySvc start= disabled
cls
sc config WinRM start= disabled
cls
sc config WerSvc start= disabled
cls
sc config WcsPlugInService start= disabled
cls
sc config ALG start= disabled
cls
sc config BDESVC start= disabled
cls
sc config EFS start= disabled
cls
sc config Fax start= disabled
cls
sc config hidserv start= disabled
cls
sc config SessionEnv start= disabled
cls
sc config TermService start= disabled
cls
sc config UmRdpService start= disabled
cls
sc config TabletInputService start= disabled
cls
sc config WbioSrvc start= disabled
cls
cls
sc config "Dnscache" start= demand
sc start Dnscache

:Undergroud2
chcp 65001
mode 40,10
@echo off

(
sc config "BITS" start= auto
sc start "BITS"
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where name="javaw.exe" CALL setpriority "realtime"
cls
wmic process where name="svchost.exe" CALL setpriority "idle"
cls
wmic process where name="explorer.exe" CALL setpriority "high"
cls
wmic process where name="mDNSResponder.exe" CALL setpriority "idle"
cls
wmic process where name="BRTSvc.exe" CALL setpriority "idle"
cls
wmic process where name="csrss.exe" CALL setpriority "idle"
cls
wmic process where name="dwm.exe" CALL setpriority "idle"
cls
wmic process where name="rundll32.exe" CALL setpriority "idle"
cls
wmic process where name="nvvsvc.exe" CALL setpriority "idle"
cls
wmic process where name="taskhost.exe" CALL setpriority "idle"
cls
wmic process where name="taskmgr.exe" CALL setpriority "idle"
cls
wmic process where name="dllhost.exe" CALL setpriority "idle"
cls
wmic process where name="dashost.exe" CALL setpriority "idle"
cls
wmic process where name="TCPSVCS.EXE" CALL setpriority "idle"
cls
wmic process where name="SetTimerResolutionService.exe" CALL setpriority "realtime"
cls
wmic process where name="WmiPrvSE.exe" CALL setpriority "idle"
cls
wmic process where name="svchost.exe (NetworkService)" CALL setpriority "idle"
cls
wmic process where name="cheatbreaker.exe" CALL setpriority "high priority"
cls
wmic process where name="svchost.exe" CALL setpriority "idle"

:Undergroud3
chcp 65001
mode 40,10
@echo off
ping localhost -n 2.5 >nul
netsh int tcp set global chimney=enabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global congestionprovider=ctcp
netsh int tcp show global
cls                                                      

netsh interface tcp set heuristics disabled
netsh interface tcp set global autotuning=restricted
netsh interface ip delete arpcache
netsh int tcp set global netdma=enabled
netsh int tcp set global dca=enabled
netsh int ipv4 set glob defaultcurhoplimit=64
netsh int ipv6 set glob defaultcurhoplimit=64
set supplemental congestionprovider=ctcp
netsh int tcp set heuristics disabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global fastopen=enabled
netsh interface tcp set global ecncapability=disabled
netsh int tcp set global autotuninglevel=restricted
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global initialRto=2000
netsh int tcp set global rsc=enabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global chimney=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global rss=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global timestamps=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set supplemental template=custom icw=8,5

@echo
@echo Disable HPET
bcdedit /deletevalue useplatformclock
@echo
@echo Disable dynamic tick (laptop power savings)
bcdedit /set disabledynamictick yes
@echo
@echo Disable synthetic timers
bcdedit /set useplatformtick yes
@echo
@echo Boot timeout 0
bcdedit /timeout 0
@echo
@echo Disable nx
bcdedit /set nx optout
@echo
@echo Disable boot screen animation
bcdedit /set bootux disabled
@echo
@echo Speed up boot times
bcdedit /set bootmenupolicy standard
@echo
@echo Disable hyper virtualization
bcdedit /set hypervisorlaunchtype off
@echo
@echo Disable trusted platform module (TPM)
bcdedit /set tpmbootentropy ForceDisable
@echo
@echo Remove windows login logo
bcdedit /set quietboot yes
@echo
@echo
@echo Disable boot logo
bcdedit /set {globalsettings} custom:16000067 true
@echo
@echo Disable spinning animation
bcdedit /set {globalsettings} custom:16000069 true
@echo
@echo Disable boot messages
bcdedit /set {globalsettings} custom:16000068 true
@echo
Cls

:Undergroud4
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TCPNoDelay " /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TCPInitialRtt" /t REG_DWORD /d "300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TCPNoDelay " /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}" /v "TCPInitialRtt" /t REG_DWORD /d "300" /f

netsh interface tcp set global autotuning=restricted

for /f "usebackq" %%i in (reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces) do (
Reg.exe add %%i /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPNoDelay" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPDelAckTicks" /d "0" /t REG_DWORD /f
)

:Undergroud5
chcp 65001
mode 40,10

for /f "usebackq" %%i in (reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces) do (
Reg.exe add %%i /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPNoDelay" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPDelAckTicks" /d "0" /t REG_DWORD /f
Reg.exe add %%i /v "MTU" /d "1450" /t REG_DWORD /f
Reg.exe add %%i /v "MSS" /d "1410" /t REG_DWORD /f
Reg.exe add %%i /v "TcpWindowSize" /d "64240" /t REG_DWORD /f
)

sc config "BITS" start= auto
sc start "BITS"
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "idle"
(
sc config "Dnscache" start= demand
sc start "Dnscache"
for /f "tokens=3" %%a in ('sc queryex "Dnscache" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "idle"
wmic process where name="mqsvc.exe" CALL setpriority "high priority"
wmic process where name="mqtgsvc.exe" CALL setpriority "high priority"
wmic process where name="javaw.exe" CALL setpriority "realtime"

ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh interface ip delete arpcache
netsh winsock reset catalog
netsh int ip reset c:resetlog.txt
netsh int ip reset C:    cplog.txt
netsh winsock reset catalog
netsh int tcp set global rsc=enabled
netsh int tcp set heuristics disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled

:Undergroud6
chcp 65001
mode 40,10

set /p MTU=What Is your Custom MTU ?:
set /a MSS = %MTU% - 40
cls
echo MTU = %MTU%
echo MSS = %MSS%
timeout 1 >nul

chcp 65001
mode 40,10

:UndergroudReal

SET minDiff=1
SET Low=550
SET High=9650
SET mid=5100
SET diff=9100
SET gateway=192.168.1.1
set serverip=www.google.com

@Echo Finding MTU for %serverIP%
@Echo %Low% %high%

:FindRoot
SET /A diff="%High%-%Low%"
If %diff% LEQ %minDiff% GOTO Found
FOR /F "tokens=1,2,3,4* delims=Lost" %%i IN ('%Sys32%ping.exe -n 1 -f -l %mid% %serverIP% ^| findstr /i "lost"') DO (
 SET lost=%%~l
)
FOR /F "tokens=1,2,3,4* delims==(" %%i IN ("%lost%") DO (
 SET lost=%%~j
)
IF %lost% GTR 0 (
 IF %mid% GEQ %High% GOTO Found
 SET High=%mid%
) ELSE (
 IF %mid% LEQ %Low% GOTO Found
 SET Low=%mid%
)
SET /A mid="(%High%+%Low%)/2"
@Echo %Low% %high%
goto FindRoot

:Found
FOR /F "tokens=1,2,3,4* delims=Lost" %%i IN ('%Sys32%ping.exe -n 1 -f -l %High% %serverIP% ^| findstr /i "lost"') DO (
 SET lost=%%~l
)
FOR /F "tokens=1,2,3,4* delims==(" %%i IN ("%lost%") DO (
 SET lost=%%~j
)

IF %lost% EQU 0 (
 SET Mtu=%High%
) ELSE (
 FOR /F "tokens=1,2,3,4* delims=Lost" %%i IN ('%Sys32%ping.exe -n 1 -f -l %Low% %serverIP% ^| findstr /i "lost"') DO (
 SET lost=%%~l
 )
 FOR /F "tokens=1,2,3,4* delims==(" %%i IN ("%lost%") DO (
 SET lost=%%~j
 )
 IF %lost% EQU 0 (
 GOTO FindMtu
 ) ELSE (
 SET Mtu=%Low%
 )
)
SET LcmMtu=%Mtu%
@Echo Server MTU %Mtu%+%MtuHeader%
@Echo.

IF "%serverIP%"=="%gateway%" GOTO SetLcmMtu
IF /I "%LCMSrvrAndGateway%"=="y" (
 GOTO FindGatewayMTU
) ELSE (
 IF /I "%MaxSrvrOrGateway%"=="y" (
 GOTO FindGatewayMTU
 ) ELSE (
 SET gwMtu=%LcmMtu%
 GOTO SetLcmMtu
 )
)

:FindGatewayMTU
@Echo Gateway is %gateway%
@Echo Finding Gateway MTU
SET gwMtu=0
SET minDiff=1
SET Low=550
SET High=9650
SET mid=5100
SET diff=9100
@Echo.
@Echo %Low% %high%

:FindGwRoot
SET /A diff="%High%-%Low%"
If %diff% LEQ %minDiff% GOTO FoundGwMtu
FOR /F "tokens=1,2,3,4* delims=Lost" %%i IN ('%Sys32%ping.exe -n 1 -f -l %mid% %gateway% ^| findstr /i "lost"') DO (
 SET lost=%%~l
)
FOR /F "tokens=1,2,3,4* delims==(" %%i IN ("%lost%") DO (
 SET lost=%%~j
)
IF %lost% GTR 0 (
 IF %mid% GEQ %High% GOTO FoundGwMtu
 SET High=%mid%
) ELSE (
 IF %mid% LEQ %Low% GOTO FoundGwMtu
 SET Low=%mid%
)
SET /A mid="(%High%+%Low%)/2"
@Echo %Low% %high%
goto FindGwRoot

:FoundGwMtu
FOR /F "tokens=1,2,3,4* delims=Lost" %%i IN ('%Sys32%ping.exe -n 1 -f -l %High% %gateway% ^| findstr /i "lost"') DO (
 SET lost=%%~l
)
FOR /F "tokens=1,2,3,4* delims==(" %%i IN ("%lost%") DO (
 SET lost=%%~j
)

IF %lost% EQU 0 (
 SET /A gwMtu="%High%+%gwMtu%"
) ELSE (
 FOR /F "tokens=1,2,3,4* delims=Lost" %%i IN ('%Sys32%ping.exe -n 1 -f -l %Low% %gateway% ^| findstr /i "lost"') DO (
 SET lost=%%~l
 )
 FOR /F "tokens=1,2,3,4* delims==(" %%i IN ("%lost%") DO (
 SET lost=%%~j
 )
 IF %lost% EQU 0 (
 GOTO FindMTU
 ) ELSE (
 SET /A gwMtu="%Low%+%gwMtu%"
 )
)
@Echo Gateway MTU is %gwMtu%+%MtuHeader%
@Echo.

:SetLcmMtu
SET /A Mtu="%Mtu%+%MtuHeader%"
SET /A gwMtu="%gwMtu%+%MtuHeader%"

IF /I "%MaxSrvrOrGateway%"=="y" (
 IF %gwMtu% GTR %Mtu% (
 SET LcmMtu=%gwMtu%
 ) ELSE (
 SET LcmMtu=%Mtu%
 )
) ELSE (
 IF %Mtu% GEQ %gwMtu% (
 SET /A LcmMtu="(%Mtu%-(%Mtu%%%%gwMtu%))"
 ) ELSE (
 SET /A LcmMtu="(%gwMtu%-(%gwMtu%%%%Mtu%))"
 )
)
@Echo.
cls
@Echo Your Optimal MTU = %LcmMtu%
cls

:Undergroud6
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "28" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumTcbTablePartitions" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "983040" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEntries" /t REG_DWORD /d "512" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheTimeout" /t REG_DWORD /d "96" /f
netsh int ip reset C:/resetlog.txt
netsh winsock reset
ipconfig /flushdns

:Undergroud7
mode con lines=5 cols=90
@echo off
cls
(
sc config "BITS" start= auto
sc start "BITS"
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "idle"
(
sc config "Dnscache" start= demand
sc start "Dnscache"
for /f "tokens=3" %%a in ('sc queryex "Dnscache" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "realtime"
wmic process where name="mqsvc.exe" CALL setpriority "high priority"
wmic process where name="mqtgsvc.exe" CALL setpriority "high priority"
wmic process where name="javaw.exe" CALL setpriority "realtime"

RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True
ipconfig /release
ipconfig /renew
ipconfig /flushdns

wmic process where ProcessId=%pid% CALL setpriority "realtime"
for /f "tokens=3" %%a in ('sc queryex "DsSvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start Dhcp
for /f "tokens=3" %%a in ('sc queryex "Dhcp" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start DPS 
for /f "tokens=3" %%a in ('sc queryex "DPS" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start Dnscache
for /f "tokens=3" %%a in ('sc queryex "Dnscache" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start WinHttpAutoProxySvc
for /f "tokens=3" %%a in ('sc queryex "WinHttpAutoProxySvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start DcpSvc
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "DcpSvc"
sc start WlanSvc
for /f "tokens=3" %%a in ('sc queryex "WlanSvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start LSM
for /f "tokens=3" %%a in ('sc queryex "LSM" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start smphost
for /f "tokens=3" %%a in ('sc queryex "smphost" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start PNRPsvc
for /f "tokens=3" %%a in ('sc queryex "PNRPsvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start SensrSvc
for /f "tokens=3" %%a in ('sc queryex "SensrSvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start Wcmsvc
for /f "tokens=3" %%a in ('sc queryex "Wcmsvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start Wersvc
for /f "tokens=3" %%a in ('sc queryex "Wersvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start Spooler
for /f "tokens=3" %%a in ('sc queryex "Spooler" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start vds
for /f "tokens=3" %%a in ('sc queryex "vds" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"


:young3
mode con lines=5 cols=90
@echo off
for /f "usebackq" %%i in (`reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`) do (
Reg.exe add %%i /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPNoDelay" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPDelAckTicks" /d "0" /t REG_DWORD /f
Reg.exe add %%i /v "TcpWindowSize" /d "65535" /t REG_DWORD /f
)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "983040" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEntries" /t REG_DWORD /d "512" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheTimeout" /t REG_DWORD /d "96" /f
netsh int ip reset C:/resetlog.txt
netsh winsock reset
ipconfig /flushdns
goto:young4


:young4
mode con lines=5 cols=90
@echo off
cls
netsh winsock reset catalog
netsh int tcp reset
netsh interface ip delete arpcache
netsh int tcp set heuristics disabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled
netsh int tcp set global netdma=enabled
netsh int tcp set global dca=enabled
netsh int tcp set supplemental template=custom icw=10
netsh int tcp set supplemental congestionprovider=ctcp
netsh int tcp set global ecncapability=disabled
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global initialRto=2000
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global fastopen=enabled
netsh interface ipv4 set interface "Ethernet" metric=70
netsh interface ipv4 set interface "Ethernet" mtu=1500
netsh interface ipv6 set interface "Ethernet" metric=70
netsh interface ipv6 set interface "Ethernet" mtu=1500
netsh int ipv4 set glob defaultcurhoplimit=255
netsh int ipv6 set glob defaultcurhoplimit=255
Cls

Exit                                                 