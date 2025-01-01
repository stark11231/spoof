@echo off
powershell Invoke-WebRequest "https://cdn.discordapp.com/attachments/956757450516746260/1052905089322455050/settings.meta" -OutFile "%USERPROFILE%\AppData\Local\FiveM\FiveM.app\citizen\platform\data\control\settings.meta"z'netsh int tcp set global chimney=enablez1netsh int tcp set global autotuninglevel=disabledz/netsh int tcp set global ecncapability=disabledz5netsh interface tcp set global ecncapability=disabledzKnetsh interface ipv4 set subinterface "Internet" mtu=10000 store=persistentz$netsh int tcp set global rss=defaultz1netsh int tcp set global congestion provider=ctcpz%netsh int tcp set heuristics disabledz!netsh int ip reset c:resetlog.txtz!netsh int ip reset C:   cplog.txtz,netsh int tcp set global timestamps=disabledz6netsh int tcp set global nonsackrttresiliency=disabledz%netsh int tcp set global dca=disabledz(netsh int tcp set global netdma=disabledz#regedit /s SG_Vista_TcpIp_Patch.regz
del SG_Vista_TcpIp_Patch.regzKnetsh interface ipv4 set subinterface "Ethernet" mtu=10000 store=persistentz)netsh int tcp set global chimney=disabledz#netsh int tcp set global dca=enablez#netsh int tcp set heuristics enablez$netsh int tcp set global rss=enabledz*netsh int tcp set global timestamps=enablez[PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabledzUPowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2zTPowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -EcnCapability disabledzQPowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -Timestamps disabledzJSet-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal NormalzISet-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics disabledzFSet-NetTCPSetting -SettingName InternetCustom -CongestionProvider ctcpz
del /q/f/s %temp%\*
netsh int tcp set global chimney=enabledz0netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global fastopen=enablez?netsh int tcp set supplemental internet congestionprovider=ctcpz%netsh int tcp set global rsc=disabled
netsh int tcp set global initialRto=8000z%netsh int tcp set global rss=disabledz
netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yesz8netsh interface ipv4 set dns name="Wi-Fi" static 1.1.1.1z9netsh interface ipv4 add dns name="Wi-Fi" 1.0.0.1 index=2zWnetsh int tnetsh advfirewall firewall set rule group="Network Discovery" new enable=Yesz]netsh int tcp setnetsh advfirewall firewall set rule group="Network Discovery" new enable=YeszLnetsh advfirewall firewall set rule group="Network Discovery" new enable=Yesz0netsh int tcp set global congestionprovider=nonez&netsh int tcp set global netdma=enablez
netsh int tcp show glob
netsh int tcp resetz netsh int tcp set glob auto=high
netsh int tcp set glob ecn=ena
netsh int tcp set glob time=ena netsh int tcp set glob init=3500
netsh int tcp set glob non=ena
netsh int tcp set glob max=8
netsh int tcp set glob pac=initz$netsh interface udp set glob uro=enaz@netsh int tcp set supplemental internet congestionprovider=dctcpz?netsh interface 6to4 set relay www.google.com enabled 999999999z?netsh interface isatap set rou www.google.com enabled 999999999z)netsh int ipv4 set glob icmpredirects=enaz'netsh int ipv4 set glob taskoffload=enaz*netsh int ipv4 set glob dhcpmediasense=enaz0netsh int ipv4 set glob randomizeidentifiers=enaz,netsh int ipv4 set glob loopbacklargemtu=enaz+netsh int ipv4 set glob sourcebasedecmp=enaz6netsh int ipv4 set glob reassemblyoutoforderlimit=9999z%netsh int ipv4 set glob flowlabel=enaz.netsh int ipv4 set glob mediasenseeventlog=enaz/netsh int ipv4 set glob multicastforwarding=enaz3netsh int ipv4 set glob groupforwardedfragments=enaz,netsh int ipv4 set glob addressmaskreply=enaz.netsh int ipv4 set glob defaultcurhoplimit=500z4netsh int ipv4 set glob neighborcachelimit=999999999z1netsh int ipv4 set glob routecachelimit=999999999z1netsh int ipv4 set glob reassemblylimit=999999999z2netsh int ipv4 set glob sourceroutingbehavior=dropz6netsh int ipv4 set glob loopbackexecutionmode=adaptivez)netsh int ipv6 set glob icmpredirects=enaz'netsh int ipv6 set glob taskoffload=enaz*netsh int ipv6 set glob dhcpmediasense=enaz0netsh int ipv6 set glob randomizeidentifiers=enaz,netsh int ipv6 set glob loopbacklargemtu=enaz+netsh int ipv6 set glob sourcebasedecmp=enaz6netsh int ipv6 set glob reassemblyoutoforderlimit=9999z%netsh int ipv6 set glob flowlabel=enaz.netsh int ipv6 set glob mediasenseeventlog=enaz/netsh int ipv6 set glob multicastforwarding=enaz3netsh int ipv6 set glob groupforwardedfragments=enaz,netsh int ipv6 set glob addressmaskreply=enaz.netsh int ipv6 set glob defaultcurhoplimit=500z4netsh int ipv6 set glob neighborcachelimit=999999999z1netsh int ipv6 set glob routecachelimit=999999999z1netsh int ipv6 set glob reassemblylimit=999999999z2netsh int ipv6 set glob sourceroutingbehavior=dropz6netsh int ipv6 set glob loopbackexecutionmode=adaptivez7netsh int tcp set supp internet congestionprovider=ctcpz.netsh int tcp set global ecncapability=enabledz(netsh int tcp set global initialRto=8500z5netsh int tcp set global nonsackttresiliency=disabledz0netsh int tcp set global MaxSynRetransmissions=2z)netsh int tcp set global fastopen=enabledz1netsh int tcp set global fastopenfallback=enabledz*netsh int tcp set global pacingprofile=offz)netsh int tcp set global hystart=disabledz$netsh int tcp set global dca=enabledz'netsh int tcp set global netdma=enabledz&netsh int 6to4 set state state=enabledz$netsh int udp set global uro=enabledz
netsh winsock set autotuning onz5netsh int tcp set supplemental template=custom icw=10 netsh interface teredo set state enterprise netsh int tcp set security mpp=disabled netsh int tcp set security profiles=disabledzGnetsh interface ipv4 set subinterface "Wi-Fi" mtu=7500 store=persistentzJnetsh interface ipv6 set subinterface "Ethernet" mtu=7500 store=persistent
netsh interface ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistentnetsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
netsh int tcp show globalz/netsh int tcp set global autotuninglevel=normal
ipconfig /flushdnsaG
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )z bcdedit /set useplatformtick yesz#bcdedit /set disabledynamictick yesz
bcdedit /timeout 0
bcdedit /set nx optout
bcdedit /set bootux disabledz$bcdedit /set bootmenupolicy standardz & bcdedit /set hypervisorlaunchtype offbcdedit /set tpmbootentropy ForceDisablez
bcdedit /set quietboot yesz2bcdedit /set {globalsettings} custom:16000067 truez2bcdedit /set {globalsettings} custom:16000069 truez2bcdedit /set {globalsettings} custom:16000068 truez#bcdedit /set linearaddress57 OptOutz%bcdedit /set increaseuserva 268435328z'bcdedit /set firstmegabytepolicy UseAllz%bcdedit /set avoidlowmemory 0x8000000z
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Defaultz&bcdedit /set usephysicaldestination No & bcdedit /set usefirmwarepcisettings No & bcdedit /deletevalue useplatformclock


Reg.exe add "HKCU\Control Panel\Mouse" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "200" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "200" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "TCPDelAckTicks" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "Tcp1323Opts" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight2" /t REG_SZ /d "0,5" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed2" /t REG_SZ /d "0,47" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth2" /t REG_SZ /d "0,5" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "AEnablePMTUBHDetect" /t REG_DWORD /d "0" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "32767" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "32767" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MouseSpeed" /t REG_SZ /d "0" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MouseThreshold1" /t REG_SZ /d "0" /fz
Reg.exe add "HKCU\Control Panel\Mouse\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MouseThreshold2" /t REG_SZ /d "0" /fr