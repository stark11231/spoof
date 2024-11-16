@echo off
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\Adapter ID"" /v ""MTU"" /t REG_DWORD /d ""5376"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""30000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""5000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""65000000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableBucketSize"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableSize"" /t REG_DWORD /d ""384"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxCacheEntryTtlLimit"" /t REG_DWORD /d ""64000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxSOACacheEntryTtlLimit"" /t REG_DWORD /d ""301"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NetFailureCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeSOACacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPNoDelay "" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPInitialRtt"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""TimeToWait"" /t REG_SZ /d ""60000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""3000000000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""100"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""65000000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DistributeTimers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity"" /t REG_SZ /d ""10"" /f
Reg.exe add ""HKU\.DEFAULT\Control Panel\Mouse"" /v ""MouseSpeed"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKU\.DEFAULT\Control Panel\Mouse"" /v ""MouseThreshold1"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKU\.DEFAULT\Control Panel\Mouse"" /v ""MouseThreshold2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DefaultTTL"" /t REG_DWORD /d ""64"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTaskOffload"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableLargeMtu"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableConnectionRateLimiting"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableDCA"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableRSS"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableTCPA"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableWsd"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPer1_0Server"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPerServer"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxFreeTcbs"" /t REG_DWORD /d ""65535"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxHashTableSize"" /t REG_DWORD /d ""65536"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxUserPort"" /t REG_DWORD /d ""65534"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NumTcbTablePartitions"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SynAttackProtect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpCreateAndConnectTcbRateLimitDepth"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDupAcks"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxSendFree"" /t REG_DWORD /d ""65535"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNumConnections"" /t REG_DWORD /d ""16777214"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpTimedWaitDelay"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpFinWait2Delay"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNoDelay"" /t REG_DWORD /d ""19435519"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TCPDelAckTicks"" /t REG_DWORD /d ""19435519"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpWindowSize"" /t REG_DWORD /d ""372300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DefaultTTL"" /t REG_DWORD /d ""32767"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""372300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000093ec45577900000000000000000000000000000093ec45570100000000000000000000000000000093ec45572b00000000000000000000000000000093ec45572c00000000000000000000000000000093ec45570600000000000000000000000000000093ec4557"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*SpeedDuplex"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*FlowControl"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*RSS"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPConnectionOffloadIPv4"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPConnectionOffloadIPv6"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*IPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPChecksumOffloadIPv6"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*UDPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*UDPChecksumOffloadIPv6"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*LsoV1IPv4"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*LsoV2IPv4"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*LsoV2IPv6"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPUDPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPUDPChecksumOffloadIPv6"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{25aa16d5-73d9-4cd8-91ff-0683b3bcd05a}"" /v ""LastProbeTime"" /t REG_DWORD /d ""1500872657"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{25aa16d5-73d9-4cd8-91ff-0683b3bcd05a}"" /v ""NetworkPerformsHijacking"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{e97ca175-e5e7-4580-895e-91be966166ba}"" /v ""LastProbeTime"" /t REG_DWORD /d ""1500872066"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{e97ca175-e5e7-4580-895e-91be966166ba}"" /v ""NetworkPerformsHijacking"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableICMPRedirect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableMediaSenseEventLog"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableRss"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTaskOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTcpChimneyOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMin"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMax"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMax"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMin"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMax"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMin"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""HibernateEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power"" /v ""HiberbootEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c"" /v ""ValueMax"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ValueMax"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler"" /v ""VsyncIdleTimeout"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"" /v ""AppCaptureEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR"" /v ""AllowgameDVR"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Intel\GMM"" /v ""DedicatedSegmentSize"" /t REG_DWORD /d ""1298"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""38"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""38"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v ""EnablePrefetcher"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v ""EnableSuperfetch"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v ""EnableBoottrace"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoLowDiskSpaceChecks"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""LinkResolveIgnoreLinkInfo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoResolveSearch"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoResolveTrack"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoInternetOpenWith"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""NtfsMftZoneReservation"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""NTFSDisable8dot3NameCreation"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""DontVerifyRandomDrivers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""NTFSDisableLastAccessUpdate"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""ContigFileAllocSize"" /t REG_DWORD /d ""64"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""AutoEndTasks"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""MenuShowDelay"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillAppTimeout"" /t REG_SZ /d ""5000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""HungAppTimeout"" /t REG_SZ /d ""4000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""LowLevelHooksTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""ForegroundLockTimeout"" /t REG_SZ /d ""150000"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""FpsAll"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""GameFluidity"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""FpsStatusGames"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""FpsStatusGamesAll"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Latency Sensitive"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Latency Sensitive"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""CPUPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""FastDRAM"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""PCIConcur"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""AGPConcur"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"" /v ""Max Cached Icons"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"" /v ""AlwaysUnloadDLL"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL"" /v ""Default"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" /v ""EnableBalloonTips"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TcpNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""NetworkThrottlingIndex"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""SystemResponsiveness"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""NetworkThrottlingIndex"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""SystemResponsiveness"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Latency Sensitive"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""GPU Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Background Only"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""GPU Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""GPU Priority"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /v ""TimeStampInterval"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\cdrom"" /v ""AutoRun"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""Class"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""7"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"" /v ""SizReqBuf"" /t REG_DWORD /d ""17424"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""DisableBandwidthThrottling"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""DisableLargeMtu"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""MaxCmds"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""MaxThreads"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""MaxCollectionCount"" /t REG_DWORD /d ""32"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""KeepConn"" /t REG_DWORD /d ""86400"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched"" /v ""NonBestEffortLimit"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""50"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""46"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""42"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""38"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""34"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""26"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""22"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""18"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""256"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""AutoRepeatDelay"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""AutoRepeatRate"" /t REG_SZ /d ""500"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""BounceTime"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""DelayBeforeAcceptance"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last BounceKey Setting"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Delay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Repeat"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Wait"" /t REG_DWORD /d ""1000"" /f
REM ; HeartPunch Flow OP By Dev PowerPunch Support 24Hr
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\Adapter ID"" /v ""MTU"" /t REG_DWORD /d ""5376"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""50000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""30000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableBucketSize"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableSize"" /t REG_DWORD /d ""384"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxCacheEntryTtlLimit"" /t REG_DWORD /d ""64000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxSOACacheEntryTtlLimit"" /t REG_DWORD /d ""301"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NetFailureCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeSOACacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPNoDelay "" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPInitialRtt"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""TimeToWait"" /t REG_SZ /d ""60000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync"" /v ""SyncPolicy"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"" /v ""EnableTransparency"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR"" /v ""value"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR"" /v ""AllowGameDVR"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"" /v ""AppCaptureEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""AllowAutoGameMode"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""AutoGameModeEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"" /v ""HwSchMode"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences"" /v ""DirectXUserGlobalSettings"" /t REG_SZ /d ""VRROptimizeEnable=0;"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\StickyKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\International\User Profile"" /v ""HttpAcceptLanguageOptOut"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" /v ""Start_TrackProgs"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" /v ""SubscribedContent-338393Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" /v ""SubscribedContent-353694Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" /v ""SubscribedContent-353696Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"" /v ""HasAccepted"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Personalization\Settings"" /v ""AcceptedPrivacyPolicy"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization"" /v ""RestrictImplicitInkCollection"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization"" /v ""RestrictImplicitTextCollection"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"" /v ""HarvestContacts"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"" /v ""ShowedToastAtLevel"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"" /v ""AllowTelemetry"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"" /v ""TailoredExperiencesWithDiagnosticDataEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey"" /v ""EnableEventTranscript"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Siuf\Rules"" /v ""NumberOfSIUFInPeriod"" /t REG_DWORD /d ""0"" /f
Reg.exe delete ""HKCU\SOFTWARE\Microsoft\Siuf\Rules"" /v ""PeriodInNanoSeconds"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v ""PublishUserActivities"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v ""UploadUserActivities"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"" /v ""GlobalUserDisabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"" /v ""BackgroundAppGlobalToggle"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"" /v ""PowerThrottlingOff"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""NetworkThrottlingIndex"" /t REG_DWORD /d ""10"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""SystemResponsiveness"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_FSEBehaviorMode"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_HonorUserFSEBehaviorMode"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_DXGIHonorFSEWindowsCompatible"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_EFSEFeatureFlags"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""AutoEndTasks"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""HungAppTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillAppTimeout"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""LowLevelHooksTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""MenuShowDelay"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"" /v ""MaintenanceDisabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""HibernateEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"" /v ""PowerThrottlingOff"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""200ffffffffff"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""500000fffffff"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""150000000ffffff"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Beep2"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""ActiveWindowTracking"" /t REG_DWORD /d ""4096"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Beep"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickHeight"" /t REG_SZ /d ""2"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickSpeed"" /t REG_SZ /d ""390"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickWidth"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""ExtendedSounds"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseHoverHeight"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseHoverTime"" /t REG_SZ /d ""30"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseHoverWidth"" /t REG_SZ /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity"" /t REG_SZ /d ""10"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSpeed"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold1"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseTrails"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SmoothMouseXCurve"" /t REG_BINARY /d ""00310000000000000090300000000000000099300000000000000000301900000000009200150000"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SmoothMouseYCurve"" /t REG_BINARY /d ""0000000000000000000038000000000000007000000000000000a800000000000000e00000000000"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SnapToDefaultButton"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SwapMouseButtons"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /ve /t REG_SZ /d """" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpWindowSize"" /t REG_DWORD /d ""372300"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TCPDelAckTicks"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DefaultTTL"" /t REG_DWORD /d ""32767"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Beep2"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickHeight2"" /t REG_SZ /d ""0.5"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickSpeed2"" /t REG_SZ /d ""0,47"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickWidth2"" /t REG_SZ /d ""0.5"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""ExtendedSounds2"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensibility2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSpeed2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold12"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold22"" /t REG_SZ /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Beep3"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity2"" /t REG_SZ /d ""0.01"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseTrails1"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseTrails2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity3"" /t REG_SZ /d ""0.01"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickSpeed3"" /t REG_SZ /d ""0.10"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""LeftClick"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DelayLeftClick"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetMouseDragOutWidth"" /t REG_SZ /d ""20"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetMouseSideMoveWidth"" /t REG_SZ /d ""50"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetMouseWidth"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetPenDragOutWidth"" /t REG_SZ /d ""30"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetPenSideMoveWidth"" /t REG_SZ /d ""50"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetPenWidth"" /t REG_SZ /d ""30"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpNoDelay2"" /t REG_DWORD /d ""5247"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""12"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpNoDelay1"" /t REG_BINARY /d ""7f14000000000000"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DelayRigthClick"" /t REG_BINARY /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""2415919104"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MaximumBuffers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MinimumBuffers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""TimeoutSecs"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""DistributeTimers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""WOW64"" /t REG_EXPAND_SZ /d ""%%systemroot%%"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_FSEBehaviorMode"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""Win32_AutoGameModeDefaultProfile"" /t REG_BINARY /d ""01000100000000000000000000000000000000000000000000000000000000000000000000000000"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""Win32_GameModeRelatedProcesses"" /t REG_BINARY /d ""010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_HonorUserFSEBehaviorMode"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_DXGIHonorFSEWindowsCompatible"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_EFSEFeatureFlags"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_FSEBehavior"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control"" /v ""SvcHostSplitThresholdInKB"" /t REG_DWORD /d ""376926742"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""999999999999"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DataBasePath"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\drivers\etc"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""ForwardBroadcasts"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""ICSDomain"" /t REG_SZ /d ""mshome.net"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""IPEnableRouter"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SyncDomainWithMembership"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NV Hostname"" /t REG_SZ /d ""DESKTOP-VDC1SA7"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Hostname"" /t REG_SZ /d ""DESKTOP-VDC1SA7"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SearchList"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""UseDomainNameDevolution"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableICMPRedirect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DeadGWDetectDefault"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DontAddDefaultGatewayDefault"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNoDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTaskOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDupAcks"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNumConnections"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpInitialRTT"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpCreateAndConnectTcbRateLimitDepth"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpWindowSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPer1_0Server"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPerServer"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxFreeTcbs"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableConnectionRateLimiting"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableWsd"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableTCPA"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableDCA"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableRSS"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableLargeMtu"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxHashTableSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NumTcbTablePartitions"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SynAttackProtect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxSendFree"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpFinWait2Delay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000093ec45577900000000000000000000000000000093ec45570100000000000000000000000000000093ec45572b00000000000000000000000000000093ec45572c00000000000000000000000000000093ec45570600000000000000000000000000000093ec4557"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableMediaSenseEventLog"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableRss"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTcpChimneyOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DefaultTTL"" /t REG_DWORD /d ""64"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxUserPort"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpTimedWaitDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{2c2b0c5f-d7ac-44d7-aeeb-204915937c46}"" /v ""LLInterface"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{2c2b0c5f-d7ac-44d7-aeeb-204915937c46}"" /v ""IpConfig"" /t REG_MULTI_SZ /d ""Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{55095b4c-2e08-421b-8523-195a894a2e1e}"" /v ""LLInterface"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{55095b4c-2e08-421b-8523-195a894a2e1e}"" /v ""IpConfig"" /t REG_MULTI_SZ /d ""Tcpip\Parameters\Interfaces\{55095B4C-2E08-421B-8523-195A894A2E1E}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""LLInterface"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""IpConfig"" /t REG_MULTI_SZ /d ""Tcpip\Parameters\Interfaces\{BF0EC538-01DF-4DE9-B678-60879BDF23C5}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""174"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""174"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TCPNoDelay"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MTU"" /t REG_DWORD /d ""988416"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MSS"" /t REG_DWORD /d ""988256"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\AdapterID"" /v ""MTU"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{122da4c0-a8c1-11ed-bcf3-806e6f6e6963}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""Lease"" /t REG_DWORD /d ""10800"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1677856209"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""T1"" /t REG_DWORD /d ""1677861609"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""T2"" /t REG_DWORD /d ""1677865659"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1677867009"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000002e150000790000000000000000000000000000002e150000770000000000000000000000000000002e1500002f0000000000000000000000000000002e1500002e0000000000000000000000000000002e1500002c0000000000000000000000000000002e1500002b0000000000000000000000000000002e150000210000000000000000000000000000002e1500001f0000000000000000000000000000002e1500000f0000000000000000000000000000002e1500000600000000000000040000000000000016002a30c0a801010300000000000000040000000000000016002a30c0a801010100000000000000040000000000000016002a30ffffff003300000000000000040000000000000016002a3000002a303600000000000000040000000000000016002a30c0a801013500000000000000010000000000000016002a3005000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a8010106000000c4a402768dbd"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Lease"" /t REG_DWORD /d ""864000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1467505923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T1"" /t REG_DWORD /d ""1467937923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T2"" /t REG_DWORD /d ""1468261923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1468369923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6627565626F687F5B41495"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""06000000000000000800000000000000038c8557d41b28f1d41b28f003000000000000000400000000000000038c8557c0a800fe01000000000000000400000000000000038c8557ffffff0036000000000000000400000000000000038c8557c0a800fe35000000000000000100000000000000038c855705000000fc000000000000000000000000000000dd89785733000000000000000400000000000000038c8557000d2f00"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a800fe060000000024d4b16589"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""MTU"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1694564351"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""61167"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpIPAddress"" /t REG_SZ /d ""94.238.154.142"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpServer"" /t REG_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Lease"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1455802053"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T1"" /t REG_DWORD /d ""1455802203"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T2"" /t REG_DWORD /d ""1455802315"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1455802353"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""24F6579776575637024556C65636F6D6027596D26496"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc000000000000000000000000000000cac6c55606000000000000000800000000000000f1c7c556c29e7a0ac29e7a0f03000000000000000400000000000000f1c7c5565eee9ffe01000000000000000400000000000000f1c7c556ffffe00033000000000000000400000000000000f1c7c5560000012c36000000000000000400000000000000f1c7c5565eee9ffe35000000000000000100000000000000f1c7c55605000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNameServer"" /t REG_SZ /d ""194.158.122.10 194.158.122.15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.1.30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Lease"" /t REG_DWORD /d ""43200"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465403852"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T1"" /t REG_DWORD /d ""1465425452"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T2"" /t REG_DWORD /d ""1465441652"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465447052"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565626F687D2241314736363"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""060000000000000004000000000000007df65857c0a801fe030000000000000004000000000000007df65857c0a801fe010000000000000004000000000000007df65857ffffff00330000000000000004000000000000007df658570000a8c0360000000000000004000000000000007df65857c0a801fe350000000000000001000000000000007df6585705000000fc000000000000000000000000000000bb4d5857"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a801fe06000000140c76b1a766"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNameServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpIPAddress"" /t REG_SZ /d ""10.49.225.216"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpServer"" /t REG_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Lease"" /t REG_DWORD /d ""130"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339910"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T1"" /t REG_DWORD /d ""1465339975"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T2"" /t REG_DWORD /d ""1465340023"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465340040"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565675966696"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""520000000000000006000000000000008850575701040a133eab00000600000000000000080000000000000088505757d41b28f1d41b28f003000000000000000400000000000000885057570a37fffe0100000000000000040000000000000088505757fff8000033000000000000000400000000000000885057570000008236000000000000000400000000000000885057570a37fffe350000000000000001000000000000008850575705000000fc00000000000000000000000000000042505757"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.223.106"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.223.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Lease"" /t REG_DWORD /d ""86400"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339966"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T1"" /t REG_DWORD /d ""1465383166"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T2"" /t REG_DWORD /d ""1465415566"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465426366"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""8405D2052796E647D29344D2F46666963656A656470243633303"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000004250575736000000000000000400000000000000bea15857c0a8df0133000000000000000400000000000000bea158570001518001000000000000000400000000000000bea15857ffffff0035000000000000000100000000000000bea1585705000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.19.214"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.19.108"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""Lease"" /t REG_DWORD /d ""3599"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1677790017"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""T1"" /t REG_DWORD /d ""1677791816"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""T2"" /t REG_DWORD /d ""1677793166"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1677793616"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpIsMeteredDetected"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpNameServer"" /t REG_SZ /d ""192.168.19.108"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.19.108"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000003a070000790000000000000000000000000000003a070000770000000000000000000000000000003a0700002f0000000000000000000000000000003a0700002e0000000000000000000000000000003a0700002c0000000000000000000000000000003a070000210000000000000000000000000000003a0700001f0000000000000000000000000000003a0700000f0000000000000000000000000000003a0700000600000000000000040000000000000033000e0fc0a8136c0300000000000000040000000000000033000e0fc0a8136c1c00000000000000040000000000000033000e0fc0a813ff0100000000000000040000000000000033000e0fffffff003b00000000000000040000000000000033000e0f00000c4d3a00000000000000040000000000000033000e0f000007073300000000000000040000000000000033000e0f00000e0f3600000000000000040000000000000033000e0fc0a8136c3500000000000000010000000000000033000e0f05000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a8136c0600000062a60dacd5e0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NsiObjectSecurity"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""UseDelayedAcceptance"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""HelperDllName"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\wshtcpip.dll"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""ProviderGUID"" /t REG_BINARY /d ""a01a0fe78babcf118ca300805f48a192"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""OfflineCapable"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""Mapping"" /t REG_BINARY /d ""08000000030000000200000001000000060000000200000001000000000000000200000000000000060000000200000002000000110000000200000002000000000000000200000000000000110000000200000003000000ff000000020000000300000000000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""Version"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""AddressFamily"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""SocketType"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""Protocol"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ProtocolMaxOffset"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ByteOrder"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""MessageSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""szProtocol"" /t REG_EXPAND_SZ /d ""@%%SystemRoot%%\System32\mswsock.dll,-60100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ProviderFlags"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ServiceFlags"" /t REG_DWORD /d ""131174"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""Version"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""AddressFamily"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""SocketType"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""Protocol"" /t REG_DWORD /d ""17"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ProtocolMaxOffset"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ByteOrder"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""MessageSize"" /t REG_DWORD /d ""65527"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""szProtocol"" /t REG_EXPAND_SZ /d ""@%%SystemRoot%%\System32\mswsock.dll,-60101"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ProviderFlags"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ServiceFlags"" /t REG_DWORD /d ""132617"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""Version"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""AddressFamily"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""SocketType"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""Protocol"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ProtocolMaxOffset"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ByteOrder"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""MessageSize"" /t REG_DWORD /d ""32768"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""szProtocol"" /t REG_EXPAND_SZ /d ""@%%SystemRoot%%\System32\mswsock.dll,-60102"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ProviderFlags"" /t REG_DWORD /d ""12"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ServiceFlags"" /t REG_DWORD /d ""132617"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""Class"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""4026531839"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""Name"" /t REG_SZ /d ""TCP/IP"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""4263488238"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""ProviderPath"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\wsock32.dll"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Description"" /t REG_SZ /d ""Controls the underlying video driver stacks to provide fully-featured display capabilities."" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""DisplayName"" /t REG_SZ /d ""LDDM Graphics Subsystem"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""ErrorControl"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Group"" /t REG_SZ /d ""Video Init"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Start"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Tag"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Type"" /t REG_DWORD /d ""32"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""DistributeTimers"" /t REG_DWORD /d ""3839"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorLatencyTolerance"" /t REG_DWORD /d ""536870911"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorRefreshLatencyTolerance"" /t REG_DWORD /d ""536870911"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""18"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\MonitorDataStore"" /v ""DataCashSize"" /t REG_DWORD /d ""15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""BufferSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""FlushTimer"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""IntervalSecs"" /t REG_DWORD /d ""60"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""MaximumBuffers"" /t REG_DWORD /d ""15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""MinimumBuffers"" /t REG_DWORD /d ""15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""ServiceDll"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\GraphicsPerfSvc.dll"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""ServiceDllUnloadOnStop"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""ServiceMain"" /t REG_SZ /d ""ServiceMain"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""TimeoutSecs"" /t REG_DWORD /d ""90"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TCPNoDelay"" /t REG_DWORD /d ""4095"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1616"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MTU"" /t REG_DWORD /d ""988416"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MSS"" /t REG_DWORD /d ""988256"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000093ec45577900000000000000000000000000000093ec45570100000000000000000000000000000093ec45572b00000000000000000000000000000093ec45572c00000000000000000000000000000093ec45570600000000000000000000000000000093ec4557"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000030617857790000000000000000000000000000003061785701000000000000000000000000000000306178572b000000000000000000000000000000306178572c000000000000000000000000000000306178570600000000000000000000000000000030617857"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000c45dfd5679000000000000000000000000000000c45dfd5601000000000000000000000000000000c45dfd562b000000000000000000000000000000c45dfd562c000000000000000000000000000000c45dfd5606000000000000000000000000000000c45dfd56"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""172.20.10.3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpServer"" /t REG_SZ /d ""172.20.10.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""Lease"" /t REG_DWORD /d ""85536"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1380286528"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""T1"" /t REG_DWORD /d ""1380329296"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""T2"" /t REG_DWORD /d ""1380361372"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1380372064"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0600000000000000080000000000000060ce4652ac14020aac1402270300000000000000040000000000000060ce4652ac140a010100000000000000040000000000000060ce4652fffffff03600000000000000040000000000000060ce4652ac140a013500000000000000010000000000000060ce465205000000fc000000000000000000000000000000818c45523300000000000000040000000000000060ce465200014e20"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""ac140a0106000000ba03d8dafe00"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpNameServer"" /t REG_SZ /d ""172.20.2.10 172.20.2.39"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""172.20.10.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.0.14"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.0.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Lease"" /t REG_DWORD /d ""864000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1467505923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T1"" /t REG_DWORD /d ""1467937923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T2"" /t REG_DWORD /d ""1468261923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1468369923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6627565626F687F5B41495"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""06000000000000000800000000000000038c8557d41b28f1d41b28f003000000000000000400000000000000038c8557c0a800fe01000000000000000400000000000000038c8557ffffff0036000000000000000400000000000000038c8557c0a800fe35000000000000000100000000000000038c855705000000fc000000000000000000000000000000dd89785733000000000000000400000000000000038c8557000d2f00"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a800fe060000000024d4b16589"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.0.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpIPAddress"" /t REG_SZ /d ""94.238.154.142"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpServer"" /t REG_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Lease"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1455802053"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T1"" /t REG_DWORD /d ""1455802203"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T2"" /t REG_DWORD /d ""1455802315"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1455802353"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""24F6579776575637024556C65636F6D6027596D26496"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc000000000000000000000000000000cac6c55606000000000000000800000000000000f1c7c556c29e7a0ac29e7a0f03000000000000000400000000000000f1c7c5565eee9ffe01000000000000000400000000000000f1c7c556ffffe00033000000000000000400000000000000f1c7c5560000012c36000000000000000400000000000000f1c7c5565eee9ffe35000000000000000100000000000000f1c7c55605000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNameServer"" /t REG_SZ /d ""194.158.122.10 194.158.122.15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.1.30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Lease"" /t REG_DWORD /d ""43200"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465403852"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T1"" /t REG_DWORD /d ""1465425452"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T2"" /t REG_DWORD /d ""1465441652"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465447052"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565626F687D2241314736363"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""060000000000000004000000000000007df65857c0a801fe030000000000000004000000000000007df65857c0a801fe010000000000000004000000000000007df65857ffffff00330000000000000004000000000000007df658570000a8c0360000000000000004000000000000007df65857c0a801fe350000000000000001000000000000007df6585705000000fc000000000000000000000000000000bb4d5857"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a801fe06000000140c76b1a766"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNameServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpIPAddress"" /t REG_SZ /d ""10.49.225.216"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpServer"" /t REG_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Lease"" /t REG_DWORD /d ""130"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339910"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T1"" /t REG_DWORD /d ""1465339975"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T2"" /t REG_DWORD /d ""1465340023"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465340040"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565675966696"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""520000000000000006000000000000008850575701040a133eab00000600000000000000080000000000000088505757d41b28f1d41b28f003000000000000000400000000000000885057570a37fffe0100000000000000040000000000000088505757fff8000033000000000000000400000000000000885057570000008236000000000000000400000000000000885057570a37fffe350000000000000001000000000000008850575705000000fc00000000000000000000000000000042505757"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.223.106"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.223.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Lease"" /t REG_DWORD /d ""86400"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339966"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T1"" /t REG_DWORD /d ""1465383166"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T2"" /t REG_DWORD /d ""1465415566"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465426366"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""8405D2052796E647D29344D2F46666963656A656470243633303"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000004250575736000000000000000400000000000000bea15857c0a8df0133000000000000000400000000000000bea158570001518001000000000000000400000000000000bea15857ffffff0035000000000000000100000000000000bea1585705000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000bd42635379000000000000000000000000000000bd42635301000000000000000000000000000000bd4263532b000000000000000000000000000000bd4263532c000000000000000000000000000000bd42635306000000000000000000000000000000bd426353"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000356ce04f79000000000000000000000000000000356ce04f01000000000000000000000000000000356ce04f2b000000000000000000000000000000356ce04f2c000000000000000000000000000000356ce04f06000000000000000000000000000000356ce04f"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000a24c065079000000000000000000000000000000a24c065001000000000000000000000000000000a24c06502b000000000000000000000000000000a24c06502c000000000000000000000000000000a24c065006000000000000000000000000000000a24c0650"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""EnableDHCP"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""NameServer"" /t REG_SZ /d ""82.163.142.7,95.211.158.134"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""Lease"" /t REG_DWORD /d ""31536000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1459876321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""T1"" /t REG_DWORD /d ""1475644321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""T2"" /t REG_DWORD /d ""1487470321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1491412321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""IPAddress"" /t REG_MULTI_SZ /d ""169.254.123.159"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""SubnetMask"" /t REG_MULTI_SZ /d ""255.255.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""NameServer"" /t REG_SZ /d ""82.163.142.7,95.211.158.134"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a800fe060000000024d4b16589"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000011b7f2567900000000000000000000000000000011b7f2560100000000000000000000000000000011b7f2562b00000000000000000000000000000011b7f2562c00000000000000000000000000000011b7f2560600000000000000000000000000000011b7f256"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000a1f5ef5679000000000000000000000000000000a1f5ef5601000000000000000000000000000000a1f5ef562b000000000000000000000000000000a1f5ef562c000000000000000000000000000000a1f5ef5606000000000000000000000000000000a1f5ef56"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000074eab94f7900000000000000000000000000000074eab94f0100000000000000000000000000000074eab94f2b00000000000000000000000000000074eab94f2c00000000000000000000000000000074eab94f0600000000000000000000000000000074eab94f"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000e064015779000000000000000000000000000000e064015701000000000000000000000000000000e06401572b000000000000000000000000000000e06401572c000000000000000000000000000000e064015706000000000000000000000000000000e0640157"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TCPNoDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""135"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MaximumBuffers"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MinimumBuffers"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""TimeoutSecs"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Description"" /t REG_SZ /d ""Controls the underlying video driver stacks to provide fully-featured display capabilities."" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""DisplayName"" /t REG_SZ /d ""LDDM Graphics Subsystem"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""ErrorControl"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Group"" /t REG_SZ /d ""Video Init"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""ImagePath"" /t REG_EXPAND_SZ /d ""\SystemRoot\System32\drivers\dxgkrnl.sys"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Start"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Tag"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Type"" /t REG_DWORD /d ""32"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorLatencyTolerance"" /t REG_BINARY /d ""31ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff31fff0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorRefreshLatencyTolerance"" /t REG_BINARY /d ""31ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff31fff0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DpcWatchdogProfileOffset"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""ObUnsecureGlobalNames"" /t REG_MULTI_SZ /d ""netfxcustomperfcounters.1.0\0SharedPerfIPCBlock\0Cor_Private_IPCBlock\0Cor_Public_IPCBlock_"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""SeTokenSingletonAttributesConfig"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""obcaseinsensitive"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DistributeTimers"" /t REG_DWORD /d ""4294967295"" /f
@echo off
cls
netsh int ip reset
netsh winsock reset catalog
netsh branchcache reset
netsh int ip reset c:resetlog.txt
netsh int ip reset C:\tcplog.txt
netsh winsock reset
netsh int ip reset all
nbtstat -R
nbtstat -RR
netsh int ipv4 reset
netsh int ipv6 reset
cls
netsh interface ipv4 set subinterface ""Ethernet"" mtu=5000 store=persistent
netsh int tcp set global congestionprovider=none
netsh int tcp set global autotuninglevel=high
netsh int tcp set global chimney=disabled
netsh int tcp set global dca=enable
netsh int tcp set global netdma=enable
netsh int tcp set heuristics enable
netsh int tcp set global rss=enabled
netsh int tcp set global timestamps=enable
for /f ""usebackq"" %%i in (`reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`) do (
Reg.exe add %%i /v ""TcpAckFrequency"" /d ""1"" /t REG_DWORD /f
Reg.exe add %%i /v ""TCPNoDelay"" /d ""1"" /t REG_DWORD /f
Reg.exe add %%i /v ""TCPDelAckTicks"" /d ""0"" /t REG_DWORD /f
Reg.exe add %%i /v ""MTU"" /d ""1500"" /t REG_DWORD /f
Reg.exe add %%i /v ""MSS"" /d ""1460"" /t REG_DWORD /f
cls
@echo off
netsh int tcp set global chimney=enable
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global ecncapability=disabled
netsh interface tcp set global ecncapability=disabled
netsh int tcp set global rss=default
netsh int tcp set global congestion provider=ctcp
netsh int tcp set heuristics disabled
netsh int ip reset c:resetlog.txt
netsh int ip reset C:cplog.txt
netsh int tcp set global timestamps=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global dca=disabled
netsh int tcp set global netdma=disabled
netsh int tcp set global congestionprovider=none
netsh int tcp set global autotuninglevel=high
netsh int tcp set global chimney=disabled
netsh int tcp set global dca=enable
netsh int tcp set global netdma=enable
netsh int tcp set heuristics enable
netsh int tcp set global rss=enabled
netsh int tcp set global timestamps=enable
ipconfig /flushdns
ipconfig /flushdns
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformclock true
fsutil behavior set disabledeletenotify 0
powercfg.exe -h off
bcdedit /deletevalue useplatformclock
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -EcnCapability disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -Timestamps disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider ctcp
PowerShell.exe Enable-NetAdapterChecksumOffload -Name 'Ethernet'
PowerShell.exe Disable-NetAdapterLso -Name 'Ethernet'
PowerShell.exe Enable-NetAdapterRss -Name 'Ethernet'
PowerShell.exe Enable-NetAdapterRsc -Name 'Ethernet'
PowerShell.exe Set-NetOffloadGlobalSetting -Chimney Automatic
@echo off
netsh interface teredo set state disabled  
netsh interface 6to4 set state disabled  
netsh winsock reset  
netsh int isatap set state disable  
netsh int ip set global taskoffload=disabled
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global fastopen=enabled 
set supplemental congestionprovider=ctcp 
netsh int ip set global neighborcachelimit=4096  
netsh int tcp set global timestamps=disabled  
netsh int tcp set heuristics disabled  
netsh int tcp set global autotuninglevel=disable  
netsh int tcp set global chimney=disabled  
netsh int tcp set global ecncapability=disabled  
netsh int tcp set global rss=enabled  
netsh int tcp set global rsc=disabled  
netsh int tcp set global dca=enabled  
netsh int tcp set global netdma=enabled  
netsh int tcp set global nonsackrttresiliency=disabled 
netsh int tcp set global initialRto=2000 
netsh int tcp set security mpp=disabled  
netsh int tcp set security profiles=disabled  
netsh int ip set global icmpredirects=disabled  
netsh int tcp set security mpp=disabled profiles=disabled  
netsh int ipv4 set glob defaultcurhoplimit=255
netsh int ipv6 set glob defaultcurhoplimit=255
netsh int ip set global multicastforwarding=disabled 
cls
@echo off
title Network
netsh int tcp set global chimney=enable
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global ecncapability=disabled
netsh interface tcp set global ecncapability=disabled
netsh int tcp set global rss=default
netsh int tcp set global congestion provider=ctcp
netsh int tcp set heuristics disabled
netsh int ip reset c:resetlog.txt
netsh int ip reset C:cplog.txt
netsh int tcp set global timestamps=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global dca=disabled
netsh int tcp set global netdma=disabled
netsh int tcp set global congestionprovider=none
netsh int tcp set global autotuninglevel=high
netsh int tcp set global chimney=disabled
netsh int tcp set global dca=enable
netsh int tcp set global netdma=enable
netsh int tcp set heuristics enable
netsh int tcp set global rss=enabled
netsh int tcp set global timestamps=enable
ipconfig /flushdns
ipconfig /flushdns
color X
ECHO Made and published by SeeUsGo,
ECHO --- === NOW TWEAKING! === ---
netsh int tcp set heuristics disabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=enabled
netsh int tcp set global autotuninglevel=high
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled
echo
color 09
echo 192.95.48.17
echo 192.99.5.38   /BadKohi/

echo 200.125.190.202
echo 200.125.190.164   /Latence/
echo - 
echo 200.68.64.20
echo 200.110.156.18   /Good Kb+reach+latency/
echo -
echo 198.50.145.155
echo 192.34.38.14    /AucunKB/
echo -
echo 94.23.1.152
echo 93.17.89.246 Good On CtlServ.fr
echo -
echo Proxy  (MushGay/""L""egias)
echo -
echo All Proxy kohi.eu And Badlion.eu
echo -
echo 92.222.234.190
echo 51.254.49.220
echo 51.254.49.219
echo 51.254.49.221
echo 92.222.234.189
echo 51.254.49.217
echo 51.254.49.216
echo 51.254.49.215
echo -
echo -
echo All Proxy Kohi.us
echo -
echo 158.69.57.22
echo 167.114.112.117
echo 158.69.57.23
echo 158.69.57.25
echo 158.69.57.89
echo 167.114.11.69
echo 158.69.57.28
echo -
echo Proxy Ctlserv.fr
echo -
echo 151.80.110.164
echo -
echo GOD Private VERZIDE/STIMPY US DNS ! 
echo God Reach :
echo -
echo 186.125.131.18
echo 200.8.65.30
echo -
echo 186.125.131.18
echo 200.110.156.18
echo -
echo Private DNS ( Caydem DNS ) 
echo -
echo 158.69.57.22
echo 190.202.81.115
echo -
echo Ctlserv
echo 190.202.81.115
echo 81.241.235.214
echo -
echo -
echo Kohi.eu
echo 134.247.141.18
echo 81.241.235.214
echo -
echo CtlservBadlion.eu
echo 80.10.246.2
echo 80.10.246.129
echo -
echo Dns lag op reach verzide 3 pot 2 time qwith them
echo 158.69.57.22
echo 200.13.137.78
echo -
echo op laggy reach
echo 8.8.8.8
echo 8.8.4.4
echo -
echo DNS for LA hosts
echo 208.67.222.222
echo 208.67.222.220
echo -
echo DNS for CA hosts
echo 192.95.48.17
echo 192.99.5.38
echo -
echo combinaison de 2 dns
echo 190.202.81.115
echo 200.13.137.78
echo -
Echo ----- Famouse Dns -----
echo -
echo -_-_-_-_-_-_- iPv4 DNS -_-_-_-_-_-_-
echo -
echo ------------- Mushway -------------
echo -
echo 208.69.222.22
echo 200.69.193.2
echo -
echo ------------- Stimpy -------------
echo -
echo 158.69.57.22
echo 190.202.81.115
echo -
echo 85.214.43.157
echo 200.69.193.2
echo -
echo ------------- Ziblaking -------------
echo -
echo 80.10.246.2
echo 80.10.246.129
echo -
echo ------------- Verzide -------------
echo -
echo 186.125.131.18
echo 200.110.156.18
echo -
echo 158.69.57.22
echo 190.202.81.115
echo -
echo ------------- Helmix94 -------------
echo -
echo 194.22.56.89
echo 192.22.54.84
echo -
echo ------------------------------------
echo -
echo -_-_-_-_-_-_- iPv6 DNS -_-_-_-_-_-_-
echo -
echo ------------- No knockback -------------
echo -
echo 2620:0:ccc::2 -
echo 2620:0:ccd::2
echo -
echo ------------- Op reach -------------
echo -
echo 2001:4860:4860::8888
echo 2001:4860:4860::8844
echo -
echo ------------- Best hit detection -------------
echo -
echo 2a01:6e00:10:401::56
echo 2a01:6e00:10:401::57
echo 
echo ----------------------------------------------
echo -
echo -
echo DNS:
echo IPV4 list:
echo -
echo Ctlserv
echo 81.253.149.2
echo 80.10.246.132
echo -
echo Hcteams
echo 208.67.222.222
echo 208.67.222.220
echo -
echo True verzide dns
echo 158.69.57.22
echo 190.202.81.115
echo -
echo Ctlserv
echo 190.202.81.115
echo 81.241.235.214
echo -
echo Kohi.eu
echo 134.247.141.18
echo 81.241.235.214
echo -
echo An other kohi.eu
echo 80.81.10.128
echo 81.241.235.214
echo -
echo Ctlserv/Badlion.eu
echo 80.10.246.2
echo 80.10.246.129
echo -
echo Ctlserv less knockback
echo 41.17.89.146
echo 93.17.89.246
echo -
echo Dns lag op reach verzide 3 pot 2 time qwith them
echo 158.69.57.22
echo 200.13.137.78
echo -
echo Stimpy DNS
echo 85.214.43.157
echo 200.69.193.2
echo -
echo laggy reach
echo 8.8.8.8
echo 8.8.4.4
echo -
echo New York Hosts
echo 170.215.255.114
echo 66.133.170.2
echo -
echo DNS for LA hosts
echo 208.67.222.222
echo 208.67.222.220
echo -
echo DNS for CA hosts
echo 192.95.48.17
echo 192.99.5.38
@echo off
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\Adapter ID"" /v ""MTU"" /t REG_DWORD /d ""5376"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""30000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""5000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""65000000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableBucketSize"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableSize"" /t REG_DWORD /d ""384"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxCacheEntryTtlLimit"" /t REG_DWORD /d ""64000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxSOACacheEntryTtlLimit"" /t REG_DWORD /d ""301"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NetFailureCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeSOACacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPNoDelay "" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPInitialRtt"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""TimeToWait"" /t REG_SZ /d ""60000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""3000000000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""100"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""65000000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DistributeTimers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity"" /t REG_SZ /d ""10"" /f
Reg.exe add ""HKU\.DEFAULT\Control Panel\Mouse"" /v ""MouseSpeed"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKU\.DEFAULT\Control Panel\Mouse"" /v ""MouseThreshold1"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKU\.DEFAULT\Control Panel\Mouse"" /v ""MouseThreshold2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DefaultTTL"" /t REG_DWORD /d ""64"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTaskOffload"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableLargeMtu"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableConnectionRateLimiting"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableDCA"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableRSS"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableTCPA"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableWsd"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPer1_0Server"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPerServer"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxFreeTcbs"" /t REG_DWORD /d ""65535"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxHashTableSize"" /t REG_DWORD /d ""65536"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxUserPort"" /t REG_DWORD /d ""65534"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NumTcbTablePartitions"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SynAttackProtect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpCreateAndConnectTcbRateLimitDepth"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDupAcks"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxSendFree"" /t REG_DWORD /d ""65535"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNumConnections"" /t REG_DWORD /d ""16777214"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpTimedWaitDelay"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpFinWait2Delay"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNoDelay"" /t REG_DWORD /d ""19435519"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TCPDelAckTicks"" /t REG_DWORD /d ""19435519"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpWindowSize"" /t REG_DWORD /d ""372300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DefaultTTL"" /t REG_DWORD /d ""32767"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""372300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000093ec45577900000000000000000000000000000093ec45570100000000000000000000000000000093ec45572b00000000000000000000000000000093ec45572c00000000000000000000000000000093ec45570600000000000000000000000000000093ec4557"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*SpeedDuplex"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*FlowControl"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*RSS"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPConnectionOffloadIPv4"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPConnectionOffloadIPv6"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*IPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPChecksumOffloadIPv6"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*UDPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*UDPChecksumOffloadIPv6"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*LsoV1IPv4"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*LsoV2IPv4"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*LsoV2IPv6"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPUDPChecksumOffloadIPv4"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0x"" /v ""*TCPUDPChecksumOffloadIPv6"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{25aa16d5-73d9-4cd8-91ff-0683b3bcd05a}"" /v ""LastProbeTime"" /t REG_DWORD /d ""1500872657"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{25aa16d5-73d9-4cd8-91ff-0683b3bcd05a}"" /v ""NetworkPerformsHijacking"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{e97ca175-e5e7-4580-895e-91be966166ba}"" /v ""LastProbeTime"" /t REG_DWORD /d ""1500872066"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\Probe\{e97ca175-e5e7-4580-895e-91be966166ba}"" /v ""NetworkPerformsHijacking"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableICMPRedirect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableMediaSenseEventLog"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableRss"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTaskOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTcpChimneyOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMin"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMax"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMax"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMin"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMax"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"" /v ""ValueMin"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""HibernateEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power"" /v ""HiberbootEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c"" /v ""ValueMax"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ValueMax"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler"" /v ""VsyncIdleTimeout"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"" /v ""AppCaptureEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR"" /v ""AllowgameDVR"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Intel\GMM"" /v ""DedicatedSegmentSize"" /t REG_DWORD /d ""1298"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""38"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""38"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v ""EnablePrefetcher"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v ""EnableSuperfetch"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"" /v ""EnableBoottrace"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoLowDiskSpaceChecks"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""LinkResolveIgnoreLinkInfo"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoResolveSearch"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoResolveTrack"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v ""NoInternetOpenWith"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""NtfsMftZoneReservation"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""NTFSDisable8dot3NameCreation"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""DontVerifyRandomDrivers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""NTFSDisableLastAccessUpdate"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"" /v ""ContigFileAllocSize"" /t REG_DWORD /d ""64"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""AutoEndTasks"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""MenuShowDelay"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillAppTimeout"" /t REG_SZ /d ""5000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""HungAppTimeout"" /t REG_SZ /d ""4000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""LowLevelHooksTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""ForegroundLockTimeout"" /t REG_SZ /d ""150000"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""FpsAll"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""GameFluidity"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""FpsStatusGames"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Games"" /v ""FpsStatusGamesAll"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Latency Sensitive"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Latency Sensitive"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""CPUPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""FastDRAM"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""PCIConcur"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\VxD\BIOS"" /v ""AGPConcur"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"" /v ""Max Cached Icons"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"" /v ""AlwaysUnloadDLL"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL"" /v ""Default"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" /v ""EnableBalloonTips"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TcpNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""NetworkThrottlingIndex"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""SystemResponsiveness"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""NetworkThrottlingIndex"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""SystemResponsiveness"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Latency Sensitive"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""GPU Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Background Only"" /t REG_SZ /d ""True"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""GPU Priority"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""GPU Priority"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability"" /v ""TimeStampInterval"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\cdrom"" /v ""AutoRun"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""Class"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""7"" /f
Reg.exe add ""HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"" /v ""SizReqBuf"" /t REG_DWORD /d ""17424"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""DisableBandwidthThrottling"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""DisableLargeMtu"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""MaxCmds"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""MaxThreads"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""MaxCollectionCount"" /t REG_DWORD /d ""32"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters"" /v ""KeepConn"" /t REG_DWORD /d ""86400"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched"" /v ""NonBestEffortLimit"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""50"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""46"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""42"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""38"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""34"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""26"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""22"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""18"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""256"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""AutoRepeatDelay"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""AutoRepeatRate"" /t REG_SZ /d ""500"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""BounceTime"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""DelayBeforeAcceptance"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last BounceKey Setting"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Delay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Repeat"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Last Valid Wait"" /t REG_DWORD /d ""1000"" /f
REM ; HeartPunch Flow OP By Dev PowerPunch Support 24Hr
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\Adapter ID"" /v ""MTU"" /t REG_DWORD /d ""5376"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""50000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""30000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableBucketSize"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""CacheHashTableSize"" /t REG_DWORD /d ""384"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxCacheEntryTtlLimit"" /t REG_DWORD /d ""64000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""MaxSOACacheEntryTtlLimit"" /t REG_DWORD /d ""301"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NetFailureCacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"" /v ""NegativeSOACacheTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPNoDelay "" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{B849614A-A5F3-4A5F-ADEF-99DDB3DDF718}"" /v ""TCPInitialRtt"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""TimeToWait"" /t REG_SZ /d ""60000"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\TimeOut"" /v ""Flags"" /t REG_SZ /d ""200"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync"" /v ""SyncPolicy"" /t REG_DWORD /d ""5"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"" /v ""EnableTransparency"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR"" /v ""value"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR"" /v ""AllowGameDVR"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"" /v ""AppCaptureEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""AllowAutoGameMode"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\GameBar"" /v ""AutoGameModeEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"" /v ""HwSchMode"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences"" /v ""DirectXUserGlobalSettings"" /t REG_SZ /d ""VRROptimizeEnable=0;"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\StickyKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\Keyboard Response"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\ToggleKeys"" /v ""Flags"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"" /v ""Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\International\User Profile"" /v ""HttpAcceptLanguageOptOut"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" /v ""Start_TrackProgs"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" /v ""SubscribedContent-338393Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" /v ""SubscribedContent-353694Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"" /v ""SubscribedContent-353696Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"" /v ""HasAccepted"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Personalization\Settings"" /v ""AcceptedPrivacyPolicy"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization"" /v ""RestrictImplicitInkCollection"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization"" /v ""RestrictImplicitTextCollection"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"" /v ""HarvestContacts"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"" /v ""ShowedToastAtLevel"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"" /v ""AllowTelemetry"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"" /v ""TailoredExperiencesWithDiagnosticDataEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey"" /v ""EnableEventTranscript"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Siuf\Rules"" /v ""NumberOfSIUFInPeriod"" /t REG_DWORD /d ""0"" /f
Reg.exe delete ""HKCU\SOFTWARE\Microsoft\Siuf\Rules"" /v ""PeriodInNanoSeconds"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v ""PublishUserActivities"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v ""UploadUserActivities"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"" /v ""Value"" /t REG_SZ /d ""Deny"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"" /v ""GlobalUserDisabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"" /v ""BackgroundAppGlobalToggle"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"" /v ""PowerThrottlingOff"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""NetworkThrottlingIndex"" /t REG_DWORD /d ""10"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"" /v ""SystemResponsiveness"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Affinity"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Background Only"" /t REG_SZ /d ""False"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Clock Rate"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""GPU Priority"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Priority"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""Scheduling Category"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"" /v ""SFIO Priority"" /t REG_SZ /d ""High"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_FSEBehaviorMode"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_HonorUserFSEBehaviorMode"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_DXGIHonorFSEWindowsCompatible"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_EFSEFeatureFlags"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""AutoEndTasks"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""HungAppTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""WaitToKillAppTimeout"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""LowLevelHooksTimeout"" /t REG_SZ /d ""1000"" /f
Reg.exe add ""HKCU\Control Panel\Desktop"" /v ""MenuShowDelay"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""2000"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"" /v ""MaintenanceDisabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power"" /v ""HibernateEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e"" /v ""DCSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"" /v ""ACSettingIndex"" /t REG_DWORD /d ""100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"" /v ""PowerThrottlingOff"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Flags"" /t REG_SZ /d ""200ffffffffff"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""MaximumSpeed"" /t REG_SZ /d ""500000fffffff"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""TimeToMaximumSpeed"" /t REG_SZ /d ""150000000ffffff"" /f
Reg.exe add ""HKCU\Control Panel\Accessibility\MouseKeys"" /v ""Beep2"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""ActiveWindowTracking"" /t REG_DWORD /d ""4096"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Beep"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickHeight"" /t REG_SZ /d ""2"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickSpeed"" /t REG_SZ /d ""390"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickWidth"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""ExtendedSounds"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseHoverHeight"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseHoverTime"" /t REG_SZ /d ""30"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseHoverWidth"" /t REG_SZ /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity"" /t REG_SZ /d ""10"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSpeed"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold1"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseTrails"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SmoothMouseXCurve"" /t REG_BINARY /d ""00310000000000000090300000000000000099300000000000000000301900000000009200150000"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SmoothMouseYCurve"" /t REG_BINARY /d ""0000000000000000000038000000000000007000000000000000a800000000000000e00000000000"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SnapToDefaultButton"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SwapMouseButtons"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /ve /t REG_SZ /d """" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpWindowSize"" /t REG_DWORD /d ""372300"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TCPDelAckTicks"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DefaultTTL"" /t REG_DWORD /d ""32767"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Beep2"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickHeight2"" /t REG_SZ /d ""0.5"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickSpeed2"" /t REG_SZ /d ""0,47"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickWidth2"" /t REG_SZ /d ""0.5"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""ExtendedSounds2"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensibility2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSpeed2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold12"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseThreshold22"" /t REG_SZ /d ""4"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""Beep3"" /t REG_SZ /d ""No"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity2"" /t REG_SZ /d ""0.01"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseTrails1"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseTrails2"" /t REG_SZ /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""MouseSensitivity3"" /t REG_SZ /d ""0.01"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickSpeed3"" /t REG_SZ /d ""0.10"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DoubleClickDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""LeftClick"" /t REG_SZ /d ""3"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DelayLeftClick"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetMouseDragOutWidth"" /t REG_SZ /d ""20"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetMouseSideMoveWidth"" /t REG_SZ /d ""50"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetMouseWidth"" /t REG_SZ /d ""1"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetPenDragOutWidth"" /t REG_SZ /d ""30"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetPenSideMoveWidth"" /t REG_SZ /d ""50"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DockTargetPenWidth"" /t REG_SZ /d ""30"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpNoDelay2"" /t REG_DWORD /d ""5247"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""12"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""TcpNoDelay1"" /t REG_BINARY /d ""7f14000000000000"" /f
Reg.exe add ""HKCU\Control Panel\Mouse"" /v ""DelayRigthClick"" /t REG_BINARY /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""2415919104"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MaximumBuffers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MinimumBuffers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""TimeoutSecs"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""DistributeTimers"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""WOW64"" /t REG_EXPAND_SZ /d ""%%systemroot%%"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_Enabled"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_FSEBehaviorMode"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""Win32_AutoGameModeDefaultProfile"" /t REG_BINARY /d ""01000100000000000000000000000000000000000000000000000000000000000000000000000000"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""Win32_GameModeRelatedProcesses"" /t REG_BINARY /d ""010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_HonorUserFSEBehaviorMode"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_DXGIHonorFSEWindowsCompatible"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_EFSEFeatureFlags"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKCU\System\GameConfigStore"" /v ""GameDVR_FSEBehavior"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control"" /v ""SvcHostSplitThresholdInKB"" /t REG_DWORD /d ""376926742"" /f
Reg.exe add ""HKLM\SYSTEM\ControlSet001\Control"" /v ""WaitToKillServiceTimeout"" /t REG_SZ /d ""999999999999"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DataBasePath"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\drivers\etc"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""ForwardBroadcasts"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""ICSDomain"" /t REG_SZ /d ""mshome.net"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""IPEnableRouter"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SyncDomainWithMembership"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NV Hostname"" /t REG_SZ /d ""DESKTOP-VDC1SA7"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Hostname"" /t REG_SZ /d ""DESKTOP-VDC1SA7"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""Tcp1323Opts"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SearchList"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""UseDomainNameDevolution"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableICMPRedirect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DeadGWDetectDefault"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DontAddDefaultGatewayDefault"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNoDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTaskOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDupAcks"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpNumConnections"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpInitialRTT"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpCreateAndConnectTcbRateLimitDepth"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUBHDetect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnablePMTUDiscovery"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""GlobalMaxTcpWindowSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpWindowSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxDataRetransmissions"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPer1_0Server"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxConnectionsPerServer"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxFreeTcbs"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableConnectionRateLimiting"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableWsd"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableTCPA"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableDCA"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""EnableRSS"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableLargeMtu"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxHashTableSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""NumTcbTablePartitions"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SackOpts"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""SynAttackProtect"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpMaxSendFree"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpFinWait2Delay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000093ec45577900000000000000000000000000000093ec45570100000000000000000000000000000093ec45572b00000000000000000000000000000093ec45572c00000000000000000000000000000093ec45570600000000000000000000000000000093ec4557"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableMediaSenseEventLog"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableRss"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DisableTcpChimneyOffload"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""DefaultTTL"" /t REG_DWORD /d ""64"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""MaxUserPort"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v ""TcpTimedWaitDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{2c2b0c5f-d7ac-44d7-aeeb-204915937c46}"" /v ""LLInterface"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{2c2b0c5f-d7ac-44d7-aeeb-204915937c46}"" /v ""IpConfig"" /t REG_MULTI_SZ /d ""Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{55095b4c-2e08-421b-8523-195a894a2e1e}"" /v ""LLInterface"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{55095b4c-2e08-421b-8523-195a894a2e1e}"" /v ""IpConfig"" /t REG_MULTI_SZ /d ""Tcpip\Parameters\Interfaces\{55095B4C-2E08-421B-8523-195A894A2E1E}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""LLInterface"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""IpConfig"" /t REG_MULTI_SZ /d ""Tcpip\Parameters\Interfaces\{BF0EC538-01DF-4DE9-B678-60879BDF23C5}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""174"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""174"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TCPNoDelay"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MTU"" /t REG_DWORD /d ""988416"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MSS"" /t REG_DWORD /d ""988256"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\AdapterID"" /v ""MTU"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{122da4c0-a8c1-11ed-bcf3-806e6f6e6963}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""Lease"" /t REG_DWORD /d ""10800"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1677856209"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""T1"" /t REG_DWORD /d ""1677861609"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""T2"" /t REG_DWORD /d ""1677865659"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1677867009"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000002e150000790000000000000000000000000000002e150000770000000000000000000000000000002e1500002f0000000000000000000000000000002e1500002e0000000000000000000000000000002e1500002c0000000000000000000000000000002e1500002b0000000000000000000000000000002e150000210000000000000000000000000000002e1500001f0000000000000000000000000000002e1500000f0000000000000000000000000000002e1500000600000000000000040000000000000016002a30c0a801010300000000000000040000000000000016002a30c0a801010100000000000000040000000000000016002a30ffffff003300000000000000040000000000000016002a3000002a303600000000000000040000000000000016002a30c0a801013500000000000000010000000000000016002a3005000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a8010106000000c4a402768dbd"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2C2B0C5F-D7AC-44D7-AEEB-204915937C46}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Lease"" /t REG_DWORD /d ""864000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1467505923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T1"" /t REG_DWORD /d ""1467937923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T2"" /t REG_DWORD /d ""1468261923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1468369923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6627565626F687F5B41495"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""06000000000000000800000000000000038c8557d41b28f1d41b28f003000000000000000400000000000000038c8557c0a800fe01000000000000000400000000000000038c8557ffffff0036000000000000000400000000000000038c8557c0a800fe35000000000000000100000000000000038c855705000000fc000000000000000000000000000000dd89785733000000000000000400000000000000038c8557000d2f00"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a800fe060000000024d4b16589"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""MTU"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1694564351"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""61167"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpIPAddress"" /t REG_SZ /d ""94.238.154.142"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpServer"" /t REG_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Lease"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1455802053"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T1"" /t REG_DWORD /d ""1455802203"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T2"" /t REG_DWORD /d ""1455802315"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1455802353"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""24F6579776575637024556C65636F6D6027596D26496"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc000000000000000000000000000000cac6c55606000000000000000800000000000000f1c7c556c29e7a0ac29e7a0f03000000000000000400000000000000f1c7c5565eee9ffe01000000000000000400000000000000f1c7c556ffffe00033000000000000000400000000000000f1c7c5560000012c36000000000000000400000000000000f1c7c5565eee9ffe35000000000000000100000000000000f1c7c55605000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNameServer"" /t REG_SZ /d ""194.158.122.10 194.158.122.15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.1.30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Lease"" /t REG_DWORD /d ""43200"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465403852"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T1"" /t REG_DWORD /d ""1465425452"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T2"" /t REG_DWORD /d ""1465441652"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465447052"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565626F687D2241314736363"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""060000000000000004000000000000007df65857c0a801fe030000000000000004000000000000007df65857c0a801fe010000000000000004000000000000007df65857ffffff00330000000000000004000000000000007df658570000a8c0360000000000000004000000000000007df65857c0a801fe350000000000000001000000000000007df6585705000000fc000000000000000000000000000000bb4d5857"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a801fe06000000140c76b1a766"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNameServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpIPAddress"" /t REG_SZ /d ""10.49.225.216"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpServer"" /t REG_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Lease"" /t REG_DWORD /d ""130"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339910"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T1"" /t REG_DWORD /d ""1465339975"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T2"" /t REG_DWORD /d ""1465340023"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465340040"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565675966696"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""520000000000000006000000000000008850575701040a133eab00000600000000000000080000000000000088505757d41b28f1d41b28f003000000000000000400000000000000885057570a37fffe0100000000000000040000000000000088505757fff8000033000000000000000400000000000000885057570000008236000000000000000400000000000000885057570a37fffe350000000000000001000000000000008850575705000000fc00000000000000000000000000000042505757"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.223.106"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.223.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Lease"" /t REG_DWORD /d ""86400"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339966"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T1"" /t REG_DWORD /d ""1465383166"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T2"" /t REG_DWORD /d ""1465415566"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465426366"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""8405D2052796E647D29344D2F46666963656A656470243633303"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000004250575736000000000000000400000000000000bea15857c0a8df0133000000000000000400000000000000bea158570001518001000000000000000400000000000000bea15857ffffff0035000000000000000100000000000000bea1585705000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.19.214"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.19.108"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""Lease"" /t REG_DWORD /d ""3599"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1677790017"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""T1"" /t REG_DWORD /d ""1677791816"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""T2"" /t REG_DWORD /d ""1677793166"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1677793616"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpIsMeteredDetected"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpNameServer"" /t REG_SZ /d ""192.168.19.108"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.19.108"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000003a070000790000000000000000000000000000003a070000770000000000000000000000000000003a0700002f0000000000000000000000000000003a0700002e0000000000000000000000000000003a0700002c0000000000000000000000000000003a070000210000000000000000000000000000003a0700001f0000000000000000000000000000003a0700000f0000000000000000000000000000003a0700000600000000000000040000000000000033000e0fc0a8136c0300000000000000040000000000000033000e0fc0a8136c1c00000000000000040000000000000033000e0fc0a813ff0100000000000000040000000000000033000e0fffffff003b00000000000000040000000000000033000e0f00000c4d3a00000000000000040000000000000033000e0f000007073300000000000000040000000000000033000e0f00000e0f3600000000000000040000000000000033000e0fc0a8136c3500000000000000010000000000000033000e0f05000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a8136c0600000062a60dacd5e0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{bf0ec538-01df-4de9-b678-60879bdf23c5}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NsiObjectSecurity"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""UseDelayedAcceptance"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""HelperDllName"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\wshtcpip.dll"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""ProviderGUID"" /t REG_BINARY /d ""a01a0fe78babcf118ca300805f48a192"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""OfflineCapable"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock"" /v ""Mapping"" /t REG_BINARY /d ""08000000030000000200000001000000060000000200000001000000000000000200000000000000060000000200000002000000110000000200000002000000000000000200000000000000110000000200000003000000ff000000020000000300000000000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""Version"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""AddressFamily"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""SocketType"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""Protocol"" /t REG_DWORD /d ""6"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ProtocolMaxOffset"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ByteOrder"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""MessageSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""szProtocol"" /t REG_EXPAND_SZ /d ""@%%SystemRoot%%\System32\mswsock.dll,-60100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ProviderFlags"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0"" /v ""ServiceFlags"" /t REG_DWORD /d ""131174"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""Version"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""AddressFamily"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""SocketType"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""Protocol"" /t REG_DWORD /d ""17"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ProtocolMaxOffset"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ByteOrder"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""MessageSize"" /t REG_DWORD /d ""65527"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""szProtocol"" /t REG_EXPAND_SZ /d ""@%%SystemRoot%%\System32\mswsock.dll,-60101"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ProviderFlags"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1"" /v ""ServiceFlags"" /t REG_DWORD /d ""132617"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""Version"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""AddressFamily"" /t REG_DWORD /d ""2"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""MaxSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""MinSockAddrLength"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""SocketType"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""Protocol"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ProtocolMaxOffset"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ByteOrder"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""MessageSize"" /t REG_DWORD /d ""32768"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""szProtocol"" /t REG_EXPAND_SZ /d ""@%%SystemRoot%%\System32\mswsock.dll,-60102"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ProviderFlags"" /t REG_DWORD /d ""12"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2"" /v ""ServiceFlags"" /t REG_DWORD /d ""132617"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""Class"" /t REG_DWORD /d ""8"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""DnsPriority"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""HostsPriority"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""LocalPriority"" /t REG_DWORD /d ""4026531839"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""Name"" /t REG_SZ /d ""TCP/IP"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""NetbtPriority"" /t REG_DWORD /d ""4263488238"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"" /v ""ProviderPath"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\wsock32.dll"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Description"" /t REG_SZ /d ""Controls the underlying video driver stacks to provide fully-featured display capabilities."" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""DisplayName"" /t REG_SZ /d ""LDDM Graphics Subsystem"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""ErrorControl"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Group"" /t REG_SZ /d ""Video Init"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Start"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Tag"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Type"" /t REG_DWORD /d ""32"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""DistributeTimers"" /t REG_DWORD /d ""3839"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorLatencyTolerance"" /t REG_DWORD /d ""536870911"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorRefreshLatencyTolerance"" /t REG_DWORD /d ""536870911"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""WppRecorder_TraceGuid"" /t REG_SZ /d ""{fc8df8fd-d105-40a9-af75-2eec294adf8d}"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"" /v ""MouseDataQueueSize"" /t REG_DWORD /d ""18"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\MonitorDataStore"" /v ""DataCashSize"" /t REG_DWORD /d ""15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""BufferSize"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""FlushTimer"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""IntervalSecs"" /t REG_DWORD /d ""60"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""MaximumBuffers"" /t REG_DWORD /d ""15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""MinimumBuffers"" /t REG_DWORD /d ""15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""ServiceDll"" /t REG_EXPAND_SZ /d ""%%SystemRoot%%\System32\GraphicsPerfSvc.dll"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""ServiceDllUnloadOnStop"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""ServiceMain"" /t REG_SZ /d ""ServiceMain"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc\Parameters"" /v ""TimeoutSecs"" /t REG_DWORD /d ""90"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TCPNoDelay"" /t REG_DWORD /d ""4095"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1616"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""TcpDelAckTicks"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MTU"" /t REG_DWORD /d ""988416"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"" /v ""MSS"" /t REG_DWORD /d ""988256"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000093ec45577900000000000000000000000000000093ec45570100000000000000000000000000000093ec45572b00000000000000000000000000000093ec45572c00000000000000000000000000000093ec45570600000000000000000000000000000093ec4557"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{01042ACD-4CEF-4700-8E63-486B18A06653}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000030617857790000000000000000000000000000003061785701000000000000000000000000000000306178572b000000000000000000000000000000306178572c000000000000000000000000000000306178570600000000000000000000000000000030617857"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{020D8964-A7D8-46F9-ABE1-E0115985E325}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000c45dfd5679000000000000000000000000000000c45dfd5601000000000000000000000000000000c45dfd562b000000000000000000000000000000c45dfd562c000000000000000000000000000000c45dfd5606000000000000000000000000000000c45dfd56"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0885640E-49ED-4833-BD6A-245D955DB29F}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""172.20.10.3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpServer"" /t REG_SZ /d ""172.20.10.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""Lease"" /t REG_DWORD /d ""85536"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1380286528"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""T1"" /t REG_DWORD /d ""1380329296"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""T2"" /t REG_DWORD /d ""1380361372"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1380372064"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0600000000000000080000000000000060ce4652ac14020aac1402270300000000000000040000000000000060ce4652ac140a010100000000000000040000000000000060ce4652fffffff03600000000000000040000000000000060ce4652ac140a013500000000000000010000000000000060ce465205000000fc000000000000000000000000000000818c45523300000000000000040000000000000060ce465200014e20"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""ac140a0106000000ba03d8dafe00"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpNameServer"" /t REG_SZ /d ""172.20.2.10 172.20.2.39"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""172.20.10.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{11F8A404-72E7-4E66-9A7C-55D90F1AB305}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{17397C8A-56E6-4309-A7A7-F136385D9613}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.0.14"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.0.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""Lease"" /t REG_DWORD /d ""864000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1467505923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T1"" /t REG_DWORD /d ""1467937923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""T2"" /t REG_DWORD /d ""1468261923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1468369923"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6627565626F687F5B41495"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""06000000000000000800000000000000038c8557d41b28f1d41b28f003000000000000000400000000000000038c8557c0a800fe01000000000000000400000000000000038c8557ffffff0036000000000000000400000000000000038c8557c0a800fe35000000000000000100000000000000038c855705000000fc000000000000000000000000000000dd89785733000000000000000400000000000000038c8557000d2f00"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a800fe060000000024d4b16589"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.0.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpIPAddress"" /t REG_SZ /d ""94.238.154.142"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpServer"" /t REG_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""Lease"" /t REG_DWORD /d ""300"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1455802053"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T1"" /t REG_DWORD /d ""1455802203"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""T2"" /t REG_DWORD /d ""1455802315"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1455802353"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""24F6579776575637024556C65636F6D6027596D26496"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc000000000000000000000000000000cac6c55606000000000000000800000000000000f1c7c556c29e7a0ac29e7a0f03000000000000000400000000000000f1c7c5565eee9ffe01000000000000000400000000000000f1c7c556ffffe00033000000000000000400000000000000f1c7c5560000012c36000000000000000400000000000000f1c7c5565eee9ffe35000000000000000100000000000000f1c7c55605000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpNameServer"" /t REG_SZ /d ""194.158.122.10 194.158.122.15"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""94.238.159.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\24F6579776575637024556C65636F6D6027596D26496"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.224.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""NameServer"" /t REG_SZ /d ""8.8.8.8,8.8.4.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.1.30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""Lease"" /t REG_DWORD /d ""43200"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465403852"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T1"" /t REG_DWORD /d ""1465425452"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""T2"" /t REG_DWORD /d ""1465441652"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465447052"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565626F687D2241314736363"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""060000000000000004000000000000007df65857c0a801fe030000000000000004000000000000007df65857c0a801fe010000000000000004000000000000007df65857ffffff00330000000000000004000000000000007df658570000a8c0360000000000000004000000000000007df65857c0a801fe350000000000000001000000000000007df6585705000000fc000000000000000000000000000000bb4d5857"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a801fe06000000140c76b1a766"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpNameServer"" /t REG_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""192.168.1.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565626F687D2241314736363"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpIPAddress"" /t REG_SZ /d ""10.49.225.216"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpServer"" /t REG_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""Lease"" /t REG_DWORD /d ""130"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339910"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T1"" /t REG_DWORD /d ""1465339975"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""T2"" /t REG_DWORD /d ""1465340023"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465340040"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""6427565675966696"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""520000000000000006000000000000008850575701040a133eab00000600000000000000080000000000000088505757d41b28f1d41b28f003000000000000000400000000000000885057570a37fffe0100000000000000040000000000000088505757fff8000033000000000000000400000000000000885057570000008236000000000000000400000000000000885057570a37fffe350000000000000001000000000000008850575705000000fc00000000000000000000000000000042505757"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpNameServer"" /t REG_SZ /d ""212.27.40.241 212.27.40.240"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpDefaultGateway"" /t REG_MULTI_SZ /d ""10.55.255.254"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\6427565675966696"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.248.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpIPAddress"" /t REG_SZ /d ""192.168.223.106"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpServer"" /t REG_SZ /d ""192.168.223.1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""Lease"" /t REG_DWORD /d ""86400"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1465339966"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T1"" /t REG_DWORD /d ""1465383166"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""T2"" /t REG_DWORD /d ""1465415566"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1465426366"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpNetworkHint"" /t REG_SZ /d ""8405D2052796E647D29344D2F46666963656A656470243633303"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""fc0000000000000000000000000000004250575736000000000000000400000000000000bea15857c0a8df0133000000000000000400000000000000bea158570001518001000000000000000400000000000000bea15857ffffff0035000000000000000100000000000000bea1585705000000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""0a37fffe060000000007cb000100"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{4B60CC79-0175-4BDC-8B2D-5CA4AA06F32A}\8405D2052796E647D29344D2F46666963656A656470243633303"" /v ""DhcpSubnetMaskOpt"" /t REG_MULTI_SZ /d ""255.255.255.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000bd42635379000000000000000000000000000000bd42635301000000000000000000000000000000bd4263532b000000000000000000000000000000bd4263532c000000000000000000000000000000bd42635306000000000000000000000000000000bd426353"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{708573E3-B871-4F8A-9447-EC9F706F7DCE}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000356ce04f79000000000000000000000000000000356ce04f01000000000000000000000000000000356ce04f2b000000000000000000000000000000356ce04f2c000000000000000000000000000000356ce04f06000000000000000000000000000000356ce04f"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{74CE9FE5-FCB4-4CA7-A2E2-F4826A481FC4}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000a24c065079000000000000000000000000000000a24c065001000000000000000000000000000000a24c06502b000000000000000000000000000000a24c06502c000000000000000000000000000000a24c065006000000000000000000000000000000a24c0650"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9430F82A-33AD-4805-A245-036425D9039E}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""EnableDHCP"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""NameServer"" /t REG_SZ /d ""82.163.142.7,95.211.158.134"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""Lease"" /t REG_DWORD /d ""31536000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""1459876321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""T1"" /t REG_DWORD /d ""1475644321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""T2"" /t REG_DWORD /d ""1487470321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""1491412321"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""IPAddress"" /t REG_MULTI_SZ /d ""169.254.123.159"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""SubnetMask"" /t REG_MULTI_SZ /d ""255.255.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{99609B11-2461-4FD2-A038-99485FE71D1F}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""NameServer"" /t REG_SZ /d ""82.163.142.7,95.211.158.134"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpGatewayHardware"" /t REG_BINARY /d ""c0a800fe060000000024d4b16589"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""DhcpGatewayHardwareCount"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9ED4BEA7-7355-4294-8900-ACC345D7445A}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000011b7f2567900000000000000000000000000000011b7f2560100000000000000000000000000000011b7f2562b00000000000000000000000000000011b7f2562c00000000000000000000000000000011b7f2560600000000000000000000000000000011b7f256"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A53106E4-5D00-4CBC-B405-F74C1584EFB1}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000a1f5ef5679000000000000000000000000000000a1f5ef5601000000000000000000000000000000a1f5ef562b000000000000000000000000000000a1f5ef562c000000000000000000000000000000a1f5ef5606000000000000000000000000000000a1f5ef56"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C877250D-4B7C-4E9E-AD35-73C3D5766384}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{C8D5E406-E62F-426A-9F54-55AA78E263CF}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""NameServer"" /t REG_SZ /d ""104.197.191.4"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f00000000000000000000000000000074eab94f7900000000000000000000000000000074eab94f0100000000000000000000000000000074eab94f2b00000000000000000000000000000074eab94f2c00000000000000000000000000000074eab94f0600000000000000000000000000000074eab94f"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{E07146A0-CE89-4A25-8A05-0B2B065E66AA}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""VPNInterface"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""DhcpInterfaceOptions"" /t REG_BINARY /d ""0f000000000000000000000000000000e064015779000000000000000000000000000000e064015701000000000000000000000000000000e06401572b000000000000000000000000000000e06401572c000000000000000000000000000000e064015706000000000000000000000000000000e0640157"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F2033375-981A-4837-9B79-886C0C8DDA09}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""UseZeroBroadcast"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""EnableDeadGWDetect"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""EnableDHCP"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""NameServer"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""Domain"" /t REG_SZ /d """" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""RegistrationEnabled"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""RegisterAdapterName"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpIPAddress"" /t REG_SZ /d ""0.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpSubnetMask"" /t REG_SZ /d ""255.0.0.0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpServer"" /t REG_SZ /d ""255.255.255.255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""Lease"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""LeaseObtainedTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""T1"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""T2"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""LeaseTerminatesTime"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""AddressType"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""IsServerNapAware"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""DhcpConnForceBroadcastFlag"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""TcpAckFrequency"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""TCPNoDelay"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{F73B9E00-323A-451D-B553-FEB28BFCC91E}"" /v ""MTU"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SOFTWARE\Microsoft\MSMQ\Parameters"" /v ""TCPNoDelay"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""Win32PrioritySeparation"" /t REG_DWORD /d ""135"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MaximumBuffers"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""MinimumBuffers"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""TimeoutSecs"" /t REG_DWORD /d ""30"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""ConvertibleSlateMode"" /t REG_DWORD /d ""4294967295"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ8Priority"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"" /v ""IRQ16Priority"" /t REG_DWORD /d ""255"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Description"" /t REG_SZ /d ""Controls the underlying video driver stacks to provide fully-featured display capabilities."" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""DisplayName"" /t REG_SZ /d ""LDDM Graphics Subsystem"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""ErrorControl"" /t REG_DWORD /d ""0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Group"" /t REG_SZ /d ""Video Init"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""ImagePath"" /t REG_EXPAND_SZ /d ""\SystemRoot\System32\drivers\dxgkrnl.sys"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Start"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Tag"" /t REG_DWORD /d ""16"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""Type"" /t REG_DWORD /d ""32"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorLatencyTolerance"" /t REG_BINARY /d ""31ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff31fff0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl"" /v ""MonitorRefreshLatencyTolerance"" /t REG_BINARY /d ""31ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff31fff0"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DpcWatchdogProfileOffset"" /t REG_DWORD /d ""10000"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""ObUnsecureGlobalNames"" /t REG_MULTI_SZ /d ""netfxcustomperfcounters.1.0\0SharedPerfIPCBlock\0Cor_Private_IPCBlock\0Cor_Public_IPCBlock_"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""SeTokenSingletonAttributesConfig"" /t REG_DWORD /d ""3"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""obcaseinsensitive"" /t REG_DWORD /d ""1"" /f
Reg.exe add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"" /v ""DistributeTimers"" /t REG_DWORD /d ""4294967295"" /f