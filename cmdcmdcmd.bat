        @echo off
        color a
        del /s /f /q c:\windows\temp\*.*
        color b
        rd /s /q c:\windows\temp
        color c
        md c:\windows\temp
        color d
        del /s /f /q C:\WINDOWS\Prefetch
        color e
        del /s /f /q C:\Windows\SoftwareDistribution\Download
        color f
        del /s /f /q %temp%\*.*
        color a
        rd /s /q %temp%
        color b
        md %temp%
        color c
        deltree /y c:\windows\tempor~1
        color d
        deltree /y c:\windows\temp
        color e
        deltree /y c:\windows\tmp
        color f
        deltree /y c:\windows\ff*.tmp
        color a
        deltree /y c:\windows\history
        color b
        deltree /y c:\windows\cookies
        color c
        deltree /y c:\windows\recent
        color d
        deltree /y c:\windows\spool\printers
        color e
        del c:\WIN386.SWP
        color a
        del /s /f /q C:\ProgramData\spf
        @echo off
        @echo off