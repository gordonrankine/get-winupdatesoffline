# Get-WinUpdastesOffline

This PowerShell script will search for either installed or missing Windows Updates and output the results to a csv file. The script does not need to connect to the internet to search for updates. The script works in offline mode but it does require the Microsoft wsusscn2.cab file to be downloaded for use. The cab file can be downloaded from http://go.microsoft.com/fwlink/?LinkId=76054. This script is an enhanced version of Microsoft's VB script from https://docs.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline.

## Parameters

.PARAMETER cab
This is the cab file used to determine if the Windows updates are installed or missing.
It can be downloaded from http://go.microsoft.com/fwlink/?LinkId=76054.
Note: This file changes at least once a month but the link does not change. It is recommended to download a new file every time this script is run.

.PARAMETER outDir
This is the directory where the csv reports are stored. If the directory doesn't exist it will be created.

.PARAMETER isInstalled
If set to Yes, the script will search for installed updates. If set to No, the script will search for missing updates.

.PARAMETER skipAgeCheck
[OPTIONAL] In normal operation if the file is older than 30 days the script will not continue.
If the file is between 2 and 29 days a warning will be displayed before the script continues.
If set to Yes, this skips the checking of the age of the WSUS scan file and the script will run and not display a warning.

## Examples

.EXAMPLE
.\Get-WinUpdatesOffline.ps1 -cab "c:\temp\wsusscn2.cab" -outDir "c:\temp" -isInstalled No
Produces a csv report that gathers missing Windows Updates and saves the report to c:\temp

.EXAMPLE
.\Get-WinUpdatesOffline.ps1 -cab "c:\temp\wsusscn2.cab" -outDir "c:\temp" -isInstalled Yes
Produces a csv report that gathers installed Windows Updates and saves the report to c:\temp

.EXAMPLE
.\Get-WinUpdatesOffline.ps1 -cab "c:\temp\wsusscn2.cab" -outDir "c:\temp" -isInstalled No -skipAgeCheck Yes
Produces a csv report that gathers missing Windows Updates and saves the report to c:\temp. The age check for wsusscn2.cab file is not performed.

## Why This Script

I needed to search some computers for missing Windows Updates for one of the projects I was working on. While researching how to do this I found Micorsoft's VB script that carried this out but it was rather limited in it's output and was a VB script. Not very PowerShelly at at all so I wrote my own version of it.

## Script Info

Based on Microsoft's VB script but has a lot more features such as; Enhanced output, cab file checking and error reporting.

## Future Updates

- None planned.

## Feedback

Please use GitHub Issues to report any, well.... issues with the script.
