<#
	.SYNOPSIS
		Creates a XML of a list of  computer.
	
	.DESCRIPTION
		This script is to retrieve the system information in XML. Then we can merge that with another script to create a computer information document.
		This is primarilydesigned for  server audits. It uses CIM to gather certain information. 
	
	.PARAMETER computername
		This is the computer to query.
	
	.PARAMETER path
		The file path to save the file.
	
	.PARAMETER local
		This determines whether the computer/s you are querying is local. This is important to choose because it determines how it queries certain information
	
	.PARAMETER dcom
		This is used against servers that can't use Get-CimInstance. Must be used against Powershell V2.
	
	.EXAMPLE
		./New-ServerXML -computername Server01 -path c:\temp\
		This will query the remote machine Server01 and put the xml files in c:\temp
	
	.EXAMPLE
		./New-ServerxML -computername DC1, DC2, DC3 -path c:\reports
		This will query the remote machine Server01 and put the xml files in c:\reports
	
	.EXAMPLE
		./New-ServerXML -computername Management -path c:\reports -local
		This will scan a local machine (Management) and then put that into the path c:\reports

	.EXAMPLE 
		./New-ServerXML -computername Management -path c:\reports -local -dcom
		This will scan a local machine with DCOM or WMI. This server would be a Windows 2008 R2 machine with Powershell Version 2.0
		
	.NOTES
		Need to have admin rights in the shell to run the command. Will also need to have Powershell remoting enabled to access remote machines to get full information.
		
#>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true,
			   ValueFromPipeline = $true,
			   ValueFromPipelineByPropertyName = $true,
			   Position = 1)]
	[string[]]$computername,
	[Parameter(Mandatory = $true)]
	[string]$path,
	[Parameter(Mandatory = $false)]
	[switch]$local,
	[switch]$dcom
)



#region Variables 

$FWprofileTypes = @{ 1GB = "All"; 1 = "Domain"; 2 = "Private"; 4 = "Public" }
$FwAction = @{ 1 = "Allow"; 0 = "Block" }
$FwProtocols = @{
	1 = "ICMPv4"; 2 = "IGMP"; 6 = "TCP"; 17 = "UDP"; 41 = "IPv6"; 43 = "IPv6Route"; 44 = "IPv6Frag";
	47 = "GRE"; 58 = "ICMPv6"; 59 = "IPv6NoNxt"; 60 = "IPv6Opts"; 112 = "VRRP"; 113 = "PGM"; 115 = "L2TP";
	"ICMPv4" = 1; "IGMP" = 2; "TCP" = 6; "UDP" = 17; "IPv6" = 41; "IPv6Route" = 43; "IPv6Frag" = 44; "GRE" = 47;
	"ICMPv6" = 48; "IPv6NoNxt" = 59; "IPv6Opts" = 60; "VRRP" = 112; "PGM" = 113; "L2TP" = 115
}
$FWDirection = @{ 1 = "Inbound"; 2 = "outbound"; "Inbound" = 1; "outbound" = 2 }
#endregion


function Get-FirewallState
{
<#
	.SYNOPSIS
		Displays the Windows Firewall state for Domain, Private, and Public profiles on local or remote computer.
	
	.DESCRIPTION
		Use Get-FirewallState to show current Firewall state that is presented on the Windows Firewall with Advanced Security Properties page, with the tabs for Domain, Private, and Public profiles.
	
	.PARAMETER ComputerName
		Specifies the remote or local computer name.
		When using ComputerName parameter, Windows PowerShell creates a temporary connection that is used only to run the specified command and is then closed.
	
	.EXAMPLE
		Get-FirewallState -ComputerName SERVER01
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ComputerName
	)
	
	$ErrorActionPreference = "Stop"
	Try
	{
		$FirewallBlock = {
			$content = netsh advfirewall show allprofiles
			If ($domprofile = $content | Select-String 'Domain Profile' -Context 2 | Out-String)
			{ $domainpro = ($domprofile.Substring($domprofile.Length - 9)).Trim() }
			Else { $domainpro = $null }
			If ($priprofile = $content | Select-String 'Private Profile' -Context 2 | Out-String)
			{ $privatepro = ($priprofile.Substring($priprofile.Length - 9)).Trim() }
			Else { $privatepro = $null }
			If ($pubprofile = $content | Select-String 'Public Profile' -Context 2 | Out-String)
			{ $publicpro = ($pubprofile.Substring($pubprofile.Length - 9)).Trim() }
			Else { $publicpro = $null }
			
			$FirewallObject = New-Object PSObject
			Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallDomain" -value $domainpro
			Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallPrivate" -value $privatepro
			Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallPublic" -value $publicpro
			$FirewallObject
		}
		
		Invoke-Command -computerName $ComputerName -command $FirewallBlock | Select-Object FirewallDomain, FirewallPrivate, FirewallPublic
		
	}
	Catch
	{
		Write-Error ($_.Exception.Message -split ' For')[0]
	}
}


# Hash table to save System Report
foreach ($computer in $computername)
{
	
	$SystemReport = @{ }
	$filepath = Join-Path -Path $Path -ChildPath "$computer.xml"
	if ($local)
	{
		$CCMEXEC = get-process -ComputerName $computer -name CcmExec
	}
	else
	{
		$CCMEXEC = Invoke-Command -ComputerName $computer { get-process -name CcmExec }
	}
	if ($local)
	{
		$SCOM = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.displayname -like "*operations manager agent*" } | select displayname
		#$SCOM = Get-RemoteSoftware -ComputerName $computer | where name -like "*operations manager agent*" | select name
	}
	else
	{
		$SCOM = invoke-command -computer $computer { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* } | where displayname -like "*operations manager agent*" | select displayname
	}
	
	if ($local)
	{
		#$ENDPOINT = Get-RemoteSoftware -ComputerName $computer | where name -like "*Symantec endpoint*" | select name
		$ENDPOINT = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.displayname -like "*Symantec endpoint*" } | select displayname
	}
	if ($dcom)
	{
		$TimeService = Get-WmiObject -ComputerName $computer -classname win32_Service | where { $_.name -eq "W32time" } | select -ExpandProperty state
	}
	Else
	{
		$TimeService = Get-CimInstance -ComputerName $computer -classname win32_Service | where { $_.name -eq "W32time" } | select -ExpandProperty state
	}
	#$TimeService = Get-Service -ComputerName $computer -Name W32Time | where { $_.status -EQ "running" } | select -ExpandProperty status
	#region NBTStatus
	$nbstatus = DATA
	{
		ConvertFrom-StringData -StringData @'
0 = EnableNetbiosViaDhcp
1 = EnableNetbios
2 = DisableNetbios
'@
	}
	#endregion
	#region Main information
	
	#region Operating System information
	if ($dcom)
	{
		$Systemreport.OperatingSystem = $((Get-Wmiobject -computer $computer -ClassName Win32_OperatingSystem).caption)
	}
	else
	{
		$Systemreport.OperatingSystem = $((Get-CimInstance -computer $computer -ClassName Win32_OperatingSystem).caption)
	}
	
	if ($dcom)
	{
		$Systemreport.ServicePack = $((get-wmiobject -computer $computer -ClassName Win32_OperatingSystem).ServicePackMajorVersion)
	}
	else
	{
		$Systemreport.ServicePack = $((Get-CimInstance -computer $computer -ClassName Win32_OperatingSystem).ServicePackMajorVersion)
	}
	
	if ($dcom)
	{
		
		$SystemReport.name = $((Get-WmiObject -computer $computer -ClassName Win32_OperatingSystem).PSComputername)
	}
	else
	{
		$SystemReport.name = $((Get-Ciminstance -computer $computer -ClassName Win32_OperatingSystem).PSComputername)
	}
	
	if ($dcom)
	{
		$SystemReport.Description = $(Get-WmiObject -ComputerName $computer -ClassName Win32_operatingsystem | select Description)
	}
	else
	{
		$SystemReport.Description = $(Get-CimInstance -ComputerName $computer -ClassName Win32_operatingsystem | select Description)
	}
	
	if ($dcom)
	{
		$SystemReport.AutomaticManagedPageFile = $((Get-WmiObject -computer $computer -ClassName Win32_ComputerSystem).AutomaticManagedPageFile)
	}
	else
	{
		$SystemReport.AutomaticManagedPageFile = $((Get-Ciminstance -computer $computer -ClassName Win32_ComputerSystem).AutomaticManagedPageFile)
	}
	#endregion
	
	#region Hardware Related Information
	if ($dcom)
	{
		$SystemReport.numCPU = $((Get-WmiObject -computer $computer -ClassName Win32_Processor).NumberofCores)
	}
	else
	{
		$SystemReport.numCPU = $((Get-CimInstance -computer $computer -ClassName Win32_Processor).NumberofCores)
	}
	
	if ($dcom)
	{
		$SystemReport.RAM = $((get-wmiobject -computer $computer -ClassName Win32_ComputerSystem).TotalPhysicalMemory)
	}
	else
	{
		$SystemReport.RAM = $((Get-CimInstance -computer $computer -ClassName Win32_ComputerSystem).TotalPhysicalMemory)
	}
	
	
	#endregion
	
	#region Logical Disk Information
	if ($dcom)
	{
		$SystemReport.FixedDisk = $(Get-WmiObject -computername $computer -ClassName Win32_LogicalDisk | where { $_.drivetype -eq "3" } | Select @{ n = 'DriveLetter'; e = { $_.DeviceID } }, @{ n = 'VolumeName'; e = { $_.VolumeName } }, @{ n = 'FreespaceGB'; e = { $_.freespace/1GB -as [int] } }, @{ n = 'TotalSizeGB'; e = { $_.size/1GB -as [int] } })
	}
	else
	{
		$SystemReport.FixedDisk = $(Get-CimInstance -computername $computer -ClassName Win32_LogicalDisk | where { $_.drivetype -eq "3" } | Select @{ n = 'DriveLetter'; e = { $_.DeviceID } }, @{ n = 'VolumeName'; e = { $_.VolumeName } }, @{ n = 'FreespaceGB'; e = { $_.freespace/1GB -as [int] } }, @{ n = 'TotalSizeGB'; e = { $_.size/1GB -as [int] } })
	}
	if ($dcom)
	{
		$SystemReport.OpticalDrive = $(Get-WmiObject -computername $computer -ClassName Win32_LogicalDisk | where { $_.drivetype -eq "5" } | Select @{ n = 'DriveLetter'; e = { $_.DeviceID } })
	}
	else
	{
		$SystemReport.OpticalDrive = $(Get-Ciminstance -computername $computer -ClassName Win32_LogicalDisk | where { $_.drivetype -eq "5" } | Select @{ n = 'DriveLetter'; e = { $_.DeviceID } })
	}
	#endregion
	
	#region Networking Related Information
	if ($dcom)
	{
		$SystemReport.DNS = $((get-wmiobject -computername $computer -ClassName win32_networkadapterconfiguration | where { $_.servicename -eq "vmxnet3ndis6" }).DNSServerSearchOrder -split ',')
	}
	else
	{
		$SystemReport.DNS = $((Get-CimInstance -computername $computer -ClassName win32_networkadapterconfiguration | where { $_.servicename -eq "vmxnet3ndis6" }).DNSServerSearchOrder -split ',')
	}
	
	if ($dcom)
	{
		$SystemReport.DNSSuffix = $((get-wmiobject -computername $computer -ClassName win32_networkadapterconfiguration | where { $_.servicename -eq "vmxnet3ndis6" }).DNSDomainSuffixSearchOrder -split ',')
	}
	else
	{
		$SystemReport.DNSSuffix = $((Get-Ciminstance -computername $computer -ClassName win32_networkadapterconfiguration | where { $_.servicename -eq "vmxnet3ndis6" }).DNSDomainSuffixSearchOrder -split ',')
	}
	if ($dcom)
	{
		$SystemReport.TCPIPNetbios = $(Get-WmiObject -computername $computer -Class Win32_NetWorkAdapterConfiguration | Where { $_.IPEnabled -eq $true } | Select  Index, @{ N = 'NetBIOSOption'; E = { $nbstatus["$($_.TcpipNetbiosOptions)"] } })
	}
	else
	{
		$SystemReport.TCPIPNetbios = $(Get-Ciminstance -computername $computer -Class Win32_NetWorkAdapterConfiguration | Where { $_.IPEnabled -eq $true } | Select  Index, @{ N = 'NetBIOSOption'; E = { $nbstatus["$($_.TcpipNetbiosOptions)"] } })
	}
	if ($dcom)
	{
		$SystemReport.LMHostLookupEnabled = $(get-wmiobject -computername $computer -ClassName win32_networkadapterconfiguration | Where { $_.IPEnabled -eq $true } | select  WINSEnableLMHostsLookup)
	}
	
	else
	{
		$SystemReport.LMHostLookupEnabled = $(Get-CimInstance -computername $computer -ClassName win32_networkadapterconfiguration | Where { $_.IPEnabled -eq $true } | select  WINSEnableLMHostsLookup)
	}
	#endregion
	
	#region Software Information
	
	$SystemReport.SCCMAGentInstalled = $($CCMEXEC -ne $null)
	$SystemReport.SCOMAgentInstalled = $($SCOM -ne $null)
	$SystemReport.SymantecEndpointInstalled = $($ENDPOINT -ne $null)
	#endregion
	
	#region Services Information
	$SystemReport.TimeserviceRunning = $($test -eq $null)
	#endregion
	
	#region SCCM client
	if ($dcom)
	{
		$SystemReport.SCCMCompliance = $(Get-WmiObject -Query "Select * from CCM_AssignmentCompliance" -Namespace root\ccm\SoftwareUpdates\DeploymentAgent -ComputerName $computer | select AssignmentID, IsCompliant)
	}
	
	else
	{
		$SystemReport.SCCMCompliance = $(Get-Ciminstance -Query "Select * from CCM_AssignmentCompliance" -Namespace root\ccm\SoftwareUpdates\DeploymentAgent -ComputerName $computer | select AssignmentID, IsCompliant)
	}
	#endregion
	
	#region Firewall Information
	$SystemReport.Firewallinformation = $(Get-FirewallState -ComputerName $computer)
	#endregion
	
	if ($local)
	{
		$SystemReport.RegionalSetting = Get-ItemProperty -Path "Registry::\HKEY_USERS\.DEFAULT\Control Panel\International" | select -ExpandProperty localename
	}
	else
	{
		$SystemReport.RegionalSetting = invoke-command -computername $computer -scriptblock { Get-ItemProperty -Path "Registry::\HKEY_USERS\.DEFAULT\Control Panel\International" | select -expand localename }
	}
	
	$SystemReport.InstalledWindowsFeatures = $(Get-WindowsFeature -ComputerName $computer | where { $_.installstate -eq "Installed" -and $_.featuretype -eq "Role" } | select displayname, installstate)
	$SystemReport | Export-Clixml $filepath
	
}
