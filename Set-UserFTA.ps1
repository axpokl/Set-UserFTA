<#
Set-UserFTA
	Set File Type Association Default Application Command Line Windows 10
Usage
	.\Set-UserFTA.ps1 -Ext <extension> -ProgId <progid>
Example
	.\Set-UserFTA.ps1 -Ext ".txt" -ProgId "txtfile"
	.\Set-UserFTA.ps1 -Ext ".pdf" -ProgId "AcroExch.Document.DC"
	.\Set-UserFTA.ps1 -Ext ".htm" -ProgId "ChromeHTML"
#>

param([string]$Ext, [string]$ProgId)
function Calc-Value($a, $b, $c){return ($a * $c + $b * ($c -shr 0x10)) -band 0xFFFFFFFFL}
function Get-MSHash([byte[]]$MD5, [string]$Data)
{
	$MD51 = [BitConverter]::ToUInt32($MD5, 0) -bor 1
	$MD52 = [BitConverter]::ToUInt32($MD5, 4) -bor 1
	for ($i = 0; $i -lt [uint32][math]::Floor($Data.length / 4); $i++)
	{
		$D = ([uint32]$Data[$i * 4 + 0]) + ([uint32]$Data[$i * 4 + 1] -shl 0x10)
		$X0 = ($D + $X1) -band 0xFFFFFFFFL
		$X1 = ($MD51 * $X0) -band 0xFFFFFFFFL
		$X0 = Calc-Value 0x69FB0000L 0xEF0569FBL $X0
		$X1 = ($X1 + $X0) -band 0xFFFFFFFFL
		$X1 = Calc-Value 0x79F8A395L 0x689B6B9FL $X1
		$X1 = Calc-Value 0xEA970001L 0xC3EFEA97L $X1
		$Y0 = ($D + $Y1) -band 0xFFFFFFFFL
		$Y1 = ($MD51 * $Y0) -band 0xFFFFFFFFL
		$Y1 = Calc-Value 0xB1110000L 0xCF98B111L $Y1
		$Y1 = Calc-Value 0x5B9F0000L 0x87085B9FL $Y1
		$Y1 = Calc-Value 0xB96D0000L 0x12CEB96DL $Y1
		$Y1 = Calc-Value 0x1D830000L 0x257E1D83L $Y1
		$X2 = ($X1 + $X2) -band 0xFFFFFFFFL
		$Y2 = ($Y1 + $Y2) -band 0xFFFFFFFFL
		$D = ([uint32]$Data[$i * 4 + 2]) + ([uint32]$Data[$i * 4 + 3] -shl 0x10)
		$X0 = ($D + $X1) -band 0xFFFFFFFFL
		$X1 = ($MD52 * $X0) -band 0xFFFFFFFFL
		$X0 = Calc-Value 0x13DB0000L 0xC31713DBL $X0
		$X1 = ($X1 + $X0) -band 0xFFFFFFFFL
		$X1 = Calc-Value 0x59C3AF2DL 0xDDCD1F0FL $X1
		$X1 = Calc-Value 0x1EC90001L 0x35BD1EC9L $X1
		$X2 = ($X1 + $X2) -band 0xFFFFFFFFL
		$Y0 = ($D + $Y1) -band 0xFFFFFFFFL
		$Y1 = ($MD52 * $Y0) -band 0xFFFFFFFFL
		$Y1 = Calc-Value 0x16F50000L 0xA27416F5L $Y1
		$Y1 = Calc-Value 0x96FF0000L 0xD38396FFL $Y1
		$Y1 = Calc-Value 0x2B890000L 0x7C932B89L $Y1
		$Y1 = Calc-Value 0x9F690000L 0xBFA49F69L $Y1
		$Y2 = ($Y1 + $Y2) -band 0xFFFFFFFFL
	}
	$H1 = [uint64]($X1 -bxor $Y1)
	$H2 = [uint64]($X2 -bxor $Y2)
	$H0 = [uint64](($H2 -shl 32) + $H1)
	$MSHash = [BitConverter]::GetBytes($H0)
	Write-Output $MSHash
}

$Time = ([uint64][math]::Floor((Get-Date).ToFileTime() / 600000000L) * 600000000L).ToString("X16")
$SID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$UserExp = "user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}"
$Data = (($Ext + $SID + $ProgId + $Time + $UserExp) + "`0").ToLower()
$MD5 = [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Data))
$MSHash = Get-MSHash $MD5 $Data
$Hash = [Convert]::ToBase64String($MSHash)
echo $Hash

$Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\" + $Ext + "\UserChoice"
$Key = "HKCU:\" + $Path
if (-not (Test-Path $Key)) { New-Item $Key | Out-Null }
$Reg = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
$Acl = $Reg.GetAccessControl()
$Rules = $Acl.Access | ? {$_.AccessControlType -eq 'Deny' -and $_.RegistryRights -eq "SetValue"}
Foreach ($Rule in $Rules) {$Acl.RemoveAccessRule($Rule) | Out-Null}
$Reg.SetAccessControl($Acl)
Set-ItemProperty -Path $Key -Name "ProgId" -Value $ProgId -Type "String"
Set-ItemProperty -Path $Key -Name "Hash" -Value $Hash -Type "String"
