# PSRecon
# This PSCore automation tool is built for reconnaissance automation toward the OSCP.
# Readme = Notes & Requirements
# created by: l0new0lf-0ffsec
##########################################

#region Input
$Subnet = '10.11.1' # ex. 'xx.xx.xx'
$Adapter = 'tap0' # ex. 'tap0'
$Rate = 5000 # masscan (test to find best)
#endregion Input

$Root = "$Home/Desktop/PSRecon"
$JSON_Report = "$Root/PSScan.json"

##########################################

#region Verification
# Check Sudo..
if (-not (timeout 2 sudo id)) {
    return "This Script Requires [Sudo] Access"
    exit
}

# Check Adapter..
if (-not (ifconfig $Adapter)) {
    return "Fix [Adapter] Config"    
    exit
}

# Check Subnet..
if (-not $Subnet) {
    return "Fix [Subnet] Config"
    exit
}
#region Verification

$IP = [string](ifconfig $Adapter | grep 'inet' | cut -d: -f2 | awk '{ print $2}')
$RouterIP = [string]( ((($IP).split('.')[1..3]) -join '.').trim() + '.1')
$AutoTitle = @"
########################################################
#                 OSCP | PSCore Recon                  #
#                   l0new0lf-0ffsec                    #
########################################################
"@
Clear-Host
# Create or Load Environment
if (Test-Path "$Root/Network-Scan.json") {
    $Network_Scan = Get-Content "$Root/Network-Scan.json" | ConvertFrom-Json
}
if (($Network_Scan.Scan).count -eq 0) {
    Write-Host "$AutoTitle`n`nSetting Up Environment`nPlease Wait.."

    # Create Scan Master Location
    if (-not (Test-Path "$Root")) {
        New-Item "$Root" -ItemType Directory | Out-Null
    }

    # Main Variable
    $Network_Scan = [PSCustomObject]@{
        Network = [PSCustomObject]@{
            Subnet = "$Subnet"
            DNS    = @()
            Online = @()
        }
        Scan    = [PSCustomObject]@()
    }

    # Collect IPs Online
    $Network_Scan.Network.Online = (nmap -n -T5 -e "$Adapter" -sn "$Subnet.0/24" -oG - `
        | grep "Host").split(' ') | Where-Object { $_ -like "*.*.*.*" }

    # Collect DNS
    $Network_Scan.Network.DNS = (nmap $Network_Scan.Network.Online -T5 -Pn -p 53 --open -e "$Adapter" -oG - `
        | grep "Ports").split(' ') | Where-Object { $_ -like "*.*.*.*" }

    # Resolve HostNames & Create Object Shell
    python ./dnsrecon/dnsrecon.py -r "$($Network_Scan.Network.Online[0])-$($Network_Scan.Network.Online[-1])" `
        -n "$($Network_Scan.Network.DNS[0])" -j "$Root/dnsrecon.json"
    $DNSRecon_Data = Get-Content "$Root/dnsrecon.json" | ConvertFrom-Json -AsHashtable
    $DNSRecon_Results = $DNSRecon_Data | Select-Object -Skip 1 | Sort-Object -Property { [System.Version]$_.address }
    ForEach ($_ in $DNSRecon_Results) {
        $Network_Scan.Scan += [PSCustomObject][Ordered]@{
            IP    = "$($_.address)"
            Name  = "$($_.name)"
            OS    = [PSCustomObject]@()
            Ports = [PSCustomObject]@()
            Vulns = [PSCustomObject]@()
        }
    }
    Remove-Item "$Root/dnsrecon.json" -Force
    $Network_Scan | ConvertTo-Json -Depth 3 | Out-File "$JSON_Report" -Force

    # Update 'IP to HostName' List
    if ( (Get-Content /etc/hosts).count -lt 60 ) {
        "`n`n# Target List" | Out-File /etc/hosts -Append
        $Network_Scan | ForEach-Object { "$($_.IP) $($_.Host)" | Out-File /etc/hosts -Append }
        Write-Host "`nUpdated Hosts List!`n"
    }

    # Create temp dir for scanner
    if (-not (Test-Path "$Root/temp")) {
        New-Item "$Root/temp" -ItemType Directory | Out-Null
    }
}
else {
    Write-Host "$AutoTitle`n`nFound Environment.."
}

### Scan
Write-Host "`n`nStarting Recon Scan`nPlease Wait.."
Start-Sleep -Seconds 2
$t = ($Network_Scan.Scan).count
$c = 1
Clear-Host
foreach ($System in $Network_Scan.Scan) {
    Write-Host "$AutoTitle`n"
    Write-Host "($c/$t) Scan In Progress..`nTarget: $($System.Name)`nIP: $($System.IP)`n"

    # Port Scan
    masscan $System.IP -c base.conf --rate $Rate --router-ip $RouterIP -e "$Adapter" `
        -oJ "$Root/temp/$($System.Name).json"
    $MasScan = Get-Content "$Root/temp/$($System.Name).json" | ConvertFrom-Json
    Remove-Item "$Root/temp/$($System.Name).json" -Force
    ForEach ($Port in ($MasScan | Sort-Object { $_.ports.port })) {
        $Current = try {
            $System.Ports.Port.Contains([string]($Port.ports.port))
        }
        catch {
            $null
        }
        if (-not $Current) {
            $System.Ports += [PSCustomObject][ordered]@{
                Port        = "$($Port.ports.port)"
                Protocol    = "$($Port.ports.proto)"
                ServiceName = ""
                Name        = ""
                Version     = ""
                Accuracy    = ""
            }
        }
        else {
            ($System.Ports | Where-Object { $_.Port -eq "$($Port.ports.port)" }).Port = "$($Port.ports.port)"
            ($System.Ports | Where-Object { $_.Port -eq "$($Port.ports.port)" }).Protocol = "$($Port.ports.proto)"
            ($System.Ports | Where-Object { $_.Port -eq "$($Port.ports.port)" }).ServiceName = ""
            ($System.Ports | Where-Object { $_.Port -eq "$($Port.ports.port)" }).Accuracy = ""
            ($System.Ports | Where-Object { $_.Port -eq "$($Port.ports.port)" }).Name = ""
            ($System.Ports | Where-Object { $_.Port -eq "$($Port.ports.port)" }).Version = ""
        }
    }

    # Collect Target Ports for Nmap and build switch
    $TCP = [string](($System.Ports | Where-Object { $_.Protocol -eq 'tcp' }).Port -join ',')
    $UDP = [string](($System.Ports | Where-Object { $_.Protocol -eq 'udp' }).Port -join ',')
    $TargetPorts = if (-not $UDP) { "T:$TCP" }else { "T:$TCP,U:$UDP" }

    # OS and Service Discovery
    nmap $System.IP -Pn -v2 -T4 -e "$Adapter" -O -sV -sU -sS -p"$TargetPorts" -oX "$Root/temp/$($System.Name).xml"

    $XMl = [xml](Get-Content "$Root/temp/$($System.Name).xml")
    Remove-Item "$Root/temp/$($System.Name).xml" -Force
    $Services = $XMl.nmaprun.host.ports.port
    $Service_Data = ForEach ($_ in $Services) {
        $_ | Select-Object -Property @{N = "Port"; E = { $_.portid } },
        @{N = "Name"; E = { $_.service.name } },
        @{N = "Product"; E = { $_.service.product } },
        @{N = "Version"; E = { $_.service.version } },
        @{N = "Extra"; E = { $_.service.extrainfo } },
        @{N = "Tunnel"; E = { $_.service.tunnel } },
        @{N = "Accuracy"; E = { ($_.service.conf / 10).ToString("P") } }
    }

    # Add OS results
    $System.OS = $XMl.nmaprun.host.os.osmatch | Select-Object -Property @{N = "Name"; E = { $_.name } } , @{N = "Accuracy"; E = { ($_.accuracy / 100).ToString("P") } }

    # Add Service Versions
    ForEach ($Item in $Service_Data) {
        $Title = ($Item | Get-Member | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Definition -notlike "*null" `
                    -and ($_.Name -ne 'Accuracy' -and $_.Name -ne 'Port') }).Definition | ForEach-Object {
            "$(($_).split('=') | Select-Object -Last 1)"
        }
        if ($Title) { $Title = $Title -join ' | ' }else { $Title = $Item.Name }
        ($System.Ports | Where-Object { $_.Port -eq "$($Item.Port)" }).ServiceName = $Title
        ($System.Ports | Where-Object { $_.Port -eq "$($Item.Port)" }).Accuracy = $Item.Accuracy
        ($System.Ports | Where-Object { $_.Port -eq "$($Item.Port)" }).Name = $Item.Name
        ($System.Ports | Where-Object { $_.Port -eq "$($Item.Port)" }).Version = $Item.Version
    }

    # Record To Scan Data
    Write-Host "Updated Network Json --> [$JSON_Report]"
    $Network_Scan | ConvertTo-Json -Depth 5 | Out-File "$JSON_Report" -Force
    Start-Sleep -Seconds 2
    $c++
    Clear-Host
}

return Write-Host "$AutoTitle`n`nScan is Complete..`nResults : [$JSON_Report]"