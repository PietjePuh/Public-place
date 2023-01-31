#var
$domain = Read-Host "webpage"
#Install-Module -Name MxLookup 

#function
function Get-DMARCRecord {
    <#
    .SYNOPSIS
        Get DMARC Record for a domain.
    .DESCRIPTION
        This function uses Resolve-DNSName to get the DMARC Record for a given domain. Objects with a DomainName property,
        such as returned by Get-AcceptedDomain, can be piped to this function.
    .EXAMPLE
        Get-AcceptedDomain | Get-DMARCRecord
 
        This example gets DMARC records for all domains returned by Get-AcceptedDomain.
    #>
    [CmdletBinding(HelpUri = 'https://ntsystems.it/PowerShell/TAK/Get-DMACRecord/')]
    param (
        # Specify the Domain name to use for the query.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true)]
        [string]
        $DomainName,
        
        # Specify a DNS server to query.
        [string]
        $Server
    )
    process {    
        $params = @{
            Name = "_dmarc.$DomainName"
            ErrorAction = "SilentlyContinue"
        }
        if($Server) { $params.Add("Server",$Server) }
        $dnsTxt = Resolve-DnsName @params -Type  TXT | Where-Object Type -eq TXT  
        $dnsTxt | Select-Object @{Name = "DMARC"; Expression = {"$DomainName`:$s"}},@{Name = "Record"; Expression = {$_.Strings}}    
    }    
}
function Get-SPFRecord {
    <#
    .Synopsis
    Get SPF Record for a domain.
    .DESCRIPTION
    This function uses Resolve-DNSName to get the SPF Record for a given domain. Objects with a DomainName property,
    such as returned by Get-AcceptedDomain, can be piped to this function.
    .EXAMPLE
    Get-AcceptedDomain | Get-SPFRecord
 
    This example gets SPF records for all domains returned by Get-AcceptedDomain.
    #>
    [CmdletBinding(HelpUri = 'https://ntsystems.it/PowerShell/TAK/Get-SPFRecord/')]
    param (
        # Specify the Domain name for the query.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true)]
        [string]
        $DomainName,
        
        # Specify the Domain name for the query.
        [string]
        $Server
    )
    process {
        $params = @{
            Type = "txt"
            Name = $DomainName
            ErrorAction = "Stop"
        }
        if($Server) { $params.Add("Server",$Server) }
        try {
            $dns = Resolve-DnsName @params | Where-Object Strings -Match "spf1"
            $dns | Select-Object @{Name="DomainName";Expression={$_.Name}},@{Name="Record";Expression={$_.Strings}}
        } catch {
            Write-Warning $_
        }
    }
}

#config
echo "============================SPFRecord========================================="
Get-SPFRecord $domain  | Fl
echo "============================Dmarc========================================="
Get-DMARCRecord $domain | select record | fl
echo "============================MX========================================="
Resolve-DnsName $domain -Type mx | select 'NameExchange'  | Ft
echo "============================TXT========================================="
Resolve-DnsName $domain -Type TXT |select 'Strings'  | Fl
echo "============================A========================================="
Resolve-DnsName $domain -Type a | select 'IPAddress' | FL
echo "============================NS========================================="
Resolve-DnsName $domain -Type ns | select NameHost | Ft
#echo "============================AFSDB========================================="
#Resolve-DnsName $domain -Type AFSDB | Ft
#echo "============================CNAME========================================="
#Resolve-DnsName $domain -Type CNAME | select PrimaryServer,NameAdministrator | Ft
#echo "============================SOA========================================="
#Resolve-DnsName $domain -Type soa | Ft
#echo "============================srv========================================="
#Resolve-DnsName $domain -Type srv | Ft

#start
pause
