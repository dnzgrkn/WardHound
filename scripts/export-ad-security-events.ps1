<#
.SYNOPSIS
    Export real Windows Security event log entries (failed logon, Event ID 4625)
    into the JSON shape app/collectors/active_directory.py's ActiveDirectoryCollector
    expects.

.DESCRIPTION
    ActiveDirectoryCollector.normalize() requires each event pre-rendered with
    named fields (TargetUserName, TargetDomainName, TimeCreated, IpAddress, ...)
    because, per its own docstring, "named fields such as TargetUserName do not
    exist in Format-List or raw positional .Properties output" — only the XML
    rendering (.ToXml()) exposes them. This script does that XML extraction so
    the existing, reviewed collector's normalize() can run unmodified.

    Run this ON the domain controller (or wherever the Security log with real
    logon-failure events lives) — Get-WinEvent reads the local machine's log,
    not a remote one, unless you add -ComputerName and have WinRM configured.
    Requires read access to the Security log (local admin, or a delegated
    "Event Log Readers" group membership).

.PARAMETER Hours
    How far back to look for Event ID 4625 entries. Default: 24.

.PARAMETER OutFile
    Where to write the resulting JSON array. Default: ad_events.json next to
    this script.

.EXAMPLE
    .\export-ad-security-events.ps1 -Hours 24 -OutFile C:\temp\ad_events.json
#>
param(
    [int]$Hours = 24,
    [string]$OutFile = (Join-Path $PSScriptRoot "ad_events.json")
)

$startTime = (Get-Date).AddHours(-$Hours)
Write-Host "Querying Security log for Event ID 4625 since $startTime ..."

$events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $startTime } -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "No matching events found. Writing an empty array."
    "[]" | Out-File -FilePath $OutFile -Encoding utf8
    exit 0
}

$records = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        if ($d.Name) { $data[$d.Name] = $d.'#text' }
    }
    $systemTime = [datetime]$xml.Event.System.TimeCreated.SystemTime

    [PSCustomObject]@{
        EventID          = [int]$xml.Event.System.EventID
        Computer         = $xml.Event.System.Computer
        TargetUserName   = $data['TargetUserName']
        TargetDomainName = $data['TargetDomainName']
        TimeCreated      = $systemTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        IpAddress        = $data['IpAddress']
    }
}

# Force array output even for a single record — ConvertTo-Json collapses a
# one-element collection to a bare object otherwise, which the ingestion
# script would then have to special-case.
@($records) | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding utf8

Write-Host "Wrote $(@($records).Count) event(s) to $OutFile"
