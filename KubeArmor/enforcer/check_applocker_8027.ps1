$e = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/Packaged app-Execution" -MaxEvents 1 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 8027 }
if ($e) {
    [xml]$xml = $e.ToXml()
    $xml.OuterXml
}