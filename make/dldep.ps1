$file = "ihulib.zip"
$url = "https://github.com/intellectualheaven/ihulib/releases/download/v1.1.1/ihulib.zip"
$clnt = new-object System.Net.WebClient

[bool]$downloadFile = $False
$clnt.OpenRead($Url).Close()
$lastModified = $clnt.ResponseHeaders["Last-Modified"]

If (!(Test-Path($file))) {
    Write-Host "File $file does not exist."
    $downloadFile = $True
} Else {
    [DateTime]$remoteLastModified = $lastModified
    $localLastModified = (Get-Item $file).LastWriteTime
    $downloadFile = !($localLastModified -eq $remoteLastModified)
    If ($downloadFile) {
        Write-Host "Local and remote files are different."
    } Else {
        Write-Host "Local and remote files are same."
    }
}

If ($downloadFile) {
    Write-Host "Downloading $file from $url ..."
    $clnt.DownloadFile($url, $file)
    $fileItem = Get-Item $file
    $fileItem.LastWriteTime = $lastModified
    Write-Host "unzip $file ..."
    $prg = "$PSScriptRoot\unzip.exe"
    $arg = "-o $file"
    Start-Process -FilePath "$prg" -ArgumentList "$arg" -Wait
}
