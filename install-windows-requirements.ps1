$ErrorActionPreference="Stop"

if ( -not (Test-Path -Path C:\Python27 -PathType Container) ) {
    Write-Host -NoNewline Python 2.7 is not installed in its default location. Press any key to exit ...
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
    exit 1
}

if ( -not (Test-Path -Path C:\Python27\Scripts\pip.exe) ) {
    (new-object System.Net.WebClient).DownloadFile('https://bootstrap.pypa.io/get-pip.py', "$env:TEMP\get-pip.py")

    C:\Python27\python "$env:TEMP\get-pip.py"
    if ($LastExitCode -ne 0) {
        del "$env:TEMP\get-pip.py"
        Write-Host -NoNewline Failed to install Python pip. Press any key to exit ...
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
        exit 1
    }
    
    del "$env:TEMP\get-pip.py"
}

C:\Python27\Scripts\pip install protobuf pylibscrypt
if ($LastExitCode -ne 0) {
    Write-Host -NoNewline Failed to install required Python libraries. Press any key to exit ...
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
    exit 1
}

Write-Host -NoNewline `nRequirements installed. Press any key to exit ...
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
