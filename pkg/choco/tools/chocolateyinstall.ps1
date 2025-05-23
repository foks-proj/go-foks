$url64       = "https://github.com/foks-proj/go-foks/releases/download/v0.0.19/foks-v0.0.19-win-choco-amd64.zip"
$url         = "https://github.com/foks-proj/go-foks/releases/download/v0.0.19/foks-v0.0.19-win-choco-x86.zip"
$checksum    = "09601e18e5284d713db0f01caabf94e41804743515053f8a4d6f561840f862a0"
$checksum64  = "c8e9e35b41416f7c454b3d0e720c09dfdbe81e85bfd27f3657a1cc3b2007df5c"
$packageName = "foks"
$toolsDir    = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

Install-ChocolateyZipPackage `
  -PackageName   $packageName `
  -FileType      'zip' `
  -Url            $url `
  -Url64bit       $url64 `
  -Checksum       $checksum `
  -ChecksumType   'sha256' `
  -Checksum64     $checksum64 `
  -ChecksumType64 'sha256' `
  -UnzipLocation  $toolsDir

# Need to copy the item over since we need to know the equivalent of os.Args[0]
# inside the executable, and we lose that via the shimming process.
Copy-Item "$toolsDir\foks.exe" "$toolsDir\git-remote-foks.exe" -Force

Install-BinFile `
  -Name 'foks' `
  -Path "$toolsDir\foks.exe"

Install-BinFile `
  -Name 'git-remote-foks' `
  -Path "$toolsDir\git-remote-foks.exe"
