[CmdletBinding()]
param(
    [string]$Compiler = "",
    [switch]$Clean,
    [switch]$TestOnly,
    [switch]$NoStrip
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    $build = Join-Path $root "build"
    if ($Clean) {
        Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
        Remove-Item -Force (Join-Path $root "FiveMGuard.exe") -ErrorAction SilentlyContinue
        Remove-Item -Force (Join-Path $root "FiveMGuard-teste.exe") -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $build | Out-Null

    if (-not $Compiler) {
        $candidates = @(
            "C:\Users\cw_23\AppData\Local\Temp\opencode\w64devkit\w64devkit\bin\g++.exe",
            "C:\w64devkit\bin\g++.exe",
            "$env:ProgramFiles\mingw64\bin\g++.exe",
            "${env:ProgramFiles(x86)}\mingw64\bin\g++.exe"
        )
        foreach ($candidate in $candidates) {
            if (Test-Path $candidate) {
                $Compiler = $candidate
                break
            }
        }
        if (-not $Compiler) {
            $command = Get-Command g++ -ErrorAction SilentlyContinue
            if ($command) { $Compiler = $command.Source }
        }
        if (-not $Compiler) {
            throw "g++ nao encontrado. Informe -Compiler C:\caminho\g++.exe"
        }
    }

    if (Test-Path $Compiler -PathType Container) {
        $gxx = Join-Path $Compiler "g++.exe"
    } else {
        $gxx = $Compiler
    }
    if (-not (Test-Path $gxx)) { throw "g++ nao encontrado: $gxx" }
    $windres = Join-Path (Split-Path -Parent $gxx) "windres.exe"
    if (-not (Test-Path $windres)) { throw "windres.exe nao encontrado ao lado de g++" }

    $src = Join-Path $root "src"
    $res = Join-Path $root "resources"
    $sources = @(Get-ChildItem -Path $src -Filter *.cpp | Sort-Object Name |
        ForEach-Object { $_.FullName })
    if ($sources.Count -eq 0) { throw "Nenhum arquivo .cpp em $src" }

    $flags = @(
        "-std=c++17", "-O2", "-pipe", "-municode", "-static",
        "-static-libgcc", "-static-libstdc++", "-finput-charset=UTF-8",
        "-DUNICODE", "-D_UNICODE", "-D_WIN32_WINNT=0x0603", "-DWINVER=0x0603",
        "-DNOMINMAX", "-DWIN32_LEAN_AND_MEAN",
        "-I$src", "-I$res",
        "-Wl,--nxcompat", "-Wl,--dynamicbase"
    )
    if (-not $NoStrip) { $flags += "-s" }

    $libs = @(
        "-lole32", "-loleaut32", "-luuid", "-lwinhttp", "-lwintrust", "-lcrypt32",
        "-liphlpapi", "-lnetapi32", "-ladvapi32", "-lshell32", "-lws2_32",
        "-lwtsapi32", "-lversion", "-luserenv"
    )

    function Invoke-Tool([string]$exe, [string[]]$arguments) {
        Write-Host ">> $exe $($arguments -join ' ')" -ForegroundColor DarkGray
        & $exe @arguments
        if ($LASTEXITCODE -ne 0) { throw "Falha (codigo $LASTEXITCODE): $exe" }
    }

    $adminRes = Join-Path $build "app-admin-res.o"
    $testRes = Join-Path $build "app-test-res.o"
    $adminExe = Join-Path $root "FiveMGuard.exe"
    $testExe = Join-Path $root "FiveMGuard-teste.exe"

    # O windres nao lida bem com caminhos contendo espacos no -I.
    # Execute-o dentro de resources e use caminhos relativos.
    Push-Location $res
    try {
        Invoke-Tool $windres @("-O", "coff", "-i", "app.rc",
            "-o", "..\\build\\app-admin-res.o")
    } finally {
        Pop-Location
    }
    Invoke-Tool $gxx ($flags + $sources + @($adminRes, "-o", $adminExe) + $libs)

    if (-not $TestOnly) {
        Push-Location $res
        try {
            Invoke-Tool $windres @("-D", "FG_ASINVOKER", "-O", "coff", "-i", "app.rc",
                "-o", "..\\build\\app-test-res.o")
        } finally {
            Pop-Location
        }
        $testFlags = @($flags | Where-Object { $_ -ne "-s" })
        Invoke-Tool $gxx ($testFlags + $sources + @($testRes, "-o", $testExe) + $libs)
    }

    Write-Host ""
    Write-Host "Build concluido:" -ForegroundColor Green
    Write-Host "  $adminExe (requer administrador)"
    if (-not $TestOnly) {
        Write-Host "  $testExe (asInvoker, apenas para testes)"
    }
} finally {
    Pop-Location
}
