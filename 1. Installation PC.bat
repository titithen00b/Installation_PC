@echo off
:-------------------------------------
REM  -->  Verification des permissions
    >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

    REM --> Erreur vous ne possedez pas les droits admin
    if '%errorlevel%' NEQ '0' (
    echo Verification des privileges administrateur
    goto UACPrompt
    ) else ( goto gotAdmin )

    :UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "%~s0", "%params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit

    :gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------


powershell "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine"
start powershell -file "1.1 Installation PC.ps1"
