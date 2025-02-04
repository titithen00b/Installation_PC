$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# Vérification des priviléges administrateur
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    # Redémarrer le script avec les priviléges administrateur
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    exit
}


# Emplacement du script et du fichier ini 
$emplacement = $PSScriptRoot


# Chemin du fichier parametre.ini
$fichierparametre = "$emplacement\parametre.ini"


# Vérification de l'existence du fichier parametre.ini
if (-not (Test-Path $fichierparametre)) {
    Write-Host "Le fichier parametre.ini est introuvable."
    Pause
    Exit
}


$nom_domaine = (Get-WmiObject -Class Win32_ComputerSystem).Domain

function imprimantes {
    # Liste des imprimantes à supprimer
    $printersToRemove = @("OneNote (Desktop)", "OneNote for Windows 10")

    Write-Host "Suppression des imprimantes"

    foreach ($printer in $printersToRemove) {
        # Vérifiez si l'imprimante existe
        $existingPrinter = Get-Printer -Name $printer -ErrorAction SilentlyContinue

        if ($existingPrinter) {
            # Si l'imprimante existe, la supprimer
            Remove-Printer -Name $printer
            Write-Host "Imprimante '$printer' supprimée."
        } else {
            # Sinon, affichez un message d'information
            Write-Host "Imprimante '$printer' non trouvée."
        }
    }

}

function demande_supression {
    $titre    = 'Supression'
    $question = 'Supression du dossier installation'
    $choix  = '&Oui','&Non'

    $decision = $Host.UI.PromptForChoice($titre, $question, $choix, 0)

    switch ($decision)
    {
        0 {write-host 'Suppression du dossier installation'
            suppression
            Start-Process c:\del.bat
        }
        1 {'Le dossier installation ne sera pas supprimer'}
        Default {}
    }
}

function demande_vpn {
    $titre    = 'Ajout VPN'
    $question = "Faut-il ajouter les profils VPN ?"
    $choix  = '&Oui','&Non'

    $decision = $Host.UI.PromptForChoice($titre, $question, $choix, 1)

    switch ($decision)
    {
        0 {write-host "Ajout des profils VPN en cours..."
            vpn
        }
        1 {"Les profils VPN ne seront pas ajouté."}
        Default {}
    }
}

function demande_confirmation {
    $titre    = ' '
    $question = 'Faut-il se connecter à un VPN ?'
    $choix  = '&Oui','&Non'

    $decision = $Host.UI.PromptForChoice($titre, $question, $choix, 1)

    switch ($decision)
    {
        0 {write-host "Ajout des profils VPN en cours..."
            vpn
            Write-Host "Merci d'appuyer sur une touche lorsque le VPN est lance"
            Pause
        }
        1 {"Les profils VPN ne seront pas ajouté."}
        Default {}
    }
}

function ajout_domaine {  
    demande_confirmation
    Write-Host "Installer Domaine..."
    $CurrentName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name
    $Serial = (Get-WmiObject -class win32_bios).SerialNumber
    if ("$CurrentName" -eq "$Serial" ){
        [string][ValidateNotNullOrEmpty()] $pw = $pw_dom
        $userPassword = ConvertTo-SecureString -String $pw -AsPlainText -Force
        $usr = $userdomain_use
        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$usr", $userPassword
        Add-Computer -DomainName $dom_use -Credential $creds -Restart -force
        exit 0
        }
    else{
        [string][ValidateNotNullOrEmpty()] $pw = $pw_dom
        $userPassword = ConvertTo-SecureString -String $pw -AsPlainText -Force
        $usr = $userdomain_use
        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$usr", $userPassword
        Add-Computer -DomainName $dom_use -NewName $Serial -Credential $creds -Restart -force
        exit 0
    }
}



function suppression {

    $suppr_template = @"

@echo off

timeout 5
cd "PLACEHOLDER_EMPLACEMENT"
cd ..
RD /s /q "Installation"
del c:\del.bat

"@

$suppr = $suppr_template -replace "PLACEHOLDER_EMPLACEMENT", $emplacement

# Chemin du fichier où le code sera ecrit
$filePath2 = "c:\del.bat"

# Ecrire le code dans le fichier
$utf8 = New-Object System.Text.UTF8Encoding($False)  # $False pour UTF-8 sans BOM
[System.IO.File]::WriteAllText($filePath2, $suppr, $utf8)
}

function Get-IniContent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$Path
    )
    
    if (-not (Test-Path $Path)) {
        throw "Le fichier '$Path' n'existe pas."
    }
    
    $iniContent = @{}
    $currentSection = ""
    
    Get-Content -Path $Path | ForEach-Object {
        $line = $_.Trim()
        
        if ($line -match '^\[.+\]$') {
            $currentSection = $line -replace '\[|\]'
            $iniContent[$currentSection] = @{}
        }
        elseif ($line -match '^.+=') {
            if (-not $currentSection) {
                throw "Erreur de syntaxe dans le fichier INI. Les clés doivent être définies à l'intérieur d'une section."
            }
            
            $keyValue = $line -split '=', 2
            $key = $keyValue[0].Trim()
            $value = $keyValue[1].Trim()
            
            $iniContent[$currentSection][$key] = $value
        }
    }
    
    return $iniContent
}


function vpn {

    
    # Définir le chemin du dossier contenant les fichiers .ovpn
    $ovpnFolderPath = "$emplacement\VPN"

    # Chemin vers l'exécutable OpenVPN Connect
    # Chemin vers le dossier contenant OpenVPN Connect
    $openvpnConnectPath = "C:\Program Files\OpenVPN Connect"

    # Récupérer le nom du fichier OpenVPNConnect.exe
    $openvpnConnect = Get-ChildItem -Path "$openvpnConnectPath" -Name "OpenVPNConnect"

    # Vérifier si le fichier existe
    if ($null -ne $openvpnConnect) {
        $openvpnConnectFullPath = Join-Path -Path $openvpnConnectPath -ChildPath $openvpnConnect
    } else {
        Write-Error "OpenVPNConnect.exe n'a pas été trouvé dans le dossier spécifié : $openvpnConnectPath"
        exit 1
    }

    # Vérifier si le dossier existe
    if (-Not (Test-Path $ovpnFolderPath)) {
        Write-Error "Le dossier spécifié n'existe pas : $ovpnFolderPath"
        }

    # Récupérer tous les fichiers .ovpn dans le dossier
    $ovpnFiles = Get-ChildItem -Path $ovpnFolderPath -Filter *.ovpn

    foreach ($file in $ovpnFiles) {
        # Extraire le nom de base du fichier sans l'extension
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        
        # Déterminer le nom affiché dans OpenVPN Connect
        $displayName = "[$baseName]"

        # Construire la commande pour importer le profil
        $arguments = "--import-profile=`"$($file.FullName)`" --name=`"$displayName`""

        # Exécuter la commande
        Start-Process -FilePath "$openvpnConnectFullPath" -ArgumentList $arguments -Wait
    }

    Start-Sleep -Seconds 3
    Start-Process "$openvpnConnect" -Args "--quit"
}

$iniPath = "$fichierparametre"
$iniContent = Get-IniContent -Path $iniPath

# Installer les logiciels en fonction des valeurs des clés
$installation_effectuee = $false

# On se met dans le bon repertoire
Set-Location $emplacement

# Parcours de toutes les sections (utiliser juste pour les variables en rapport avec le domaine)
foreach ($section in $iniContent.Keys) {
    # Récupération des valeurs de la section
    $sectionValues = $iniContent[$section]
    
    # Traitement des valeurs de la section
    foreach ($key in $sectionValues.Keys) {
        $value = $sectionValues[$key]
        
        # Appel au script d'installation automatique avec les valeurs correspondantes
        switch ($key) {
            "dom" {
                $dom_use = $value
            }
            "userdom" {
                $userdomain_use = $value
            }
            "pw" {
                $pw_dom = $value
            }    
            default {
                # Clé inconnue, ne rien faire ou afficher un avertissement selon vos besoins
            }
        }
    }
    
    Write-Host
}

function get_lastVLC {
    # URL de base du dépôt VLC
    $baseUrl = "https://mirrors.ircam.fr/pub/videolan/vlc/"

    # Télécharger la page pour obtenir la liste des versions
    $response = Invoke-WebRequest -Uri $baseUrl

    # Extraire tous les sous-dossiers (ceux qui se terminent par '/')
    $folders = $response.Links | Where-Object { $_.href -match "^.*/$" } | Sort-Object href -Descending

    # Parcourir chaque sous-dossier pour chercher dans 'win64'
    foreach ($folder in $folders) {
        $folderUrl = $baseUrl + $folder.href + "win64/"
        Write-Host "Vérification du dossier : $folderUrl"

        # Télécharger la page du sous-dossier 'win64'
        try {
            $subResponse = Invoke-WebRequest -Uri $folderUrl
        } catch {
            Write-Host "Erreur lors de l'accès au dossier $folderUrl"
            continue
        }

        # Chercher les fichiers MSI dans le sous-dossier 'win64'
        $msiLink = ($subResponse.Links | Where-Object { $_.href -like "*.msi" }).href

        # Si un fichier MSI est trouvé
        if ($msiLink) {
            $msiUrl = $folderUrl + $msiLink
            Write-Host "Fichier MSI trouvé : $msiUrl"

            # Définir le chemin de destination pour télécharger le fichier MSI
            $destinationPath = "$emplacement\vlc.msi"

            # Télécharger le fichier MSI
            Invoke-WebRequest -Uri $msiUrl -OutFile $destinationPath

            Write-Host "VLC installé avec succès."
            break
        }
    }

    # Si aucun fichier MSI n'a été trouvé
    if (-not $msiLink) {
        Write-Host "Aucun fichier MSI n'a été trouvé dans les dossiers parcourus."
    }
}

# Installer les logiciels en fonction des valeurs des clés
$installation_effectuee = $false

# Parcours de toutes les sections

foreach ($section in $iniContent.Keys) {
    Write-Host "Section: $section"
    
    # Récupération des valeurs de la section
    $sectionValues = $iniContent[$section]
    
    # Traitement des valeurs de la section
    foreach ($key in $sectionValues.Keys) {
        $value = $sectionValues[$key]
        
        # Appel au script d'installation automatique avec les valeurs correspondantes
        switch ($key) {
            "wsus" {
                if ($value -eq "1") {
                    if ($nom_domaine -eq "WORKGROUP") {
                        Write-Host "Désactivation Windows Update..."
                        net stop wuauserv
                        $installation_effectuee = $true
                    }
                    else {
                        Write-Output "Windows Update ne s'arretera pas car le poste est deja dans le domaine $nom_domaine"
                    }
                }
            }
            "Winrar" {
                if ($value -eq "1") {
                    Write-Host "Installer Winrar..."
                    Invoke-WebRequest "https://www.rarlab.com/rar/winrar-x64-621fr.exe" -OutFile winrar.exe
                    Start-Process winrar.exe -Args "/S" -Verb RunAs -Wait
                    Remove-Item winrar.exe
                    $installation_effectuee = $true
                }
            }
            "ren" {
                if ($value -eq "1") {
                    $CurrentName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name
                    $Serial = (Get-WmiObject -class win32_bios).SerialNumber
                    if ("$CurrentName" -eq "$Serial" ){
                        Write-Host "RAS"
                    }
                    else {
                        Rename-Computer -NewName $Serial -Force
                    }
                    $installation_effectuee = $true
                }
            }
            "basic" {
                if ($value -eq "1") {
                    Write-Host "Mode basique"
                    Write-Host ""
                    Write-Host "Verouillage numerique au demarrage en cours d'activation"
                    reg add "hkcu\Control panel\keyboard" /v InitialKeyboardIndicators /t reg_sz /d 2 /f
                    reg add "hku\.DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t reg_sz /d 2 /f
                    
                    Write-Host ""
                    Write-Host "Parametrage de l'ecran de veille"
                    powercfg -change -monitor-timeout-dc 15
                    powercfg -change -monitor-timeout-ac 60
                    Write-Host "Paramétrage OK"
                    Write-Host ""
                    Write-Host "Parametrage de la veille"
                    powercfg -change -standby-timeout-dc 30
                    powercfg -change -standby-timeout-ac 0
                    Write-Host "Paramétrage OK"
                    Write-Host "Parametrage de la veille prolongée"
                    powercfg -h off
                    Write-Host Paramétrage OK
                    Write-Host ""
                    imprimantes
                    timeout 5 /nobreak 
                        
                    $installation_effectuee = $true
                    }
                }
            "Anydesk" {
                if ($value -eq "1") {
                    Write-Host "Installer Anydesk..."
                    Invoke-WebRequest "https://download.anydesk.com/AnyDesk.exe" -OutFile anydesk.exe
                    Start-Process anydesk.exe -Args "--install `"C:\Program Files (x86)\AnyDesk`" --start-with-win --silent --create-shortcuts --create-desktop-icon" -Verb RunAs -Wait
                    Remove-Item anydesk.exe
                    Write-Host Installation de AnyDesk terminée !
                    $installation_effectuee = $true
                }
            }
            "Office" {
                if ($value -eq "1") {
                    Write-Host "Microsoft 365..."
                    Start-Process $emplacement\Logiciels\OfficeSetup.exe -Verb RunAs -Wait
                    $installation_effectuee = $true
                }
            }
            "Foxit" {
                if ($value -eq "1") {
                    Write-Host "Installer Foxit Reader..."
                    Start-Process $emplacement\Logiciels\foxit.exe -Args "/SP /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Verb RunAs -Wait
                    $installation_effectuee = $true
                }
            }
            "Firefox" {
                if ($value -eq "1") {
                    Write-Host "Installer Firefox..."
                    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=fr" -OutFile FF.exe -UserAgent "NativeHost"
                    Start-Process FF.exe -Args "-ms" -Verb RunAs -Wait
                    Remove-Item FF.exe
                    $installation_effectuee = $true
                }
            }
            "Chrome" {
                if ($value -eq "1") {
                    Write-Host "Installer Chrome..."
                    $Path = $env:TEMP
                    $Installer = "chrome_installer.exe"
                    Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer
                    Start-Process -FilePath $Path\$Installer -Args "/install" -Verb RunAs -Wait
                    Remove-Item $Path\$Installer
                    $installation_effectuee = $true
                }
            }
            "HPSupportAssistant" {
                if ($value -eq "1") {
                    Write-Host "Installer HPSupportAssistant..."
                    Invoke-WebRequest -OutFile HP.exe "https://ftp.hp.com/pub/softpaq/sp146001-146500/sp146042.exe"
                    Start-Process hp.exe -Args "/S" -Verb RunAs -Wait
                    Remove-Item hp.exe
                    $installation_effectuee = $true
                }
            }
            "VLC" {
                if ($value -eq "1") {
                    Write-Host "Installer VLC..."
                    get_lastVLC{}
                    Start-Process "msiexec.exe" -ArgumentList "/i `"$destinationPath`" /quiet /norestart" -Wait
                    Remove-Item vlc.msi
                    $installation_effectuee = $true
                }
            }
            "FortiClientVPN" {
                if ($value -eq "1") {
                    Write-Host "Installer Forti Client VPN..."
                    Start-Process $emplacement\Logiciels\FortiClientVPN.exe -Args " /quiet /norestart" -Verb RunAs -Wait
                    $installation_effectuee = $true
                }
            }
            "Sophos" {
                if ($value -eq "1") {
                    Write-Host "Installer Sophos..."
                    Start-Process $emplacement\Logiciels\SophosSetup_PC.exe -Verb RunAs -Wait
                    $installation_effectuee = $true
                }
            }
            "OpenVPN" {
                if ($value -eq "1") {
                    Write-Host "Installer OpenVPN..."
                    Invoke-WebRequest https://openvpn.net/downloads/openvpn-connect-v3-windows.msi -OutFile open.msi -UserAgent "NativeHost"
                    Start-Process msiexec.exe -Verb RunAs -Wait -Args "/I open.msi /qn"
                    Remove-Item open.msi
                    demande_vpn
                    $installation_effectuee = $true
                }
            }
            "Domaine" {
                if ($value -eq "1") {
                    if ($nom_domaine -eq "WORKGROUP") {
                        ajout_domaine
                        $installation_effectuee = $true
                    }
                else {
                        Write-Output "Le PC est deja dans le domaine $nom_domaine"
                    }
                }
            }

            "VPN" {
                if ($value -eq "1") {
                    Write-Host "Ajout des profiles VPN"
                    vpn
                    $installation_effectuee = $true
                }
            }   
                        
            default {
                # Clé inconnue, ne rien faire ou afficher un avertissement selon vos besoins
            }
        }
    }
    
    Write-Host
}
# Vérifier si une installation a été effectuée
if ($installation_effectuee) {
    Clear-Host
    Write-Host "Les installations ont été effectuées avec succés."
    demande_supression
    
} else {
    Write-Host "Aucune installation n'a été effectuée."
}
# Pause à la fin du script
Timeout /NoBreak 101.1 Installation PC.ps11.1 Installation PC.ps1
