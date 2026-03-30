# 🖥️ Installation_PC — Installation automatique de logiciels via fichier INI

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=for-the-badge)
![Licence](https://img.shields.io/badge/Licence-MIT-green?style=for-the-badge)

Script PowerShell d'installation automatique de logiciels pour nouveaux postes Windows. La sélection des logiciels à installer se fait via un fichier de configuration `.ini` simple à éditer.

---

## Fonctionnalités

- Lecture des options d'installation depuis `parametre.ini`
- Installation automatique des logiciels activés
- Lanceur batch avec gestion des droits administrateur
- Support des logiciels nécessitant un installateur local (ex. FoxitReader)

---

## Prérequis

- Windows 10 / 11
- PowerShell 5.1 ou supérieur
- Droits administrateur local

---

## Installation

1. Copier les fichiers dans `C:\source\installation`
2. Placer les installateurs locaux dans `C:\source\installation\Logiciels\`

```bash
git clone https://github.com/titithen00b/Installation_PC.git
```

---

## Configuration

Ouvrir `parametre.ini` et mettre à `1` les logiciels à installer, `0` pour les ignorer :

```ini
[Logiciels]
Anydesk=1
Winrar=1
Office=0
Foxit=1
Firefox=1
Chrome=0
VLC=1

[Paramètre]
basic=1
ren=1

[Windows update]
wsus=0

[Domaine]
Domaine=0
```

> **Note :** Certains logiciels (ex. FoxitReader) ne sont pas disponibles en téléchargement automatique. L'installateur doit être placé manuellement dans `C:\source\installation\Logiciels\`.

---

## Utilisation

Double-cliquer sur `1. Installation PC.bat` — le script s'exécute en mode administrateur et traite le fichier `parametre.ini`.

```batch
1. Installation PC.bat
```

---

## Fichiers du projet

| Fichier | Description |
|---------|-------------|
| `1. Installation PC.bat` | Lanceur batch avec élévation des droits |
| `1.1 Installation PC.ps1` | Script PowerShell principal |
| `parametre.ini` | Fichier de configuration des logiciels à installer |

---

## Licence

MIT © Titithen00b
