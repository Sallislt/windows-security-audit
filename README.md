# Windows Security Audit (PowerShell)

🇫🇷 Audit de sécurité **en lecture seule** d’un poste Windows 10/11, inspiré des recommandations
CIS et ANSSI. Le script vérifie les points de durcissement courants et produit un rapport HTML
avec une recommandation pour chaque écart. Il ne modifie rien sur la machine.

🇬🇧 *Read-only security baseline audit for Windows 10/11 workstations, with a console summary and an HTML report. Nothing is changed on the machine.*

## Points contrôlés

| Catégorie | Contrôle |
|---|---|
| Système | Version de Windows, temps depuis le dernier redémarrage |
| Mises à jour | Date de la dernière mise à jour installée (alerte au-delà de 45 jours) |
| Pare-feu | Profils Domaine / Privé / Public activés |
| Antivirus | Protection en temps réel Microsoft Defender, âge des signatures |
| Comptes | Compte Invité, Administrateur intégré, nombre d’administrateurs locaux |
| Durcissement | UAC, SMBv1, exécution automatique (AutoRun) |
| Accès distant | Bureau à distance (RDP) et authentification NLA |
| Chiffrement | BitLocker sur le disque système (droits administrateur requis) |

Statuts : `PASS`, `WARN`, `FAIL`, `INFO`, `SKIPPED` (contrôle impossible sans droits administrateur).

## Utilisation

```powershell
# Session utilisateur : audit partiel
.\Invoke-SecurityAudit.ps1

# Session administrateur : audit complet, rapport dans un dossier choisi
.\Invoke-SecurityAudit.ps1 -ReportPath C:\Audit\pc01.html
```

Exemple de résultat sur mon poste (session utilisateur) :

```
Summary - INFO: 1 | PASS: 13 | WARN: 1 | SKIPPED: 1
Hardening     AutoRun on removable media WARN    NoDriveTypeAutoRun = not set
Encryption    BitLocker                  SKIPPED Requires administrator rights
```

Si l’exécution des scripts est bloquée : `powershell -ExecutionPolicy Bypass -File .\Invoke-SecurityAudit.ps1`
(uniquement pour cette exécution, la stratégie du poste n’est pas modifiée).

## Pistes d’amélioration

- politique de mots de passe et de verrouillage (`secedit`) ;
- journalisation (taille des journaux, audit des connexions) ;
- export CSV pour comparer plusieurs postes d’un parc.

---

Développé avec l’aide d’un assistant IA, dans le cadre de ma reconversion vers l’IT. · Licence MIT
