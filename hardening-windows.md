

https://stackedit.io/app#

## 1. Mehrere Konten für IT-Administratoren: Trennung zwischen Surf- / Mail-Account und Admin-Account
- Aufwand lohnt sich bzgl. Sicherheit (Risikoreduzierung beim Internetzugriff oder öffnen eines gefährlichen Dateianhangs)
- Bessere Übersicht und Nachvollziehbarkeit bei Auffälligkeiten
- Admin-Account kann dann in gut geschützte AD-Gruppen hinzugefügt werden, ohne eingeschränkt zu sein bei Einwahl, Mail, Internetzugriff
- Großteil der Schadsoftware kommt per Mail oder von einer Website, die man als Admin besucht
- Mehrere Konten sollten auch VERSCHIEDENE Kennwörter haben
- https://www.security-insider.de/e-mails-sind-wichtigstes-einfallstor-fuer-cyberangriffe-a-794599/

## ------------------------------------------------------------------------------

## **2. Patche Software und Windows auf Servern und Clients frühzeitig**
- Oft wird erst ein paar Tage nach der Veröffentlichung von Updates bekannt, welche Lücken die Vorgängerversion hatte. Hacker brauchen nach Veröffentlichung und nach Bekanntgabe der Lücke oft ca. 24-48 Stunden, um die Lücke zu knacken.
- Tool1: WingetUI: https://github.com/marticliment/WingetUI/releases/ und https://github.com/marticliment/WingetUI/
- Tool2: WindowsUpdateManager: https://github.com/DavidXanatos/wumgr/releases/ und https://github.com/DavidXanatos/wumgr
- News zu Patches https://www.ghacks.net/category/windows/ und https://www.bleepingcomputer.com/news/microsoft/ und https://isc.sans.edu/diary/ zur Einschätzung.
- Bei https://www.ghacks.net/category/windows/  kann die KB-Nummer ermittelt werden (steht bei Serverversion hinten dran).
- Seite, um einschätzen zu können, ob aktuelle Patches Fehler verursachen: https://www.askwoody.com bzw. https://www.askwoody.com/patch-list-master/
- Es gibt auch eine Google-Gruppe, wo man schnell erfährt, falls es Probleme mit den Updates gibt: https://groups.google.com/g/patchmanagement (nur mit Google-Konto)

## ------------------------------------------------------------------------------

## **3. Pentest vs. Vulscan**
- Vulscan zeigt an, welche Lücken dein Computer hat, Pentest sucht eher nach üblicherweise ausgenutzten Lücken
- Angreifer suchen oft nach dem kürzesten Weg zum Ziel. Selten ist es eine einzige Lücke, die Probleme bereitet, sondern die Kombination aus mehreren leicht zu knackenden Lücken.
- https://www.pingcastle.com/documentation/healthcheck/
- https://www.semperis.com/de/purple-knight/security-indicators/

## ------------------------------------------------------------------------------

## **4. Nutzung von FQDN (Fully Qualified Domain Name) bei RDP, Skripten usw.**
- Ziel: Soe viel wie möglich Kerberos, denn Kerberos ist im Gegensatz zu NTLM sehr sicher 
- Kerberos für RDP kann nur genutzt werden, wenn der FQDN deines Computers genutzt wird. Bei Nutzung des reinen Servernamens oder der IP wird üblicherweise das unsichere NTLM genutzt
- Beispiel: svaSERVER1.ha10.ohoh.local

## ------------------------------------------------------------------------------



## **5. Wie sicher ist mein Computer? Mach den Audit-Test**

**5a. ATAPAuditor (HTML-Report)**

https://github.com/fbprogmbh/Audit-Test-Automation

https://www.fb-pro.com/audit-test-automation-package-audit-tap/

Install-Module -Name PowerShellGet -Force

Install-Module -Name ATAPAuditor -Force

Import-Module ATAPHtmlReport

Import-Module ATAPAuditor

Save-ATAPHtmlReport -ReportName "Microsoft Windows Server 2022" -force -RiskScore

Save-ATAPHtmlReport -ReportName "Microsoft Windows 11" -force -RiskScore

**5b. HardeningKitty (keine GUI)**

https://github.com/scipag/HardeningKitty

#region winver

    $OSVersion=Get-CimInstance Win32_Operatingsystem | Select-Object -expand Caption

    $OSVersion

#endregion

Import-Module HardeningKitty.psm1

#machine

Invoke-HardeningKitty -Mode Audit -EmojiSupport -report -log -FileFindingList "Hardening-
Audit\HardeningKitty\lists\finding_list_cis_microsoft_windows_11_enterprise_22h2_machine.csv"

#user

Invoke-HardeningKitty -Mode Audit -EmojiSupport -report -log -FileFindingList "Hardening-
Audit\HardeningKitty\lists\finding_list_cis_microsoft_windows_11_enterprise_22h2_user.csv"

## ------------------------------------------------------------------------------

## ** 6. Sichere Kryptographie nutzen !
**6a Website https://privacy.sexy/**
Auf der linken Seite "Security Improvements" anklicken
dann
Secure cryptpgraphy on IIS ...
dann unten kopieren in die Zwischanablage
und als Kryptographie.cmd speichern

**6b. IISCrypto**
https://www.nartac.com/Products/IISCrypto

## ------------------------------------------------------------------------------


## ** 7. Nessus, um sich einen Überblick über einen Computer zu verschaffen
**7a. Nessus-Scan Tenable intern**
URL https://tenable/ aufrufen
rechts oben
![image](https://github.com/endoleg/endoleg-hardening/assets/49591978/9d5c7a6a-3cb9-4ecc-81d5-a54b5db4bce9)
Host Assets auswählen
IP-Adresse des gewünschten Endgerätes eingeben

**7b. Nessus-Tenable Audits**
https://www.tenable.com/audits
https://www.tenable.com/audits/CIS_Microsoft_Windows_Server_2022_Benchmark_v2.0.0_L1_DC


## ------------------------------------------------------------------------------

## ** 8. Stigviewer
https://www.stigviewer.com/stigs
- kostenlos
- ermöglicht es, die Sicherheitsvorgaben (Security Technical Implementation Guides, kurz STIGs) des US-Verteidigungsministeriums für verschiedene Betriebssysteme und Anwendungen anzuzeigen und zu verwalten.
- STIGs sind detaillierte Richtlinien, die sicherstellen sollen, dass Systeme sicher konfiguriert sind und Sicherheitsstandards einhalten. 

## ------------------------------------------------------------------------------

## ** 9. Wissen aufbauen 

https://hotcakex.github.io/ durchforsten

Tools
https://www.oo-software.com/de/shutup10
https://www.w10privacy.de/deutsch-start/anleitung/

SiSyPHuS Win10 - Studie zu Systemaufbau, Protokollierung, Härtung und Sicherheitsfunktionen in Windows 10: 
https://www.bsi.bund.de/DE/Service-Navi/Publikationen/Studien/SiSyPHuS_Win10/SiSyPHuS_node.html

CIS Benchmark PDFs: 
https://downloads.cisecurity.org/#/

Group Policy Objects - Vorlagen: 
https://public.cyber.mil/stigs/gpo/

admx.help
https://admx.help/

## ------------------------------------------------------------------------------

## ** 10. Studie: "Evidence-based cybersecurity policy? A meta-review of security control effectiveness"

https://www.tandfonline.com/doi/full/10.1080/23738871.2024.2335461

"Wir fanden kaum Belege für die Wirksamkeit von Sicherheitslösungen von der Stange, wie etwa spezielle Firewalls oder Antivirenprodukte. Stattdessen legen die Ergebnisse nahe, dass die wirksamsten Sicherheitsmaßnahmen die Systemkonfiguration und -wartung betreffen. Vor allem die Angriffsfläche einer Organisation ist der stärkste Prädiktor für Cybervorfälle. Die Angriffsfläche kann durch eine Reihe von Härtungsmaßnahmen verringert werden. Die Häufigkeit von Patches war der zweitstärkste Prädiktor für Cyber-Vorfälle."


## ------------------------------------------------------------------------------

## ** 11. LAPS (Local Administrator Password Solution)
LAPS ist eine, von Microsoft entwickelte Lösung, Passwörter automatisiert und zyklisch zu verwalten. In erster Linie ergibt das für die lokalen Administratorkonten Sinn.

[https://www.scip.ch/?labs.20230518](https://www.scip.ch/?labs.20230518)

[https://techcommunity.microsoft.com/t5/windows-it-pro-blog/skilling-snack-windows-laps/ba-p/3805257](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/skilling-snack-windows-laps/ba-p/3805257)

[https://learn.microsoft.com/de-de/windows-server/identity/laps/laps-overview](https://learn.microsoft.com/de-de/windows-server/identity/laps/laps-overview)

[https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747)

[https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)

## ------------------------------------------------------------------------------

## ** 12. RDP-Sitzungen absichern mit Remote Credential Guard
[https://www.windowspro.de/wolfgang-sommergut/rdp-sitzungen-absichern-remote-credential-guard](https://www.windowspro.de/wolfgang-sommergut/rdp-sitzungen-absichern-remote-credential-guard)

[https://www.der-windows-papst.de/2021/06/06/rdp-verbindungen-mit-windows-defender-remote-credential-guard-absichern/](https://www.der-windows-papst.de/2021/06/06/rdp-verbindungen-mit-windows-defender-remote-credential-guard-absichern/)

[https://www.escde.net/blog/remote-verbindungen-mit-dem-windows-defender-remote-credential-guard-wdrcg-sicher-gestalten](https://www.escde.net/blog/remote-verbindungen-mit-dem-windows-defender-remote-credential-guard-wdrcg-sicher-gestalten)

[https://4sysops.com/archives/secure-rdp-connections-using-remote-credential-guard/](https://4sysops.com/archives/secure-rdp-connections-using-remote-credential-guard/)

## ------------------------------------------------------------------------------

## ** 13. Sicher surfen mit Edge oder Firefox** 
**Prüfung mit SSLLabs**
https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html

**Immer die aktuellste Browser-Version nutzen**
edge://settings/help
Wer andere Browser nutzt: Autoupdate anschalten!

**Stelle deinen Browser sicher ein**
https://hotcakex.github.io/#edge-browser-configurations

**13a. MS Edge mitgeben, welche Ciphers er NICHT nutzen soll**
Aufruf mit Parametern und Direktaufruf von https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html :
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --args --cipher-suite-denylist=0x009c,0x009d,0x002f,0x0035,0x000a,0xc00a,0xc009,0xc013,0xc014 https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html

Auch mögliche Parameter:
--ssl-version-max=tls1.2
--ssl-version-min=tls1.2
https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#tlsciphersuitedenylist

**13b. Firefox** 
Link: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Mindeststandards/Archivdokumente/Migrationsleitfaden_Mindeststandard_BSI_TLS_Version_1_2.pdf?__blob=publicationFile&v=1
Link: https://helgeklein.com/blog/disable-tls-1-0-and-1-1-in-firefox-now/
Link: https://www.kim.uni-konstanz.de/en/email-and-internet/it-security-and-privacy/device-security/mozilla-firefox/optionen-fuer-sichere-verbindungen/

**TLS-Version "Firefox" GUI**
1. Aufrufen von about:config
2. Suchen nach "security.tls.version.min"
3. Wert "3" setzen und bestätigen 
4. Suchen nach "security.tls.version.max"
5. Wert "4" setzen und bestätigen 

0 = SSL 3.0
1 = TLS 1.0
2 = TLS 1.1
3 = TLS 1.2
4 = TLS 1.3

 
## ------------------------------------------------------------------------------

**14 RSS Feeds

CERT.at-Tagesberichte: https://cert.at/de/services/feeds/

Kann auch in Outlook genutzt werden

## ------------------------------------------------------------------------------

**15 Event Viewer: Custom Views

https://devblogs.microsoft.com/scripting/use-custom-views-from-windows-event-viewer-in-powershell/

## ------------------------------------------------------------------------------

**16 Analyse (Incident response - gathering data)

https://github.com/nov3mb3r/trident/blob/main/trident.ps1
https://github.com/securycore/Get-Baseline/blob/master/Get-Baseline.ps1
https://github.com/A-mIn3/WINspect/blob/master/WINspect.ps1
https://github.com/gladiatx0r/Powerless/blob/master/Powerless.bat

## ------------------------------------------------------------------------------


erstellt mit Markdown Editor
https://stackedit.io/app#
