1. Trennung zwischen Surf- / Mail-Account und Admin-Account
Admin-Account ist schützenswert und kann evtl. in privilegierte AD-Gruppe hinzugefügt werden, die unsichere Dinge verhindert, die ein Admin normalerweise auch nicht braucht
Der Surf- / Mail-Account kann normaler User oder Admin auf dem Client sein, aber ist durch Browser und Mails gefährdet. Der Großteil der Schadsoftware komtm per Mail oder von einer Website, die man als Admin besucht. Wir wollen die wichtigen Server schützen, indem auf den also etwas mehr gefährdeten Clients nicht die gleichen User arbeiten, die die Server administrieren.

2. Patche Software und Windows auf Servern und Clients frühzeitig
Oft wird erst ein paar Tage nach der Veröffentlichung von Updates bekannt, welche Lücken die Vorgängerversion hatte. Hakcer brauchen nach Veröffentlichung und nach Bekanntgabe der Lücke oft ca. 24-48 Stunden, um die Lücke zu knacken.

3. Pentest vs. Vulscan
Der Vulscan zeit dir an, welche Lücken dein Computer hat. Der Pentest sucht oft nach ausgenutzten Lücken. Angreifer suchen oft nach dem kürzesten Weg zum Ziel. Selten ist es eine Lücke, die Probleme bereitet, sondern die Kombination aus mehreren Lücken.

4. Nutze FQDN bei RDP
Kerberos ist sehr sicher und kann aber nur genutzt werden, wenn der FQDN deines Computers genutzt wird. Bei Nutzung des reinen Servernamens oder der IP wird das unsichere NTLM genutzt

5. Wie sicher ist mein Computer? Mach den Audit-Test
5a. ATAPAuditor (HTML-Report)
#https://github.com/fbprogmbh/Audit-Test-Automation
#https://www.fb-pro.com/audit-test-automation-package-audit-tap/
Install-Module -Name PowerShellGet -Force
Install-Module -Name ATAPAuditor -Force
Import-Module ATAPHtmlReport
Import-Module ATAPAuditor
#Save-ATAPHtmlReport -ReportName "Microsoft Windows Server 2022" -force -RiskScore
Save-ATAPHtmlReport -ReportName "Microsoft Windows 11" -force -RiskScore

5b. HardeningKitty (keine GUI)
#region winver
    $OSVersion=Get-CimInstance Win32_Operatingsystem | Select-Object -expand Caption
    $OSVersion
#endregion
Import-Module HardeningKitty.psm1
#machine
Invoke-HardeningKitty -Mode Audit -EmojiSupport -report -log -FileFindingList "Hardening-Audit\HardeningKitty\lists\finding_list_cis_microsoft_windows_11_enterprise_22h2_machine.csv"
#user
Invoke-HardeningKitty -Mode Audit -EmojiSupport -report -log -FileFindingList "Hardening-Audit\HardeningKitty\lists\finding_list_cis_microsoft_windows_11_enterprise_22h2_user.csv"
#https://github.com/scipag/HardeningKitty

6. Sichere Kryptographie
https://privacy.sexy/
Auf der linken Seite "Security Improvements" anklicken
dann
Secure cryptpgraphy on IIS ...
dann unten kopieren in die Zwischanablage
und als Kryptographie.cmd speichern

7. IISCrypto
https://www.nartac.com/Products/IISCrypto

9. Sicher surfen - https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
Immer die aktuellste Version nutzen
edge://settings/help
Wer andere Browser nutzt: Autoupdate anschalten!
MS Edge mitgeben, welche Ciphers er NICHT nutzen soll
(Aufruf mit Parametern und Direktaufruf von https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html )
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --args --cipher-suite-denylist=0x009c,0x009d,0x002f,0x0035,0x000a,0xc00a,0xc009,0xc013,0xc014 https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
Auch möglich:
--ssl-version-max=tls1.2
--ssl-version-min=tls1.2
Achtung! Unterschied Chrome/Edge
Achtung: Brave oder Chrome nutzen nicht cipher-suite-denylist, sondern cipher-suite-blacklist als Parameter!
The command-line flag is --cipher-suite-blacklist, with a comma-delimited list of cipher suites in hexadecimal. 
"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe" --ssl-version-min=tls1.2 --cipher-suite-blacklist=0x009c,0x009d,0x002f,0x0035,0x000a,0xc00a,0xc009,0xc013,0xc014 https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe" --ssl-version-min=tls1.3 --cipher-suite-blacklist=0x009c,0x009d,0x002f,0x0035,0x000a,0xc00a,0xc009,0xc013,0xc014 https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
Nur Edge lässt sich per GPO/Reg konfigurieren, die anderen Chromium-Browser (Brave, Google Chrome) können nur per Start-Parameter konfiguriert werden
Edge-Browser-Hardening per Registry/GPO
https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#tlsciphersuitedenylist
So if you wanted to disable those ciphers without Forward Secrecy, you'd use
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList]
"1"="0xc013"
"2"="0xc014"
"3"="0x009c"
"4"="0x009d"
"5"="0x002f"
"6"="0x0035"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList]
"1"="0x0035"
"2"="0xc014"
"3"="0x009c"
"4"="0x009d"
"5"="0x002f"

List of cipher suites that are often considered weak or insecure and may be candidates for blocking
DES-CBC3-SHA (0x000a)
RC4-MD5 (0x0004)
RC4-SHA (0x0005)
AES128-SHA (0x002f)
AES256-SHA (0x0035)
DHE-RSA-AES128-SHA (0x0033)
DHE-RSA-AES256-SHA (0x0039)
ECDHE-RSA-DES-CBC3-SHA (0xc012)
ECDHE-RSA-AES128-SHA (0xc013)
ECDHE-RSA-AES256-SHA (0xc014)
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9C)
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9D)
https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
https://www.ibm.com/docs/en/wip-mg/5.0.0.1?topic=lists-cipher-list-best-quality-ciphers
https://en.wikipedia.org/wiki/Transport_Layer_Security
https://en.wikipedia.org/wiki/Version_history_for_TLS/SSL_support_in_web_browsers


6b. Firefox 
Link: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Mindeststandards/Archivdokumente/Migrationsleitfaden_Mindeststandard_BSI_TLS_Version_1_2.pdf?__blob=publicationFile&v=1
Link: https://helgeklein.com/blog/disable-tls-1-0-and-1-1-in-firefox-now/
Link: https://www.kim.uni-konstanz.de/en/email-and-internet/it-security-and-privacy/device-security/mozilla-firefox/optionen-fuer-sichere-verbindungen/

## Ciphersuites "Firefox" GUI:

1. Aufrufen von "about:config"
2. Suchen nach "security.ssl3."
3. Werte wie folgt auf "false" setzen

security.ssl3.deprecated.rsa_des_ede3_sha    
security.ssl3.ecdhe_ecdsa_aes_128_sha
security.ssl3.ecdhe_ecdsa_aes_256_sha    
security.ssl3.ecdhe_rsa_aes_128_sha    
security.ssl3.ecdhe_rsa_aes_256_sha    
security.ssl3.rsa_aes_128_gcm_sha256    
security.ssl3.rsa_aes_128_sha    
security.ssl3.rsa_aes_256_gcm_sha384    
security.ssl3.rsa_aes_256_sha



## TLS-Version "Firefox" GUI

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

## Verteilung

In großen Betriebsumgebungen kann die Konfigurationsdatei prefs.js für Firefox auch
mittels Automatisierungswerkzeugen zentral verteilt und für den Benutzerzugriff gesperrt werden.
> %APPDATA%\Mozilla\Firefox\Profiles\ 

Bspw. für Cipher:
user_pref("security.ssl3.deprecated.rsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.rsa_aes_128_gcm_sha256", false);
user_pref("security.ssl3.rsa_aes_128_sha", false);
user_pref("security.ssl3.rsa_aes_256_gcm_sha384", false);
user_pref("security.ssl3.rsa_aes_256_sha", false);

## Sonstige Settings

security.pki.sha1_enforcement_level = 1

> Unsichere Renegotiation verbieten (kann Probleme verursachen):
security.ssl.require_safe_negotiation = true
security.ssl.treat_unsafe_negotiation_as_broken = true


> Strenges Certifikate Pinning (HPKP) erzwingen (z.B. für Add-on Updates):
security.cert_pinning.enforcement_level = 2

> Mixed Content verbieten:
security.mixed_content.block_display_content = true
security.mixed_content.block_active_content = true 

> Warnungen bei unverschlüsselten Seitenaufrufen:
security.insecure_connection_icon.enabled = true
security.insecure_connection_icon.pbmode.enabled = true
security.insecure_connection_text.enabled = true
security.insecure_connection_text.pbmode.enabled = true

> Alle Teile der URL in der Adressleiste anzeigen (z.B. http(s)://)::
browser.urlbar.trimURLs = false

"аррӏе.com" und "apple.com" sehen zwar auf den ersten Blick gleich aus, ersteres enthält aber kyrillische Zeichen

> Punycode für internationalisierte Domainnamen, um mögliches Spoofing zu verhindern:
network.IDN_show_punycode = true

10. Dateianhänge und Makros in office

11. Nessus

12. Stigviewer

13. https://hotcakex.github.io/
