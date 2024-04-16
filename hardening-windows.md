1. Trennung zwischen Surf- / Mail-Account und Admin-Account
Admin-Account ist schützenswert und kann evtl. in privilegierte AD-Gruppe hinzugefügt werden, die unsichere Dinge verhindert, die ein Admin normalerweise auch nicht braucht
Der Surf- / Mail-Account kann normaler User oder Admin auf dem Client sein, aber ist durch Browser und Mails gefährdet. Der Großteil der Schadsoftware komtm per Mail oder von einer Website, die man als Admin besucht. Wir wollen die wichtigen Server schützen, indem auf den also etwas mehr gefährdeten Clients nicht die gleichen User arbeiten, die die Server administrieren.

2. Patche Software und Windows auf Servern und Clients frühzeitig
Oft wird erst ein paar Tage nach der Veröffentlichung von Updates bekannt, welche Lücken die Vorgängerversion hatte. Hakcer brauchen nach Veröffentlichung und nach Bekanntgabe der Lücke oft ca. 24-48 Stunden, um die Lücke zu knacken.

3. Pentest vs. Vulscan
Der Vulscan zeit dir an, welche Lücken dein Computer hat. Der Pentest sucht oft nach ausgenutzten Lücken. Angreifer suchen oft nach dem kürzesten Weg zum Ziel. Selten ist es eine Lücke, die Probleme bereitet, sondern die Kombination aus mehreren Lücken.

4. Nutze FQDN bei RDP
Kerberos ist sehr sicher und kann aber nur genutzt werden, wenn der FQDN deines Computers genutzt wird. Bei Nutzung des reinen Servernamens oder der IP wird das unsichere NTLM genutzt

