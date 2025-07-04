# NIDSense
```
+------------------------+            +-----------------------------+             +----------------------------------------+
|   🛡️ Serveur Rocky     |            |   🔎 Machine Ubuntu        |             |      🤖 IA Windows                     |
|      (Vulnérable)      |            | (Traitement des données)    |             |    (Mistral + Ollama)                  |
+------------------------+            +-----------------------------+             +----------------------------------------+
| Services exposés :     |            | Services :                  |             | Services :                             |
|  - Apache (port 80)    |            |  - rsyslog (UDP 514)        |             |  - Ollama (Mistral)                    |
|  - MariaDB (3306)      |            |  - Zeek NIDS                |             |  - GPU Accélération                    |
|  - SSH (22)            |            |                             |             |                                        |
|  - Auditd              |            |                             |             |                                        |
|                        |            | Flux entrant :              |             |                                        |
| Génère logs :          | -------->  |  - apache-access.log        |             |                                        |
|  - Apache logs         |  Rsyslog   |  - mariadb.log              |             |                                        |
|  - MariaDB logs        |  (UDP)     |  - auditd.log               |             |                                        |
|  - AuditD logs         |            |  - zeek logs                |             |                                        |
|                        |            |                             |             |                                        |
|                        |            | Script (parsing des logs et |             |                                        |
|                        |            | communication avec l'IA ):  |   PROMPT    | Analyse IA (à partir du prompt reçu) : |
|                        |            |    - parser_and_twia.py     |  -------->  |   - Réception des logs parsés          |
|                        |            |                             |             |   - Vérifie comportement               |
|                        |            |                             |   REPONSE   |   - Détecte attaques                   |
|                        |            |                             |  <--------- |   - Génère alertes                     |
+------------------------+            +-----------------------------+             +----------------------------------------+
```

                                                VPN Mesh sécurisé (Tailscale)
                                                🔒 Chiffrement point-à-point
