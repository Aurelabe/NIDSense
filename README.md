# NIDSense

+------------------------+            +-----------------------------+            +-------------------------------+
|   🛡️ Serveur Rocky     |            |   🔎 Machine Ubuntu        |            |      🤖 IA Windows            |
|      (Vulnérable)      |            | (Traitement des données)    |            |    (Mistral + Ollama)         |
+------------------------+            +-----------------------------+            +-------------------------------+
| Services exposés :     |            | Services :                  |            | Services :                    |
|  - Apache (port 80)    |            |  - rsyslog (UDP 514)        |            |  - Ollama (Mistral)           |
|  - MariaDB (3306)      |            |  - Zeek NIDS                |            |  - GPU Accélération           |
|  - SSH (22)            |            |                             |            |                               |
|  - Auditd              |            |                             |            |                               |
|                        |            | Flux entrant :              |            |                               |
| Génère logs :          | -------->  |  - apache-access.log        |            | Analyse IA :                  |
|  - Apache logs         |  Rsyslog   |  - mariadb.log              |   JSON     |  - Réception des logs parsés  |
|  - MariaDB logs        |  (UDP)     |  - auditd.log               |   --->     |  - Vérifie comportement       |
|  - AuditD logs         |            |  - zeek logs                |            |  - Détecte attaques           |
|                        |            |                             |            |  - Génère alertes             |
|                        |            | Script (parsing des logs et |
|                        |            | communication avec l'IA ):  |
|                        |            |    - parser_and_twia.py     |
|                        |            |                             |


+------------------------+            +---------------------------+            +-------------------------------+

                                    VPN Mesh sécurisé (Tailscale)
                                    🔒 Chiffrement point-à-point
