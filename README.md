# NIDSense

## Description du projet

**NIDSense** est un système intelligent de détection d'intrusion (IDS) en temps réel, conçu pour identifier automatiquement les attaques ou comportements suspects sur un serveur.
Il s'appuie sur la collecte de logs système, réseau, base de données et applicatifs web, qui sont transformés et analysés par une intelligence artificielle (Mistral via Ollama) hébergée localement.
L'architecture distribue les rôles sur trois machines distinctes, interconnectées via un VPN sécurisé (Tailscale) pour garantir confidentialité et résilience.

---

## Structure du projet

```
+------------------------+            +-----------------------------+             +----------------------------------------+
|   🛡️ Serveur Rocky     |            |   🔎 Machine Ubuntu        |             |               🤖 Windows               |
|      (Cible)           |            | (Traitement des données)    |             |           (Mistral + Ollama)           |
+------------------------+            +-----------------------------+             +----------------------------------------+
| Services exposés :     |            | Services :                  |             | Services :                             |
|  - Apache (port 80)    |            |  - rsyslog (UDP 514)        |             |  - Ollama (Mistral)                    |
|  - MariaDB (3306)      |            |  - Zeek NIDS                |             |  - GPU Accélération                    |
|  - SSH (22)            |            |                             |             |                                        |
|  - Auditd              |            |                             |             |                                        |
|                        |            | Flux entrant :              |             |                                        |
| Génère logs :          | -------->  |  - apache-access.log        |             |                                        |
|  - Apache logs         |  Rsyslog   |  - mariadb.log              |             |                                        |
|  - MariaDB logs        |   (UDP)    |  - auditd.log               |             |                                        |
|  - AuditD logs         |            |        +                    |             |                                        |
|                        |            |  - zeek.log                 |             |                                        |
|                        |            |                             |             |                                        |
|                        |            | Script (parsing des logs et |             |                                        |
|                        |            | communication avec l'IA ):  |   PROMPT    | Analyse IA (à partir du prompt reçu) : |
|                        |            |  - parser_and_twia.py       |  -------->  |   - Réception des logs parsés          |
|                        |            |                             |             |   - Vérifie comportement               |
|                        |            |                             |   REPONSE   |   - Détecte attaques                   |
|                        |            |                             |  <--------- |   - Génère alertes                     |
+------------------------+            +-----------------------------+             +----------------------------------------+
```

                                                VPN Mesh sécurisé (Tailscale)
                                                🔒 Chiffrement point-à-point

