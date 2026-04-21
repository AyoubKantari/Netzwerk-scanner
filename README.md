# Netzwerk-Scanner
ein Python-Tool zur Analyse von lokalen Netzwerken
scannt aktive Hosts und offene ports und speichert die 
Ergebniss als json-Report

## Features
- host-Discovery im lokalen Netzwerk (ICMP Ping)
- port-Scanner mit Service-Erkennung (FTP, SSH, HTTP, MySQL...)
- multithreading für schnelle Ausführung (50 parallele Threads)
- automatischer json-Report mit Datum und ergebnissen

## Technologien
- Python 3.8+
- socket, subprocess, concurrent.futures, json

## Verwendung
```bash
python scanner.py
```

## Beispiel-Output (report.json)
```json
{
    "scan_datum": "2026-03-16 00:12",
    "eigene_ip": "10.6.228.2",
    "hosts": [
        {
            "ip": "10.6.228.2",
            "offene_ports": [
                {"port": 3306, "service": "MySQL"}
            ]
        }
    ]
}
```

## Hinweis
Universitätsnetzwerke blockieren ICMP-Ping aus sicherheitsgründen
Das Tool funktioniert optimal in lokalen heimnetzwerken