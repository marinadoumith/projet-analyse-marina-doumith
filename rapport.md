# Rapport - Analyse des journaux du pare-feu

## Résumé
Le fichier couvre une semaine (5 au 11 octobre 2026) et contient 5 440 connexions après nettoyage (60 doublons supprimés, 166 valeurs `bytes_sent` manquantes remplacées par la médiane, protocoles mis en majuscules). Le trafic est dominé par HTTPS (port 443, le plus fréquent), puis HTTP et DNS. Le pare-feu bloque 13,57 % des connexions. Deux comportements sortent nettement du lot : un balayage de ports depuis 192.168.1.99 et un volume d'octets sortants anormal depuis la caméra 192.168.1.11.

## Comportements suspects

### 1. Scan de ports depuis 192.168.1.99
- **Preuve** : cette IP a contacté 328 ports distincts, alors que les autres IP en contactent environ 8 (médiane). Elle cumule 400 connexions vers une seule destination, avec 95,8 % de DENY, toutes depuis un appareil de type PC.
- **Figure** : `figures/ip_ports_distincts.png`.
- **Interprétation** : le schéma (un seul hôte ciblé, des centaines de ports différents, presque tout bloqué) correspond à une reconnaissance réseau. Le PC est probablement compromis ou utilisé à des fins malveillantes.

### 2. Exfiltration possible depuis 192.168.1.11 (caméra IoT)
- **Preuve** : cette IP a envoyé environ 260 Mo au total, soit 94,7 % de tous les octets de la semaine, contre une médiane d'environ 0,5 Mo par IP. Sa moyenne est de 1,34 Mo par connexion contre 50 Ko pour l'ensemble du trafic, et 185 de ses 194 connexions ont été autorisées.
- **Figure** : `figures/octets_par_appareil.png`.
- **Interprétation** : une caméra n'a aucune raison d'envoyer autant de données vers l'extérieur (8.8.8.8, 1.1.1.1, ports 443/8080). L'appareil est probablement compromis et sert à sortir des données.

## Autres observations
- Telnet (port 23) : 100 tentatives, dont 26 autorisées, alors que ce protocole n'est pas chiffré.
- RDP (port 3389) : 111 connexions à vérifier.
- Pic d'activité le 8 octobre (1 137 connexions contre environ 700 les autres jours), probablement lié au scan.

## Recommandations
1. **Bloquer et isoler** 192.168.1.99 et 192.168.1.11 le temps d'une analyse, puis réinstaller ou réinitialiser les appareils.
2. **Segmentation IoT** : mettre caméras et capteurs dans un VLAN dédié, sans accès sortant sauf vers les destinations nécessaires (par exemple le broker MQTT sur le port 1883).
3. **Fermer Telnet (23)** sur tout le réseau et utiliser SSH (22) avec authentification par clé.
4. **Règles de détection** : alerte quand une IP contacte plus de 50 ports distincts en peu de temps, et quand un appareil dépasse un seuil d'octets sortants (limitation du débit sortant des objets IoT).
5. **Restreindre RDP (3389)** aux seules IP d'administration.
