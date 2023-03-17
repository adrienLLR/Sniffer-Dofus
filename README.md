# Sniffer Dofus

Programme développé en C permettant de récupérer les paquets émis et envoyés par le client dofus lors d'une session de jeu et de les parser afin en sortie d'obtenir des informations sur l'état courant du jeu. Ces informations seraient ensuite transmises à un autre programme pour réaliser des actions en conséquences.

# Explication

Le programme utilise la librairie libpcap pour récolter les paquets reçus et envoyés par le client dofus. <br>
Une fois les paquets reçus, en connaissant le protocole réseau du jeu, il est possible de deserializer les paquets pour obtenir les informations voulues. Chaque paquet contient un ou plusieurs messages, ainsi le programme découpe le paquet en messages et deserialize chacun de ces messages. <br>

Malheureusement, je n'ai eu le temps que de deserializer les messages d'identifiant 5080, donc le programme est inachevé.

# Idée possible 

Hook ( avec frida ) la socket du client dofus pour changer l'ip et la rediriger vers un proxy qui fera l'intermédiaire entre le client et le serveur, faciliant l'analyse des paquets et l'envoie des paquets ( pour un bot plus évolué ). 

