# README - Analyseur de Protocoles Réseau 'Offline'

## _Encadré par Madame THAI Kim Loan_

Ce projet a été réalisé par Sitang Ninine et Jankovskaja Elina dans le cadre de l'UE LU3IN003 de Réseaux. Il a été encadré par Mme. THAI Kim Loan en travaux dirigés et par M. Spathis Prométhée en cours magistraux.<br>

Il permet d'analyser une trame provenant d'un réseau Ethernet.<br>

Notre programme est en mesure de comprendre les protocoles:

* Couche 2: Ethernet
* Couche 3: IP
* Couche 4: UDP
* Couche 7: DNS et DHCP

## Particularités

* Dans le cas de DNS, notre analyseur décode les six (6) champs d'entête ainsi que<br><br><br>
les sections Questions, Réponses, Autorités et Additionnelles. Il décode<br><br><br>
toutes les informations y compris les noms compressés.
* Dans le cas de DHCP, notre analyseur décode les huit (8) types de messages et<br><br><br>
l'ensemble des options définies pour chaque type de message.
* A chaque exécution, le résultat de notre analyseur est sauvegardé dans un<br><br><br>
ficher texte formaté de façon à faciliter sa lecture.

Dans ce README, nous donnons une description des classes ainsi que des fonctions qui la composent. L'ensemble des attributs sont initialisés dans le constructeur de la classe.

## Classes

## _Classe Ethernet_

> La classe Ethernet permet de déchiffrer un protocol Ethernet.

La classe Ethernet possède les attributs privés:

| Type | Nom de l'attribut | Description |
| --- | --- | --- |
| String | mac_dest | Valeur de l'adresse MAC destination |
| String | mac_src | Valeur de l'adresse MAC source |
| String | type | Valeur du type |
| List<String> | trame | Trame actuelle a analyser |
| Path | path | Permet l'écriture dans un fichier choisi |

La classe Ethernet possède les fonctions:

| Type | Nom de la fonction | Description |
| --- | --- | --- |
| String | mac_dest | Valeur de l'adresse MAC destination |
| String | mac_src | Valeur de l'adresse MAC source |
| String | type | Valeur du type |
| List<String> | trame | Trame actuelle a analyser |
| Path | path | Permet l'écriture dans un fichier choisi |
| String | toString | Permet de représenter l'entête Ethernet en chaine de caractères |

## _Classe Ip_

> La classe Ip permet de déchiffrer un protocol IP.

La classe Ip possède les attributs privés:

| Type | Nom de l'attribut | Description |
| --- | --- | --- |
| String | src | Adresse IP source sous la forme x.x.x.x |
| String | dest | Adresse IP destination sous la forme x.x.x.x |
| String | version_hl | Version et longueur du header |
| int | totalLength | Longueur totale de la trame |
| String | id | Identifiant de l'entête IP |
| String | flags | Flags de l'entête IP |
| int | ttl | Time to live |
| String | protocol | Protocol encapsulé |
| String | header_checksum | Protocol encapsulé |
| List<String> | trame | Trame actuelle a analyser |
| boolean | trameValide | Booléen qui passe à faux si la trame est invalide |
| Path | path | Permet l'écriture dans un fichier choisi |

La classe Ip possède les fonctions:

| Type | Nom de la fonction | Description |
| --- | --- | --- |
| static void | writeFile | Va permettre d'écrire dans un fichier |
| static String | hexToBinc | Permet de convertir un hexadecimal en String binaire |
| int | hexToDecimal | Permet de convertir un hexadecimal en int décimal |
| int | getProtocol | Retourne le protocole encapsulé par IP |
| String | protocolSolver | Retourne le protocole utilisé |
| String | ipBuilder | Permet de construire des adresse ip à partir de nombre héxadécimaux |
| int | getHl | Permet de récupérer le Header Length |
| int | binToDec | Permet de passer d'une String binaire à un int décimal |
| String | toString | Permet de représenter l'entête IP en chaine de caractères |

## _Classe Udp_

> La classe Udp permet de déchiffrer un protocol UDP.

La classe Udp posseède les attributs privés:

| Type | Nom de l'attribut | Description |
| --- | --- | --- |
| List<String> | trame | Trame actuelle a analyser |
| int | port_src | Valeur de l'adresse MAC destination |
| int | port_dest | Valeur de l'adresse MAC source |
| int | longueur | Longueur de l'entête UDP et du protocole qu'il encapsule |
| String | checksum | Checksum |
| Path | path | Permet l'écriture dans un fichier choisi |
| Ip | ip | Permet d'accéder à toutes les méthodes d'IP |

La classe UDP possède les fonctions:

| Type | Nom de la fonction | Description |
| --- | --- | --- |
| boolean | verificationPort | Fonction qui va vérifier les ports et voir si notre code accepte les protocoles |
| String | toString | Permet de représenter l'entête UDP en chaine de caractères |

## _Classe Dhcp_

> La classe Dhcp permet de déchiffrer un protocol DHCP. Elle prend en compte l'ensemble des options DHCP.

La classe Dhcp possède les attributs privés:

| Type | Nom de l'attribut | Description |
| --- | --- | --- |
| String | info | Permet d'avoir les informations de l'entête |
| String | message_type | Type du message |
| int | hard_l | Longueur du hardware |
| int | hops | Nombre de sauts effectués |
| String | trans_id | Identifiant de la transaction DHCP |
| int | sec_elapsed | Temps écoulé en secondes |
| String | c_ip | Adresse IP du client sous la forme x.x.x.x |
| String | y_ip | Votre adresse IP sous la forme x.x.x.x |
| String | next_ip | Prochaine adresse IP sous la forme x.x.x.x |
| String | relay_agent_ip | Adresse IP du relay agent sous la forme x.x.x.x |
| String | c_mac | Adresse MAC du client |
| String | server_hname | Nom du server host |
| String | bf_name | Nom du boot file |
| String | bootp_f | Boot file |
| StringBuilder | opt | Options |
| List<String> | trame | Trame actuelle a analyser |
| boolean | trameValide | Booléen qui passe à faux si la trame est invalide |
| Ip | ip | Entête IP encapsulant la couche DHCP |
| Path | path | Permet l'écriture dans un fichier choisi |
| Udp | udp | Entête UDP encapsulant la couche UDP |

La classe Dhcp possède les fonctions:

| Type | Nom de la fonction | Description |
| --- | --- | --- |
| int | hexToDecimal | Permet de convertir un hexadecimal en int décimal |
| String | ipBuilder | Construit une chaîne ip |
| String | hexTotext | Transforme des caractère héxadécimal en caractères ASCII |
| String | timeSolver | Donne le temps |
| String | optionSolver | Permet de gérer les différentes options DHCP |
| String | ParameterRequestListSolver | Permet de déterminer les options du Parameter Request |
| String | DHCPMessageType | Permet de retrouver le type du message |
| String | toString | Permet de représenter l'entête DHCP en chaine de caractères |

## _Classe Dns_

> La classe Dns permet de déchiffrer un protocol DNS. Elle prend en compte la compression des messages DNS.

La classe Dns possède les attributs privés:

| Type | Nom de l'attribut | Description |
| --- | --- | --- |
| List<String> | trame | Trame actuelle a analyser |
| String | Transaction_ID | Identifiant |
| String | Flags | Flags de l'entête DNS |
| int | Questions | Nombre de questions |
| int | Answer_RRs | Nombre de réponses |
| int | Authority_RRs | Nombre d'authorités |
| String | Additional_RRs | Nombre d'additionnels |
| Ip | ip | Entête IP encapsulant la couche DNS |
| int | encap_l | Longueur des couches qui encapsulent DNS |
| StringBuilder | name | Permet d'obtenir les différentes valeurs du champ NAME |
| int | type | Permet d'obtenir les différentes valeurs du champ TYPE(16) |
| String | classe | Permet d'obtenir les différentes valeurs du champ CLASS(16) |
| int | ttl | Permet d'obtenir les différentes valeurs du champ TTL(32) |
| int | data | Permet d'obtenir les différentes valeurs du champ RDATA_LENGTH (16) |
| int | preference | Contient le nombre de préférences des réponses MX |
| StringBuilder | Mail_Exchange | Permet d'avoir un resource record d'un champ Mail Exchange (MX (0x000F)) |
| StringBuilder | Name_Server | Permet d'avoir un resource record d'un champ Name Server (NS (0x0002)) |
| StringBuilder | cname | Permet d'avoir un resource record d'un champ Nom canonique (CNAME (0x0005)) |
| StringBuilder | AAAA_Adress | Permet d'avoir un resource record d'une adresse IPv6 (AAAA (0x001C)) |
| StringBuilder | Adress | Permet d'avoir un resource record d'une adresse IPv4 (A (0x0001)) |
| StringBuilder | Primary_name_server | Permet d'avoir le nom du champ Start of Authority (SOA) |
| StringBuilder | Responsible_authority_mailbox | Permet d'avoir le nom du champ Responsible authority's mailbox (SOA) |
| int | Serial_Number | Numéro de série (SOA) |
| int | Refresh_Interval | Intervalle de rafraîchissement (SOA) |
| int | Expire_limit | Limite d'expiration (SOA) |
| int | Minimum_TTL | Minimum Time To Live (SOA) |
| Path | path | Permet l'écriture dans un fichier choisi (SOA) |

La classe Dns possède les fonctions:

| Type | Nom de la fonction | Description |
| --- | --- | --- |
| int | hexTobin | Fonction qui permet de convertir un hexadecimal en String binaire |
| String | hexTotext | Transforme des caractère héxadécimal en caractères ASCII |
| String | time | Permet de donner le temps |
| void | flagSolver | Permet de résoudre le champ flag |
| void | typeQuestion_title | Permet de résoudre le type dans le titre du champ Questions |
| void | typeSolver | Permet de résoudre le type |
| void | typeAnswers_title | Permet de résoudre le type dans le titre du champ Answers |
| void | typeValue | Indentifie et donne la valeur selon le type |
| int | binTodec | Donne un chiffre decimal a partir d'une String binaire |
| int | nameSolverbis | Détermine la taille des noms compressés dans la trame |
| void | nameSolver | Initialise les valeurs qui stockent un nom |
| int | answersSolver | Permet de résoudre les champs Answers, Authority et Additionnal |
| String | toString | Permet de représenter l'entête DNS en chaine de caractères |

## Installation

Notre projet a été vérifié pour fonctionner avec openjdk 11.0.11.

Nous vous recommendons d'installer cette version de java.

```
sudo mkdir /usr/lib/jvm
<span class="hljs-built_in">cd</span> /usr/lib/jvm
sudo tar -xvzf ~/Downloads/jdk-<span class="hljs-number">11.0</span>.<span class="hljs-number">13</span>_linux-x64_bin.tar.gz
sudo nano /etc/environment
/usr/lib/jvm/jdk-<span class="hljs-number">11.0</span>.<span class="hljs-number">13</span>/bin
JAVA_HOME=<span class="hljs-string">"/usr/lib/jvm/jdk-11.0.13"</span>
PATH=<span class="hljs-string">"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"</span>
sudo update-alternatives --install <span class="hljs-string">"/usr/bin/java"</span> <span class="hljs-string">"java"</span> <span class="hljs-string">"/usr/lib/jvm/jdk-11.0.13/bin/java"</span> <span class="hljs-number">0</span>
sudo update-alternatives --install <span class="hljs-string">"/usr/bin/javac"</span> <span class="hljs-string">"javac"</span> <span class="hljs-string">"/usr/lib/jvm/jdk-11.0.13/bin/javac"</span> <span class="hljs-number">0</span>
sudo update-alternatives --set java /usr/lib/jvm/jdk-<span class="hljs-number">11.0</span>.<span class="hljs-number">13</span>/bin/java
sudo update-alternatives --set javac /usr/lib/jvm/jdk-<span class="hljs-number">11.0</span>.<span class="hljs-number">13</span>/bin/javac
update-alternatives --list java
update-alternatives --list javac
```

Puis pour vérifier la version de java installée:

```
java -version
```

Pour installer notre projet, il vous faudra décompresser l'archive:

```
unzip ProjetReseaux.zip <span class="hljs-operator">-d</span> somedir
```

## Fichiers de tests supplémentaires

En plus des classes permettant de déchiffrer la trame, notre projet vous fournis des trames test:

* DHCPDiscover.txt : Trame DHCP Discover
* DHCPOffer.txt : Trame DHCP Offer
* DNSSimple.txt : Trame DNS avec uniquement un champ Questions
* DNSInter.txt : Trame DNS avec un champ Questions et un champ Answers
* DNSDifficile.txt : Trame DNS avec tous les champs possibles
* TrameProblématique.txt : Trame avec du texte interposé entre les lignes

