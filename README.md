# Shelly - Soliscloud Connector

Dieses Skript schaltet den Shelly ein, wenn die Einspeisung der Solaranlage größer als 3kW ist.
Das Skript muss einmalig gestartet werden und prüft dann alle 5 Minuten den Wert der Einspeisung (`psum`) in der Soliscloud.


## Verbindung zur Soliscloud

Für den Zugang zur Soliscloud REST API wird ein `key` und ein `keySecret` benötigt. Diese müssen beantragt werden und dann in das Skript eingefügt werden: [Request API Access](https://solis-service.solisinverters.com/en/support/solutions/articles/44002212561-request-api-access-soliscloud)

## Verwendung
Der Inhalt des Skripts `shelly-solis-min.js` wird in ein neues Shelly-Skript kopiert.
Im Skript selbst muss dann der `key` und das `keySecret` der Soliscloud eingefügt werden (siehe TODOs im Code).

### Inhalt dieses Repositories
`shelly-solis-min.js`: Optimierte Variante von `shelly-solis.js`, bei dem der MD5-Hash nicht bei jeder Ausführung berechnet wird. Da der Request-Body immer leer ist (`{}`), ist diese Optimierung möglich. Das ist sinnvoll, da die Hash-Berechnungen (MD5 und HMAC SHA1) den Shelly fast an seine Leistungsgrenze bringt.

`shelly-solis.js`: Variante mit MD5-Berechnung

`java-tool`: Maven-Projekt der Testanwendung von Solis, das bei der Erstellung des Skripts hilfreich war.


## Links
- [SolisCloud Platform API Document v2.0.2](https://oss.soliscloud.com/templet/SolisCloud%20Platform%20API%20Document%20V2.0.2.pdf)
- [SHA1 + HMAC in Javascript](https://gist.github.com/Seldaek/1730205)
- [Hex to ASCII](https://stackoverflow.com/a/3745677)

