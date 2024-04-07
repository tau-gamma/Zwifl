# Zwifl (Onion)
Java implementation of an onion router like used in the TOR network. Encrypts the traffic between two clients that are connected over arbitrarily many servers.  The encrypted data is transmitted through a series of network nodes called "onion routers," each of which "peels" away a single layer, revealing the data's next destination. When the final layer is decrypted, the message arrives at its destination. The sender remains anonymous because each intermediary knows only the location of the immediately preceding and following nodes.[1]

[1] Goldschlag D., Reed M., Syverson P. (1999.) Onion Routing for Anonymous and Private Internet Connections, Onion Router.


## Installation
./ gradlew install

## Conguration
The module requires the following options in the conguration le to be set:
 - hostkey is the path to the private key used by the peer for key exchange
 - listen address is used by the peers to connect to each other and should have the format 127.0.0.1:6301
 - api address allows external modules to communicate to the onion module and should have the format 127.0.0.1:7301
 - time period is the interval in which an opaque tunnel switch will be executed (in seconds)
 - hopcount species the number of intermediate hops used for the tunnel
 - truststore is the path to the trust store which contains the TLS certicates to build a TLS connection
 - truststore passphrase is the passphrase of the truststore
 - keystore is the path to the trust store which contains the keys to build a TLS connection
 - keystore passphrase is the passphrase of the keystore

