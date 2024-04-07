package onion.security;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;


public class SSLSocketUtility {
	private SSLSocketFactory factory;
	
	private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	public SSLSocketUtility(SSLConfig config) {
		try {
			InputStream keyStoreResource = new FileInputStream(config.getKeystore());
			
			char[] keyStorePassphrase = config.getKeystorePassphrase().toCharArray();
			KeyStore ksKeys = KeyStore.getInstance("JKS");
			ksKeys.load(keyStoreResource, keyStorePassphrase);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ksKeys, keyStorePassphrase);

			InputStream trustStoreIS = new FileInputStream(config.getTruststore());
			char[] trustStorePassphrase = config.getTruststorePassphrase().toCharArray();
			KeyStore ksTrust = KeyStore.getInstance("JKS");
			ksTrust.load(trustStoreIS, trustStorePassphrase);

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ksTrust);

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

			factory = sslContext.getSocketFactory();
		} catch (Exception e) {
			logger.warning(e.getMessage());
		}
	}
	
	/**
	 * Create a SSLsocket connection to a server
	 * @param port
	 * @param address
	 * @return
	 */
	public Socket getSSLSocket(InetAddress address, int port) {
		try {
			SSLSocket socket = (SSLSocket) factory.createSocket(address, port);
			socket.setEnabledProtocols(StrongTLS.intersection(socket.getSupportedProtocols(), StrongTLS.ENABLED_PROTOCOLS));
			socket.setEnabledCipherSuites(StrongTLS.intersection(socket.getSupportedCipherSuites(), StrongTLS.ENABLED_CIPHER_SUITES));

			return socket;
		} catch (Exception e) {
			logger.warning(e.getMessage());
		}
		return null;
	}

	/**
	 * Convert a socket form the server to a sslsocket   
	 * @param socket
	 * @return
	 * @throws Exception
	 */
	public Socket convertToSSLSocket(Socket socket) throws Exception {
		InetSocketAddress address = (InetSocketAddress) socket.getRemoteSocketAddress();
		SSLSocket sslSocket = (SSLSocket) factory.createSocket(socket, address.getHostName(), socket.getPort(), true);
		sslSocket.setEnabledProtocols(StrongTLS.intersection(sslSocket.getSupportedProtocols(), StrongTLS.ENABLED_PROTOCOLS));
		sslSocket.setEnabledCipherSuites(StrongTLS.intersection(sslSocket.getSupportedCipherSuites(), StrongTLS.ENABLED_CIPHER_SUITES));
		sslSocket.setUseClientMode(false);
		sslSocket.startHandshake();

		return sslSocket;
	}
}