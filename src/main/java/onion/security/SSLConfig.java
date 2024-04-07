package onion.security;

public class SSLConfig {
	private String truststorePassphrase;
	private String keystorePassphrase;
	private String truststore;
	private String keystore;
	
	public SSLConfig(String truststorePassphrase, String keystorePassphrase, String truststore, String keystore) {
		this.truststorePassphrase = truststorePassphrase;
		this.keystorePassphrase = keystorePassphrase;
		this.truststore = truststore;
		this.keystore = keystore;
	}

	public String getTruststorePassphrase() {
		return truststorePassphrase;
	}

	public void setTruststorePassphrase(String truststorePassphrase) {
		this.truststorePassphrase = truststorePassphrase;
	}

	public String getKeystorePassphrase() {
		return keystorePassphrase;
	}

	public void setKeystorePassphrase(String keystorePassphrase) {
		this.keystorePassphrase = keystorePassphrase;
	}

	public String getTruststore() {
		return truststore;
	}

	public void setTruststore(String truststore) {
		this.truststore = truststore;
	}

	public String getKeystore() {
		return keystore;
	}

	public void setKeystore(String keystore) {
		this.keystore = keystore;
	}
}
