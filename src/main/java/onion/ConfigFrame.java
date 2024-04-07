package onion;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.ini4j.ConfigParser.InterpolationException;
import org.ini4j.ConfigParser.NoOptionException;
import org.ini4j.ConfigParser.NoSectionException;

import onion.security.SSLConfig;
import util.PEMParser;
import util.config.ConfigurationImpl;

public class ConfigFrame extends ConfigurationImpl  {
	
	private static final String HOPCOUNT = "hopcount";
	private int hopcount;

	private static final String HOSTKEY_PATH = "hostkey";
	private String hostkeyPath;

	private static final String TIME_PERIOD= "time_period";
	private int timePeriod;

	private static final String TRUST_STORE= "truststore";
	private static final String TRUSTSTORE_PASSPHRASE = "truststore_passphrase";

	private static final String KEY_STORE= "keystore";
	private static final String KEYSTORE_PASSPHRASE = "keystore_passphrase";
	
	private SSLConfig sslConfig;
	

	protected ConfigFrame(String filename, String section, Map<String, String> defaults) throws IOException, NoSectionException, NoOptionException, InterpolationException {
		super(filename, section, defaults);

		setHostkeyPath(parser.get(this.section, HOSTKEY_PATH));
		setTimePeriod(parser.getInt(this.section, TIME_PERIOD));
		setHopcount(parser.getInt(this.section, HOPCOUNT));
		sslConfig = new SSLConfig(parser.get(this.section, TRUSTSTORE_PASSPHRASE), parser.get(this.section, KEYSTORE_PASSPHRASE), parser.get(this.section, TRUST_STORE), parser.get(this.section, KEY_STORE));
	}
	
	public ConfigFrame(String filename) throws NoSectionException, NoOptionException, InterpolationException, IOException {
		this(filename, "onion", getDefaultMap());
	}
	
	private static Map<String, String> getDefaultMap() {
		Map<String, String> defaultMap = new HashMap<>();
		defaultMap.put(HOPCOUNT, String.valueOf(3));
		defaultMap.put(TIME_PERIOD, String.valueOf(100));
		return defaultMap;
	}
	

	public int getHopcount() {
		return hopcount;
	}

	public void setHopcount(int hopcount) {
		this.hopcount = hopcount;
	}

	public String getHostkeyPath() {
		return hostkeyPath;
	}

	public void setHostkeyPath(String hostkeyPath) {
		this.hostkeyPath = hostkeyPath;
	}

	public int getTimePeriod() {
		return timePeriod;
	}

	public void setTimePeriod(int timePeriod) {
		this.timePeriod = timePeriod;
	}

    public RSAPublicKey getPublicKey() throws InvalidKeyException, IOException {
        File file = new File(getHostkeyPath());
        return PEMParser.getPublicKeyFromPEM(file);
    }
    
    public RSAPrivateKey getPrivateKey() throws InvalidKeyException, IOException {
    	File file = new File(getHostkeyPath());
    	return PEMParser.getPrivateKeyFromPEM(file);
    }

	public SSLConfig getSslConfig() {
		return sslConfig;
	}

	public void setSslConfig(SSLConfig sslConfig) {
		this.sslConfig = sslConfig;
	}
    
}
