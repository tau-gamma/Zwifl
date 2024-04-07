package onion.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;

import org.junit.Test;

import onion.security.SymmetricKeyExchange;

public class SymmetricKeyExchangeTest {

	@Test
	public void generateAESKeyTest() {
		SecretKey key1 = SymmetricKeyExchange.generateAESKey();
		SecretKey key2 = SymmetricKeyExchange.generateAESKey();

		assertFalse("key1 should not equal key2", Arrays.equals(key1.getEncoded(), key2.getEncoded()));
	}

	@Test
	public void encryptDecryptRSATest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

		KeyPair keyPair = kpg.generateKeyPair();
		KeyPair wrongPair = kpg.generateKeyPair();

		byte[] data = new byte[16];
		SecureRandom random = new SecureRandom();

		random.nextBytes(data);

		byte[] encrypted = SymmetricKeyExchange.encryptRSA((RSAPublicKey) keyPair.getPublic(), data);
		assertFalse("encrypted should not equal data", Arrays.equals(data, encrypted));

		byte[] decrypted = SymmetricKeyExchange.decryptRSA(encrypted, (RSAPrivateKey) keyPair.getPrivate());
		assertArrayEquals(data, decrypted);

		try {
			SymmetricKeyExchange.decryptRSA(encrypted, (RSAPrivateKey) wrongPair.getPrivate());
			fail( "BadPaddingException didn't throw when I expected it to" );
		} catch (BadPaddingException e) {
		}

	}

}
