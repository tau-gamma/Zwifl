package onion.security;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricKeyExchange {
	
	SecureRandom random = new SecureRandom();
	
	private static final String CIPHER_MODE = "RSA/ECB/PKCS1Padding";

	public static SecretKey generateAESKey() {
		SecureRandom random = new SecureRandom();
		byte[] keyBytes = new byte[16];
		random.nextBytes(keyBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		return key;
	}

	public static byte[] encryptRSA(RSAPublicKey publicKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = null;
		byte[] key = null;
		cipher = Cipher.getInstance(CIPHER_MODE);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		key = cipher.doFinal(data);
		return key;
	}

	public static byte[] decryptRSA(byte[] data, RSAPrivateKey privateKey) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = null;

		cipher = Cipher.getInstance(CIPHER_MODE);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

}
