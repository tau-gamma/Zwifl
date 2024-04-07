package onion.security;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import onion.protocol.OnionAESEncryptedMessage;
import onion.protocol.OnionBaseMessage;
import onion.protocol.interfaces.OnionBaseIv;

public class SymmetricEncryption {
	
	private static final String CIPHER_MODE = "AES/CBC/NoPadding";
	private static final String IV_MODE = "AES/ECB/NoPadding";
	private static final Cipher ivCipher;
	
	static {
        try {
            ivCipher = Cipher.getInstance(IV_MODE);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            ex.printStackTrace();
            throw new RuntimeException();
        }
	}

	public static byte[] encryptCBC(byte[] plainText, byte[] iv, SecretKey key) {

		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		Cipher cipher;

		try {
            cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new RuntimeException(); //AES CBC w Padding has to be available
        }
		
        try {
           return cipher.doFinal(plainText);
        } catch (BadPaddingException
                | IllegalBlockSizeException ex) {
            //ShortBufferException: we made sure that the buffer is long enough
            //IllegalBlockSizeException: our block is always *1024 bytes
            //BadPaddingException: we are not decrypting here
        	ex.printStackTrace();
            throw new RuntimeException();
        }
	}

	public static byte[] decryptCBC(byte[] encrypted, byte[] iv, SecretKey key) {

		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		Cipher cipher;

		try {
            cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
        	ex.printStackTrace();
            throw new RuntimeException(); //AES CBC w Padding has to be available
        }
		
        try {
           return cipher.doFinal(encrypted);
        } catch (BadPaddingException
                | IllegalBlockSizeException ex) {
        	ex.printStackTrace();
            //ShortBufferException: we made sure that the buffer is long enough
            //IllegalBlockSizeException: our block is always *1024 bytes
            //BadPaddingException: we are not decrypting here
            throw new RuntimeException();
        }
	}
	
	public static byte[] encryptIv(byte[] iv, SecretKey key) throws Exception {
        try {
            ivCipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException ex) {
        	ex.printStackTrace();
            throw new RuntimeException(ex);
        }
        byte[] output = null;
        try {
            output = ivCipher.doFinal(iv);
        } catch (BadPaddingException ex) {
        	ex.printStackTrace();
        	throw new RuntimeException(ex); 
        }
        return output;
	}

	public static byte[] decryptIv(byte[] encryptedIv, SecretKey key) throws Exception {
        try {
            ivCipher.init(Cipher.DECRYPT_MODE, key);
        } catch (InvalidKeyException ex) {
        	ex.printStackTrace();
            throw new RuntimeException(ex);
        }
        try {
            return ivCipher.doFinal(encryptedIv);
        } catch (BadPaddingException ex) {
        	ex.printStackTrace();
            throw new RuntimeException(ex);
        }
	}
	

	
	public static OnionAESEncryptedMessage encryptMessage(OnionBaseIv msg, SecretKey key) throws Exception {
		ByteBuffer buffer = ByteBuffer.allocate(OnionBaseMessage.ONION_MAX_LENGTH);
		msg.send(buffer);
		byte[] packet = buffer.array();
		// We only encrypt the payload part ( which starts at 32: 4B public header + 12B reserved + 16B IV)
		byte[] encryptedPayload = encryptCBC(Arrays.copyOfRange(packet, 20+12, packet.length), msg.getIv(), key);
		byte[] encryptedIV = encryptIv(msg.getIv(), key);
		
		return new OnionAESEncryptedMessage(msg.getCircId(), msg.getPublicType(), encryptedIV, encryptedPayload);
	}
	
	
	public static OnionAESEncryptedMessage decryptMessage(OnionAESEncryptedMessage msg, SecretKey key) throws Exception {
		byte [] decryptedIV = decryptIv(msg.getIv(), key);
		byte [] decryptedPayload = decryptCBC(Arrays.copyOfRange(msg.getPayload(), 0, msg.getPayload().length), decryptedIV, key);
		
		return new OnionAESEncryptedMessage(msg.getCircId(), msg.getPublicType(), decryptedIV, decryptedPayload);
	}

}
