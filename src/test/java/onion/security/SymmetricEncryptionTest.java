package onion.security;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.Test;

import onion.OnionCircuit;
import onion.Utility;
import onion.api.OnionApiHandler;
import onion.protocol.OnionAESEncryptedMessage;
import onion.protocol.OnionBaseMessage;
import onion.protocol.OnionCoverTrafficMessage;
import onion.protocol.OnionDataMessage;
import onion.protocol.OnionKeyExchangeSuccessMessage;
import onion.protocol.interfaces.OnionBaseIv;
import onion.security.SymmetricEncryption;
import onion.security.SymmetricKeyExchange;

public class SymmetricEncryptionTest {
	
	byte[] data = "Some random plain text to be encrypted".getBytes();
	SecureRandom random = new SecureRandom();
	SecretKey key1 = SymmetricKeyExchange.generateAESKey();
	SecretKey key2 = SymmetricKeyExchange.generateAESKey();
	
	@Test
	public void encryptDecryptIv() throws Exception {
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		
		byte[] enc = SymmetricEncryption.encryptIv(iv, key1);
		assertFalse("iv and encrypted iv should not be equal", Arrays.equals(iv, enc));
		
		byte[] decWrong = SymmetricEncryption.decryptIv(enc, key2);
		assertFalse("iv should not be decrypted by wrong key", Arrays.equals(iv, decWrong));
		
		byte[] decRight = SymmetricEncryption.decryptIv(enc, key1);
		assertArrayEquals("iv should be decrypted by right key", iv, decRight);
	}
	
	@Test
	public void cbcEncryptDecrpt() throws Exception {
		byte[] plainText = new byte[480];
		random.nextBytes(plainText);
		
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		
		byte[] cipher = SymmetricEncryption.encryptCBC(plainText, iv, key1);
		assertFalse("plaintext and cipher should not be equal", Arrays.equals(iv, cipher));
		assertEquals("plainText and cipher should habve same size", plainText.length, cipher.length);
		
		byte[] decWrong = SymmetricEncryption.decryptCBC(cipher, iv, key2);
		assertFalse("cipher should not be decrypted by wrong key", Arrays.equals(cipher, decWrong));
		
		byte[] decRight = SymmetricEncryption.decryptCBC(cipher, iv, key1);
		assertArrayEquals("cipher should be decrypted by right key", plainText, decRight);
	}
	
	@Test
	public void encryptDecryptOneLayer() throws Exception {
		OnionDataMessage msg = new OnionDataMessage((short) 99, (short) 42, (short) 0, data);
		
		OnionApiHandler handler = new OnionApiHandler(null, null, null);
		OnionCircuit c = new OnionCircuit((short) 99, null, null, null);
		handler.addCricuit(c);
		
		c.addKey(SymmetricKeyExchange.generateAESKey());
		
		OnionAESEncryptedMessage encrypted = handler.ecnryptMessageLayers(msg);
		assertFalse("encrypted layer should not equal plaintext", Arrays.equals(Utility.messageToArray(msg), Utility.messageToArray(encrypted)));
		
		ByteBuffer b = ByteBuffer.allocate(OnionBaseMessage.ONION_MAX_LENGTH);
		encrypted.send(b);
		b.position(0);
		
		OnionBaseMessage decrypted = handler.decryptMessageLayers(b, msg.getCircId());
		assertTrue(decrypted instanceof OnionDataMessage);
		OnionDataMessage casted = (OnionDataMessage) decrypted;
		assertEquals(msg.getCircId(), casted.getCircId());
		assertEquals(msg.getFileIdentifier(), casted.getFileIdentifier());
		assertArrayEquals(msg.getData(), casted.getData());
		assertEquals(msg.getDestCheck(), casted.getDestCheck());
		
	}
	
	public OnionBaseMessage encryptDecryptMultipleLayers(OnionBaseIv msg) throws Exception {
		OnionApiHandler handler = new OnionApiHandler(null, null, null);
		OnionCircuit c = new OnionCircuit((short) 99, null, null, null);
		handler.addCricuit(c);
		
		for (int i = 0; i < random.nextInt(10) + 2; i++) {
			c.addKey(SymmetricKeyExchange.generateAESKey());
		}
		OnionAESEncryptedMessage encrypted = handler.ecnryptMessageLayers(msg);
		assertFalse("encrypted layers should not equal plaintext", Arrays.equals(Utility.messageToArray((OnionBaseMessage)msg), Utility.messageToArray(encrypted)));
		
		ByteBuffer b = ByteBuffer.allocate(OnionBaseMessage.ONION_MAX_LENGTH);
		encrypted.send(b);
		b.position(0);
		
		OnionBaseMessage decrypted = handler.decryptMessageLayers(b, msg.getCircId());
		
		return decrypted;
	}
	
	private void assertNotEqualMessages(String msg, OnionBaseMessage expected, OnionBaseMessage actual) {
		assertFalse(msg, Arrays.equals(Utility.messageToArray(expected), Utility.messageToArray(actual)));
	}
	

	
	@Test
	public void encryptDecryptOnionDataMessage() throws Exception {
		OnionDataMessage msg = new OnionDataMessage((short) 99, (short) 42, (short) 0, data);
		OnionBaseMessage decrypted = encryptDecryptMultipleLayers(msg);
		
		assertTrue(decrypted instanceof OnionDataMessage);
		OnionDataMessage casted = (OnionDataMessage) decrypted;
		assertEquals(msg.getCircId(), casted.getCircId());
		assertEquals(msg.getFileIdentifier(), casted.getFileIdentifier());
		assertArrayEquals(msg.getData(), casted.getData());
		assertEquals(msg.getDestCheck(), casted.getDestCheck());
	}

	@Test
	public void encryptDecryptOnionKeyExchangeSuccessMessage() throws Exception {
		OnionKeyExchangeSuccessMessage msg = new OnionKeyExchangeSuccessMessage((short) 99);
		OnionBaseMessage decrypted = encryptDecryptMultipleLayers(msg);
		
		assertTrue(decrypted instanceof OnionKeyExchangeSuccessMessage);
		OnionKeyExchangeSuccessMessage casted = (OnionKeyExchangeSuccessMessage) decrypted;
		assertEquals(msg.getCircId(), casted.getCircId());
		assertEquals(msg.getDestCheck(), casted.getDestCheck());
	}
	
	@Test
	public void encryptDecryptOnionCoverTrafficMessage() throws Exception {
		OnionCoverTrafficMessage msg = new OnionCoverTrafficMessage((short) 99);
		OnionBaseMessage decrypted = encryptDecryptMultipleLayers(msg);
		
		assertTrue(decrypted instanceof OnionCoverTrafficMessage);
		OnionCoverTrafficMessage casted = (OnionCoverTrafficMessage) decrypted;
		assertEquals(msg.getCircId(), casted.getCircId());
		assertEquals(msg.getDestCheck(), casted.getDestCheck());
	}
	
}
