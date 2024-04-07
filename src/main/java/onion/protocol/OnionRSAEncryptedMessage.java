package onion.protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import onion.security.SymmetricKeyExchange;

public class OnionRSAEncryptedMessage extends OnionPublicMessage {
	
	public final static int RSA_ENCRYPTED_LENGTH = 256;

	private byte [] payload;
	
	public OnionRSAEncryptedMessage(short circId, OnionPublicMessageType publicType, byte [] payload) throws KnouflException {
		super(circId, publicType);
		if(payload.length != RSA_ENCRYPTED_LENGTH)
			throw new KnouflException("Encrypted Payload length must be " + RSA_ENCRYPTED_LENGTH);
		this.payload = payload;
	}
	
	@Override
	public void send(ByteBuffer out) {
		super.send(out);
		out.put(payload);
    	// Add padding
    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength() - payload.length;
    	byte[] padding = new byte[padLength];
    	out.put(padding);
	}

	public byte [] getPayload() {
		return payload;
	}

	public void setPayload(byte [] payload) {
		this.payload = payload;
	}
	
	public static OnionBaseMessage parse(ByteBuffer buffer, OnionBaseMessage baseMessage, RSAPrivateKey rsa) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, KnouflException {
		byte[] payload = new byte[buffer.remaining()];
		buffer.get(payload);
		byte[] decrypted = SymmetricKeyExchange.decryptRSA(Arrays.copyOfRange(payload, 0, RSA_ENCRYPTED_LENGTH), rsa); //TODO should we really decrypt here?
		
		switch (baseMessage.getPublicType()) {
			case KEY_EXCHANGE:
				return OnionKeyExchangeMessage.parse(ByteBuffer.wrap(decrypted), baseMessage);
		default:
			break;
			}
		throw new KnouflException("Public type unknown");
	}

}
