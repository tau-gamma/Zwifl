package onion.protocol;

import java.nio.ByteBuffer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import onion.Utility;

public class OnionKeyExchangeMessage extends OnionPublicMessage {
	
	private SecretKey secretKey;
	
	
	public OnionKeyExchangeMessage(short circId, SecretKey secretKey) {
		super(circId, OnionPublicMessageType.KEY_EXCHANGE);
		this.secretKey = secretKey;
	}
	
	public SecretKey getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}

	public static OnionKeyExchangeMessage parse(ByteBuffer buffer, OnionBaseMessage baseMessage) {
		int length = 16;
		byte[] bytes = new byte[length];
		buffer.get(bytes);		
		SecretKeySpec key = new SecretKeySpec(bytes, "AES");
		
		OnionKeyExchangeMessage ret = new OnionKeyExchangeMessage(baseMessage.getCircId(), key);
		return ret;
	}
	
    @Override
	public void send(ByteBuffer out) {
    	super.send(out);
    	out.put(secretKey.getEncoded());
    	// Add padding
    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength() - secretKey.getEncoded().length;
    	Utility.addRandomPadding(out, padLength);
    }
	
	
	
}
