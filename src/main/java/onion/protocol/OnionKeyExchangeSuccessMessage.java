package onion.protocol;

import java.nio.ByteBuffer;

import onion.Utility;

public class OnionKeyExchangeSuccessMessage extends OnionPrivateMessage {
	
	public OnionKeyExchangeSuccessMessage(short circId) {
		super(circId, OnionPrivateMessageType.KEY_EXCHANGE_SUCCESS);
	}
	
	public static OnionKeyExchangeSuccessMessage parse(ByteBuffer buffer, OnionBaseMessage baseMessage) {
		return new OnionKeyExchangeSuccessMessage(baseMessage.getCircId());
	}
	
    @Override
	public void send(ByteBuffer out) {
    	super.send(out);
    	// Add padding
    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength();
    	Utility.addRandomPadding(out, padLength);
    }
    
    public static OnionKeyExchangeSuccessMessage parse(ByteBuffer out, OnionAESEncryptedMessage decrypted) {
    	return new OnionKeyExchangeSuccessMessage(decrypted.getCircId());
    }
	
	
	
}
