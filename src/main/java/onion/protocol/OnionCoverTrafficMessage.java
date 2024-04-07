package onion.protocol;

import java.nio.ByteBuffer;

import onion.Utility;

public class OnionCoverTrafficMessage extends OnionPrivateMessage {
	
	
	public OnionCoverTrafficMessage(short circId) throws KnouflException {
		super(circId, OnionPrivateMessageType.COVER);
	}
	
	/**
	 * Only 
	 * @param payload Only payload of message! without headers
	 * @return OnionDataMessage with circId set to -1
	 * @throws KnouflException
	 */
	public static OnionCoverTrafficMessage parse(ByteBuffer payload, OnionAESEncryptedMessage msg) throws KnouflException {
		return new OnionCoverTrafficMessage(msg.getCircId());
	}
	
    @Override
	public void send(ByteBuffer out) {
    	super.send(out);
    	// Add padding
    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength();
    	Utility.addRandomPadding(out, padLength);
    }
	
}
