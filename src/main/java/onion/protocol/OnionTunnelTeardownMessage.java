package onion.protocol;

import java.nio.ByteBuffer;

import onion.Utility;

public class OnionTunnelTeardownMessage extends OnionPublicMessage {
		
		public OnionTunnelTeardownMessage(short circId) {
			super(circId, OnionPublicMessageType.TEARDOWN_TUNNEL);
		}
		
		public static OnionTunnelTeardownMessage parse(ByteBuffer buffer, OnionBaseMessage baseMessage) {
			return new OnionTunnelTeardownMessage(baseMessage.getCircId());
		}
		
	    @Override
		public void send(ByteBuffer out) {
	    	super.send(out);
	    	// Add padding
	    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength();
	    	Utility.addRandomPadding(out, padLength);
	    }
		
		
		

}
