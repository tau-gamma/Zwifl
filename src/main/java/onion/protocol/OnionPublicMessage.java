package onion.protocol;

public class OnionPublicMessage extends OnionBaseMessage {

	protected OnionPublicMessage(short circId, OnionPublicMessageType publicType) {
		super(circId, publicType);
	}
	
}
