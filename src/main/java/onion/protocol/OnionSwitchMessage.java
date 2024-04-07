package onion.protocol;

import java.nio.ByteBuffer;

import onion.Utility;

public class OnionSwitchMessage extends OnionPrivateMessage {
	
	private int uid;
	private byte isNew;
	private byte isAck;
	
	
	public OnionSwitchMessage(short circId, boolean isNew, boolean isAck, int uid) {
		super(circId, OnionPrivateMessageType.SWITCH);
		setIsNew(isNew);
		setIsAck(isAck);
		this.uid = uid;
	}
	
	
	@Override
	public int getMessageLength() {
		return super.getMessageLength()
				+ 4 // uid
				+ 1 //isNew
				+ 1; //isAck;
				
	}
	
	public static OnionSwitchMessage parse(ByteBuffer payload, OnionAESEncryptedMessage msg) throws KnouflException {
		int uid = payload.getInt();
		byte isNew = payload.get();
		byte isAck = payload.get();
		
		return new OnionSwitchMessage(msg.getCircId(), (isNew == 1), (isAck == 1), uid);
	}
	
    @Override
	public void send(ByteBuffer out) {
    	super.send(out);
    	out.putInt(uid);
    	out.put(isNew);
    	out.put(isAck);
    	// Add padding
    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - getMessageLength();
    	Utility.addRandomPadding(out, padLength);
    }

	public int getUid() {
		return uid;
	}

	public void setUid(int uid) {
		this.uid = uid;
	}

	public boolean getIsNew() {
		return isNew == 1;
	}

	public void setIsNew(boolean isNew) {
		this.isNew = (byte) (isNew ? 1 : 0);
	}

	public boolean getIsAck() {
		return isAck == 1;
	}

	public void setIsAck(boolean isAck) {
		this.isAck = (byte) (isAck ? 1 : 0);
	}
    
    
    
}
