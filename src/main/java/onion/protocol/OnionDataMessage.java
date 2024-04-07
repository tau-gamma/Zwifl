package onion.protocol;

import java.nio.ByteBuffer;
import java.util.Arrays;

import onion.Utility;

public class OnionDataMessage extends OnionPrivateMessage {
	private short fileIdentifier;
	private short position;
	private byte[] data;
	
	public OnionDataMessage(short circId, short fileIdentifier, short position, byte[] data) throws KnouflException {
		super(circId, OnionPrivateMessageType.DATA);
		if(data != null && data.length + super.getMessageLength() > OnionBaseMessage.ONION_MAX_LENGTH)
			throw new KnouflException("Data size too big, max allowed size is: " + (OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength() - 2 /*for size*/));
		this.data = data;
		this.fileIdentifier = fileIdentifier;
		this.position = position;
	}
	
	public OnionDataMessage() {
		super((short) 0, OnionPrivateMessageType.DATA);
	}
	
	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public short getSize() {
		return (short)data.length;
	}
	
	@Override
	public int getMessageLength() {
		return super.getMessageLength()
				+ 2 // for size 
				+ 2 //fileIdentifier
				+ 2; //position;
				
	}


	/**
	 * Only 
	 * @param payload Only payload of message! without headers
	 * @return OnionDataMessage with circId set to -1
	 * @throws KnouflException
	 */
	public static OnionDataMessage parse(ByteBuffer payload, OnionAESEncryptedMessage msg) throws KnouflException {
		int maxLength = (OnionBaseMessage.ONION_MAX_LENGTH - 32 - 4); // 4 public header + 12 reserved + 16iv + 4 private header
		if(payload.remaining() != maxLength) //TODO should this be variable?
			throw new KnouflException("Onion message has wrong size: expected size" + maxLength + ", but got " + payload.remaining());
		
		short length = payload.getShort();
		short fileIdentifier = payload.getShort();
		short position = payload.getShort();
		
		byte[] data = new byte[length];
		payload.get(data);
		
		return new OnionDataMessage(msg.getCircId(), fileIdentifier, position, data);
	}
	
    @Override
	public void send(ByteBuffer out) {
    	super.send(out);
    	out.putShort(getSize());
    	out.putShort(fileIdentifier);
    	out.putShort(position);
    	out.put(data);
    	// Add padding
    	int padLength = OnionBaseMessage.ONION_MAX_LENGTH - getMessageLength() - getSize();
    	Utility.addRandomPadding(out, padLength);
    }

	public short getFileIdentifier() {
		return fileIdentifier;
	}

	public void setFileIdentifier(short fileIdentifier) {
		this.fileIdentifier = fileIdentifier;
	}

	public short getPosition() {
		return position;
	}

	public void setPosition(short position) {
		this.position = position;
	}

	@Override
	public String toString() {
		return "OnionDataMessage [fileIdentifier=" + fileIdentifier + ", position=" + position + ", dataSize=" + data.length + ", data=" + Arrays.toString(data) + "]";
	}
	
}
