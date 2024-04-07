package onion.protocol;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import onion.protocol.interfaces.OnionBaseIv;

public class OnionPrivateMessage extends OnionBaseMessage implements OnionBaseIv {
	
	public static short DESTINATION_CODE = (short) 0xB00B;
	
	
    private OnionPrivateMessageType privateType;
    private short destCheck = DESTINATION_CODE;
    private byte[] iv = new byte[16];
    
    public OnionPrivateMessage(short circId, OnionPrivateMessageType privateType) {
		super(circId, OnionPublicMessageType.PRIVATE);
		this.privateType = privateType;
		
		//Generate secure random IV
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
	}
    

	public OnionPrivateMessageType getPrivateType() {
		return privateType;
	}

	public void setPrivateType(OnionPrivateMessageType privateType) {
		this.privateType = privateType;
	}

	public short getDestCheck() {
		return destCheck;
	}

	public void setDestCheck(short destCheck) {
		this.destCheck = destCheck;
	}
	
    @Override
	public void send(ByteBuffer out) {
    	super.send(out);
    	byte[] reserved = new byte[12];
    	out.put(reserved); // this part is not encrypted!
    	out.put(iv);
        out.putShort(this.destCheck);
        out.putShort((short)this.privateType.getNumVal());
    }
    
	@Override
	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}
	
	@Override
	public int getMessageLength() {
		return super.getMessageLength() 
				+ 2 //privateType
				+ 12 // reserved
				+ 2 //destCheck
				+ 16; //iv 
	}

	public static OnionPrivateMessage parse(ByteBuffer buffer, OnionAESEncryptedMessage decrypted) throws Exception {
		OnionPrivateMessageType type = OnionPrivateMessageType.fromValue(buffer.getShort());
		switch (type) {
			case DATA:
				return OnionDataMessage.parse(buffer, decrypted);
			case KEY_EXCHANGE_SUCCESS:
				return OnionKeyExchangeSuccessMessage.parse(buffer, decrypted);
			case EXTEND:
				return OnionExtendMessage.parse(buffer, decrypted);
			case COVER:
				return OnionCoverTrafficMessage.parse(buffer, decrypted);
			case SWITCH:
				return OnionSwitchMessage.parse(buffer, decrypted);
		}
		throw new KnouflException("Private Type unknown");
	}
	
    
}
