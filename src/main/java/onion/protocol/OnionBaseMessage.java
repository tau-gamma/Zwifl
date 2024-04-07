package onion.protocol;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.SecretKey;

public class OnionBaseMessage {
	
	public final static int ONION_MAX_LENGTH = 512;

	private short circId;
	private OnionPublicMessageType publicType;
	
	protected OnionBaseMessage(short circId, OnionPublicMessageType publicType) {
		this.circId = circId;
		this.publicType = publicType;
	}

	public void send(ByteBuffer out) {
		out.putShort(this.circId);
		out.putShort((short) this.publicType.getNumVal());
	}

	public int getMessageLength() {
		return 2 // circId
			 + 2; // publicType
	}

	public short getCircId() {
		return circId;
	}

	public void setCircId(short circId) {
		this.circId = circId;
	}

	public OnionPublicMessageType getPublicType() {
		return publicType;
	}

	public void setPublicType(OnionPublicMessageType publicType) {
		this.publicType = publicType;
	}
	
	public static OnionBaseMessage parse(ByteBuffer buffer, SecretKey aes, RSAPrivateKey rsa) throws Exception {
		short circId = buffer.getShort();
		OnionPublicMessageType type = OnionPublicMessageType.fromValue(buffer.getShort());
		OnionBaseMessage baseMessage = new OnionBaseMessage(circId, type);
		switch (type) {
		case PRIVATE:
			return OnionAESEncryptedMessage.parse(buffer, baseMessage, aes);
		case KEY_EXCHANGE:
			return OnionRSAEncryptedMessage.parse(buffer, baseMessage, rsa); 
		case TEARDOWN_TUNNEL:
			return OnionTunnelTeardownMessage.parse(buffer, baseMessage);
		default:
			return baseMessage;
		}
		
	}

}
