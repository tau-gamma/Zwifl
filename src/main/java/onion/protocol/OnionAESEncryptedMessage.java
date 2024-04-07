package onion.protocol;

import java.nio.ByteBuffer;

import javax.crypto.SecretKey;

import onion.protocol.interfaces.OnionBaseIv;
import onion.security.SymmetricEncryption;

public class OnionAESEncryptedMessage extends OnionBaseMessage implements OnionBaseIv{
	
	private byte[] iv;
	private byte[] payload;
	
	public OnionAESEncryptedMessage(short circId, OnionPublicMessageType publicType, byte[] iv, byte[] payload) {
		super(circId, publicType);
		this.iv = iv;
		this.payload = payload;
	}
	
	@Override
	public void send(ByteBuffer out) {
		super.send(out);
    	byte[] reserved = new byte[12];
    	out.put(reserved);
		out.put(iv);
		out.put(payload);
	}

	public byte [] getPayload() {
		return payload;
	}

	public void setPayload(byte [] payload) {
		this.payload = payload;
	}

	@Override
	public byte [] getIv() {
		return iv;
	}

	public void setIv(byte [] iv) {
		this.iv = iv;
	}
	
	public boolean isMessageAtDestination() {
		ByteBuffer b = ByteBuffer.wrap(payload);
		return b.getShort() == OnionPrivateMessage.DESTINATION_CODE;
	}

	public static OnionBaseMessage parse(ByteBuffer buffer, OnionBaseMessage onionBaseMessage, SecretKey aes) throws Exception {
		byte[] reserved = new byte[12];
		buffer.get(reserved);
		byte [] iv = new byte [16];
		buffer.get(iv);
		byte [] encryptedPayload = new byte [buffer.remaining()];
		buffer.get(encryptedPayload);
		OnionAESEncryptedMessage decrypted = SymmetricEncryption.decryptMessage(new OnionAESEncryptedMessage(onionBaseMessage.getCircId(), onionBaseMessage.getPublicType(), iv, encryptedPayload), aes);
		if(decrypted.isMessageAtDestination()) {
			ByteBuffer decBuffer = ByteBuffer.allocate(OnionBaseMessage.ONION_MAX_LENGTH);
			decrypted.send(decBuffer);
			decBuffer.position(4 + 12 + 16 + 2);
			return OnionPrivateMessage.parse(decBuffer, decrypted);
		}
		return decrypted;
	}
}
