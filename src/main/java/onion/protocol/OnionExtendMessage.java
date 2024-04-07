package onion.protocol;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;

import onion.Utility;

public class OnionExtendMessage extends OnionPrivateMessage {

	private byte[] rsaEncryptedSecretKey;
	private InetAddress destAddress;
	private short destPort;

	public InetAddress getDestAddress() {
		return destAddress;
	}

	public void setDestAddress(InetAddress destAddress) {
		this.destAddress = destAddress;
	}

	public short getDestPort() {
		return destPort;
	}

	public void setDestPort(short destPort) {
		this.destPort = destPort;
	}

	public OnionExtendMessage(short circId, byte[] rsaEncryptedSecretKey, InetAddress destAddress, short destPort) throws KnouflException {
			super(circId, OnionPrivateMessageType.EXTEND);
			if(rsaEncryptedSecretKey.length != OnionRSAEncryptedMessage.RSA_ENCRYPTED_LENGTH)
				throw new KnouflException("rsaEncryptedSecretKey must be of length " + OnionRSAEncryptedMessage.RSA_ENCRYPTED_LENGTH);
			this.rsaEncryptedSecretKey = rsaEncryptedSecretKey;
			this.destAddress = destAddress;
			this.destPort = destPort;
			
		}

	public byte[] getRsaEncryptedSecretKey() {
		return rsaEncryptedSecretKey;
	}

	public void setRsaEncryptedSecretKey(byte[] rsaEncryptedSecretKey) {
		this.rsaEncryptedSecretKey = rsaEncryptedSecretKey;
	}

	public static OnionExtendMessage parse(ByteBuffer buffer, OnionAESEncryptedMessage baseMessage) throws Exception {
		byte[] encryptedKey = new byte[OnionRSAEncryptedMessage.RSA_ENCRYPTED_LENGTH];
		buffer.get(encryptedKey);
		short port  = buffer.getShort();
		byte[] addressBytes;
		if (buffer.get() == 4) {
			addressBytes = new byte[4];
		} else {
			addressBytes = new byte[16];
		}
		InetAddress address = InetAddress.getByAddress(addressBytes);

		return new OnionExtendMessage(baseMessage.getCircId(), encryptedKey, address, port);
	}

	@Override
	public void send(ByteBuffer out) {
		super.send(out);
		out.put(rsaEncryptedSecretKey);
		out.putShort(this.destPort);
		if (this.destAddress instanceof Inet6Address) {
		   out.put((byte) 6);
		} else if (this.destAddress instanceof Inet4Address) {
			out.put((byte) 4);
		}
		out.put(this.destAddress.getAddress());
		// Add padding
		
		int padLength = OnionBaseMessage.ONION_MAX_LENGTH - super.getMessageLength() - rsaEncryptedSecretKey.length - 2/*port*/ - 1/*version flag*/ - this.destAddress.getAddress().length;
		Utility.addRandomPadding(out, padLength);
	}

}
