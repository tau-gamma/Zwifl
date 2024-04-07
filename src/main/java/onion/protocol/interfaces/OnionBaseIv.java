package onion.protocol.interfaces;

import java.nio.ByteBuffer;

import onion.protocol.OnionPublicMessageType;

public interface OnionBaseIv {
	byte[] getIv();
	void send(ByteBuffer out);
	short getCircId();
	OnionPublicMessageType getPublicType();
}
