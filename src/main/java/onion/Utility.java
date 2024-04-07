package onion;

import java.nio.ByteBuffer;
import java.util.Random;

import onion.protocol.OnionBaseMessage;

public class Utility {
	
	public static byte[] messageToArray(OnionBaseMessage msg) {
		ByteBuffer b = ByteBuffer.allocate(OnionBaseMessage.ONION_MAX_LENGTH);
		msg.send(b);
		return b.array();
	}
	
	public static short getRandomShort() {
		return (short) new Random().nextInt(Short.MAX_VALUE + 1);
	}
	
	public static void addRandomPadding(ByteBuffer out, int length) {
    	byte[] padding = new byte[length];
//    	SecureRandom r = new SecureRandom();
//    	r.nextBytes(padding);
//    	
    	out.put(padding);
	}

}
