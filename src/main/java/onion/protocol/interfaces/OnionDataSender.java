package onion.protocol.interfaces;

import java.io.IOException;

import onion.protocol.KnouflException;
import onion.protocol.OnionDataMessage;

public interface OnionDataSender {
	public void sendData(OnionDataMessage msg) throws Exception;
	public boolean knowsTunnel(short tunnelId);
	public void destroyTunnel(short circId) throws IOException, KnouflException;
}
