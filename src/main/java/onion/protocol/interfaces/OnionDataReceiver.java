package onion.protocol.interfaces;

import onion.api.OnionTunnelDataMessage;

public interface OnionDataReceiver {
	public void notifyDataIncoming(OnionTunnelDataMessage msg) throws Exception;
}
