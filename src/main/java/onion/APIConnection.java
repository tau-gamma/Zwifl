package onion;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import onion.api.OnionErrorMessage;
import onion.api.OnionTunnelDataMessage;
import onion.api.OnionTunnelIncomingMessage;
import protocol.MessageSizeExceededException;
import protocol.Protocol;

public class APIConnection {
	
	private Set<Short> unsubscribedTunnels = new HashSet<>();
	private Set<Short> knownTunnels = new HashSet<>();
	
	private Socket socket;
	
	private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	public APIConnection(Socket socket) {
		this.socket = socket;
	}
	
	public void dataIncoming(OnionTunnelDataMessage msg) throws MessageSizeExceededException {
		short tunnelId = (short)msg.getId();
		
		if(!knownTunnels.contains(tunnelId))
			notifyTunnelIncoming(tunnelId);
		
		if(unsubscribedTunnels.contains(tunnelId))
			return;
		logger.info("notifying about "+new String(msg.getData()) + " --> " + getSocket().getPort());
		notifyDataIncoming(msg);
		
	}
	
	private void notifyDataIncoming(OnionTunnelDataMessage msg) throws MessageSizeExceededException {
		
		ByteBuffer buffer = ByteBuffer.allocate(msg.getSize());
		msg.send(buffer);
		try {
			socket.getOutputStream().write(buffer.array());
		} catch (IOException e) {
			logger.warning("Failed to notify api-client about incoming data: " + e.getMessage());
		}
	}
	
	public void notifyTunnelIncoming(short tunnelId) {
		OnionTunnelIncomingMessage notifyMsg = new OnionTunnelIncomingMessage(tunnelId);
		ByteBuffer buffer = ByteBuffer.allocate(notifyMsg.getSize());
		notifyMsg.send(buffer);
		try {
			socket.getOutputStream().write(buffer.array());
			logger.fine("Notified Tunnel Incoming ID " + tunnelId + " to client " + socket.getPort());
		} catch (IOException e) {
			logger.warning("Failed to notify api-client about incoming tunnel: " + e.getMessage());
		}
		knownTunnels.add(tunnelId);
	}
	
	public void sendErrorMessage(short tunnelId, Protocol.MessageType type) {
		OnionErrorMessage msg = new OnionErrorMessage(type, tunnelId);
		ByteBuffer buffer = ByteBuffer.allocate(msg.getSize());
		msg.send(buffer);
		try {
			socket.getOutputStream().write(buffer.array());
		} catch (IOException e) {
			logger.warning("Failed to deliver error message to api-client: " + e.getMessage());
		}
	}
	
	public void closeConnection() {
		try {
			this.socket.close();
		} catch (IOException e) {
			logger.warning("Failed to close api-client connection: " + e.getMessage());
		}
	}

	public Socket getSocket() {
		return socket;
	}
	
	public void addTunnelToKown(short tunnelId) {
		this.knownTunnels.add(tunnelId);
	}
	
	public void unsubscribeFromTunnel(short tunnelId) {
		this.unsubscribedTunnels.add(tunnelId);
	}
	
	public boolean isUnsubscribedFromTunnel(short tunnelId) {
		return this.unsubscribedTunnels.contains(tunnelId);
	}

}
