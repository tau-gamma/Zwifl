package onion.api;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.ini4j.ConfigParser.InterpolationException;
import org.ini4j.ConfigParser.NoOptionException;
import org.ini4j.ConfigParser.NoSectionException;

import onion.APIConnection;
import onion.ConfigFrame;
import onion.DataSplitter;
import onion.OnionLogger;
import onion.protocol.KnouflException;
import onion.protocol.OnionBaseMessage;
import onion.protocol.interfaces.OnionDataReceiver;
import onion.protocol.interfaces.OnionDataSender;
import protocol.Message;
import protocol.Protocol;
import rps.RpsConfigurationImpl;
import rps.api.RpsPeerMessage;
import rps.api.RpsQueryMessage;

public class OnionAPInterface implements OnionDataReceiver{
	
	public static int PEER_SEARCH_TIMEOUT = 5000;
	private ConfigFrame config;
	private RpsConfigurationImpl rpsConfig;
	private OnionApiHandler apiHandler;
	private OnionHopServer hopServer;
	private ServerSocket onionSocket;
	
	private List<APIConnection> apiConnections = new ArrayList<>();

	private static final Logger logger = Logger.getLogger(OnionAPInterface.class.getName());
	
	public OnionAPInterface(String path) throws Exception {
		this.config = new ConfigFrame(path);
		this.rpsConfig = new RpsConfigurationImpl(path);
		apiHandler = new OnionApiHandler(this.config, rpsConfig, this);
		hopServer = new OnionHopServer(this.config, this);
	}
	
	public void start() throws KnouflException {
		OnionLogger.setup();
		logger.info("Starting API Interface at port " + config.getAPIAddress().getPort());
		
		try {
			this.hopServer.start(config);
		} catch (NoSectionException | NoOptionException | InterpolationException | IOException e) {
			logger.warning("Failed to start HopServer: " + e.getMessage());
			throw new RuntimeException();
		}
		
		try {
			this.onionSocket = new ServerSocket(config.getAPIAddress().getPort());
		} catch (Exception e) {
			logger.warning("Failed to start onion API socket: " + e.getMessage());
			throw new RuntimeException();
		}

		new Thread(new Runnable() {
			
			@Override
			public void run() {
				while (onionSocket != null && !onionSocket.isClosed()) {
				Socket client;
				try {
					client = onionSocket.accept();
					try {
						APIConnection apiConnection = new APIConnection(client);
						apiConnections.add(apiConnection);
						logger.fine("Accepted API client");
						startClientThread(apiConnection);
					} catch (Exception e) {
						logger.warning("Failed to serve client: " + e.getMessage());
					}
				} catch (IOException e1) {}
				}
			}
		}).start();
	}
	
	public void stop() {
			
		try {
			hopServer.stop();
		} catch (Exception e) {
			logger.warning("Failed to stop HopServer" + e.getMessage());
		}
		try {
			onionSocket.close();
			onionSocket = null;
		} catch (Exception e) {
			logger.warning("Failed to stop APIInterface" + e.getMessage());
		}
	}

	private void startClientThread(final APIConnection apiConnection) {
		new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					while (true) {

						handleClient(apiConnection);

					}

				} catch (Exception e) {
					logger.warning("Client did something wrong, connection will be closed: " + e.getMessage());
					removeClient(apiConnection);
				}
			}
		}).start();

	}

	private void handleClient(APIConnection client) throws Exception {
		Message request = getApiMessage(client.getSocket());
		if (request instanceof OnionTunnelBuildMessage) {
			try {
				handleTunnelBuildMessage(client, (OnionTunnelBuildMessage) request);
			} catch (Exception e) {
				logger.warning("Error building tunnel. Sending error message: " + e.getMessage());
				client.sendErrorMessage((short) 0, Protocol.MessageType.API_ONION_TUNNEL_BUILD);
			}
			
		} else if (request instanceof OnionTunnelDataMessage) {
			try {
				handleTunnelSendData((OnionTunnelDataMessage)request);
			} catch (Exception e) {
				logger.warning("Error sending tunnel data. Sending error message: " + e.getMessage());
				client.sendErrorMessage((short) ((OnionTunnelDataMessage)request).getId(), Protocol.MessageType.API_ONION_TUNNEL_DATA);
			}
			
		} else if (request instanceof OnionTunnelDestroyMessage) {
			
			try {
				handleTunnelDestroy((OnionTunnelDestroyMessage) request, client);
			} catch (KnouflException | IOException e) {
				logger.warning("Error destroying tunnel. Sending error message: " + e.getMessage());
				client.sendErrorMessage((short) ((OnionTunnelDestroyMessage) request).getId(), Protocol.MessageType.API_ONION_TUNNEL_DESTROY);
			}
			
		} else if (request instanceof OnionCoverMessage) {
			try {
				handleOnionCover((OnionCoverMessage)request);
			} catch (Exception e) {
				logger.warning("Error destroying tunnel. Sending error message");
				client.sendErrorMessage((short) 0, Protocol.MessageType.API_ONION_COVER);
			}
		}

	}

	private void handleTunnelSendData(OnionTunnelDataMessage msg) throws Exception {
		OnionDataSender sender = getTunnelOwner((short) msg.getId());
		DataSplitter.sendData(msg, sender);
	}

	private void handleTunnelBuildMessage(APIConnection client, OnionTunnelBuildMessage msg)throws Exception {
		short tunnelId = apiHandler.tunnelBuild(msg.getAddress(), msg.getKey());
		logger.info("Succesfully build tunnel " + tunnelId);
		client.addTunnelToKown(tunnelId);
		OnionTunnelReadyMessage response = new OnionTunnelReadyMessage(tunnelId, msg.getEncoding());
		ByteBuffer buffer = ByteBuffer.allocate(response.getSize());
		response.send(buffer);
		client.getSocket().getOutputStream().write(buffer.array());
		logger.info("Responded with OnionTunnelReadyMessage");
	}

	private Message getApiMessage(Socket client) throws Exception {
		logger.fine("Waiting for API messages");

		DataInputStream dis = new DataInputStream(client.getInputStream());
		int length = dis.readChar();
		Protocol.MessageType type = Protocol.MessageType.asMessageType(dis.readChar());

		ByteBuffer buffer = ByteBuffer.allocate(length - 4);
		for (int i = 0; i < buffer.limit(); i++) {
			buffer.put(dis.readByte());
		}
		buffer.position(0);
		
		switch (type) {
			case API_ONION_TUNNEL_BUILD:
				return OnionTunnelBuildMessage.parse(buffer);
			case API_ONION_TUNNEL_DATA:
				return OnionTunnelDataMessage.parse(buffer);
			case API_ONION_TUNNEL_DESTROY:
				return OnionTunnelDestroyMessage.parse(buffer);
			case API_ONION_COVER:
				return OnionCoverMessage.parse(buffer);

		default:
			throw new KnouflException("Onion API cannot handle this type of request.");
		}
	}
	
	private void handleOnionCover(OnionCoverMessage msg) throws Exception {
		RpsPeerMessage randomDest = getRandomHop();
		
		short coverTunnelId = apiHandler.tunnelBuild(randomDest.getAddress(), randomDest.getHostkey());
		int coverSize = msg.getCoverSize();
		int numberPackets = (int) Math.ceil(coverSize / OnionBaseMessage.ONION_MAX_LENGTH);
		logger.fine("Should cover " + coverSize + ". Will send "+numberPackets+"cover messages");
		for (int i = 0; i < numberPackets; i++) {
			logger.fine("Tunnel Cover on TunnelId "+coverTunnelId + ". Sending " + (i+1) + " of " + numberPackets );
			this.apiHandler.sendCoverData(coverTunnelId);
		}
		apiHandler.destroyTunnel(coverTunnelId);
	}
	
	public void handleTunnelDestroy(OnionTunnelDestroyMessage msg, APIConnection client) throws KnouflException, IOException {
		short tunnelId = (short) msg.getId();
		client.unsubscribeFromTunnel(tunnelId);
		
		OnionDataSender owner = getTunnelOwner(tunnelId);
		if(owner instanceof OnionApiHandler) {
			//We created the tunnel, so no need to check if anybody cares about it
			owner.destroyTunnel(tunnelId);
			return;
		}
		boolean nobodyCaresAboutTunnel = this.apiConnections.stream()
											.map(c -> c.isUnsubscribedFromTunnel(tunnelId))
											.reduce(true,(isUnsubscribed, accumulator) -> accumulator && isUnsubscribed);
		
		if(owner instanceof OnionHopServer && nobodyCaresAboutTunnel) {
			owner.destroyTunnel(tunnelId);
		}
			
	}
	
	@Override
	public void notifyDataIncoming(OnionTunnelDataMessage msg) throws Exception {
		for (APIConnection apiConnection : apiConnections) {
			apiConnection.dataIncoming(msg);
		}

	}
	
	private OnionDataSender getTunnelOwner(short tunnelId) throws KnouflException {
		if(apiHandler.knowsTunnel(tunnelId))
			return apiHandler;
		if(hopServer.knowsTunnel(tunnelId))
			return hopServer;
		throw new KnouflException("Tunnel does not exist: "+tunnelId);
	}
	
	public RpsPeerMessage getRandomHop() throws Exception {

		Socket socket = new Socket(rpsConfig.getAPIAddress().getAddress(), rpsConfig.getAPIAddress().getPort());
		socket.setSoTimeout(PEER_SEARCH_TIMEOUT);
		RpsQueryMessage msg = new RpsQueryMessage();

		ByteBuffer b = ByteBuffer.allocate(msg.getSize());
		msg.send(b);
		socket.getOutputStream().write(b.array());

		DataInputStream dis = new DataInputStream(socket.getInputStream());
		int length = dis.readChar();
		ByteBuffer buffer = ByteBuffer.allocate(length - 4);

		if (Protocol.MessageType.asMessageType(dis.readChar()) == Protocol.MessageType.API_RPS_PEER) {
			for (int i = 0; i < buffer.limit(); i++) {
				buffer.put(dis.readByte());
			}
			buffer.position(0);
			socket.close();
			return RpsPeerMessage.parse(buffer);
		} else {
			socket.close();
			throw new KnouflException("RPS module did not respond with API_RPS_PEER");
		}
	}
	
	private void removeClient(APIConnection client) {
		client.closeConnection();
		this.apiConnections.remove(client);
		
	}
	
	public static void main(String[] args) throws Exception {
		String path = "D:\\git\\tum\\testing\\config\\peer-2.conf";
		
		int i = 0;
		if(i == 0) {
			path = "D:\\git\\tum\\testing\\config\\bootstrap.conf";
		}
		if(i == 1) {
			path = "D:\\git\\tum\\testing\\config\\peer-2.conf";
		}
		if(i == 2) {
			path = "D:\\git\\tum\\testing\\config\\peer-3.conf";
		}
		
		
		OnionAPInterface server = new OnionAPInterface(path);
		server.start();
	}

	public ConfigFrame getConfig() {
		return config;
	}

	

}