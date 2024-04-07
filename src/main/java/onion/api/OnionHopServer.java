package onion.api;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import org.ini4j.ConfigParser.InterpolationException;
import org.ini4j.ConfigParser.NoOptionException;
import org.ini4j.ConfigParser.NoSectionException;

import onion.ConfigFrame;
import onion.ConnectionGlue;
import onion.DataSplitter;
import onion.Utility;
import onion.protocol.KnouflException;
import onion.protocol.OnionAESEncryptedMessage;
import onion.protocol.OnionBaseMessage;
import onion.protocol.OnionCoverTrafficMessage;
import onion.protocol.OnionDataMessage;
import onion.protocol.OnionExtendMessage;
import onion.protocol.OnionKeyExchangeMessage;
import onion.protocol.OnionKeyExchangeSuccessMessage;
import onion.protocol.OnionPublicMessageType;
import onion.protocol.OnionRSAEncryptedMessage;
import onion.protocol.OnionSwitchMessage;
import onion.protocol.OnionTunnelTeardownMessage;
import onion.protocol.interfaces.OnionDataSender;
import onion.security.SSLSocketUtility;
import onion.security.SymmetricEncryption;

public class OnionHopServer implements OnionDataSender {
	
	private List<ConnectionGlue> allConnections = Collections.synchronizedList(new ArrayList<ConnectionGlue>());
	private ConcurrentHashMap<Integer, ConnectionGlue> uidMapping = new ConcurrentHashMap<>();
	private ConcurrentHashMap<Short, Short> circIdMapping = new ConcurrentHashMap<>();
	private ConfigFrame config;
	private DataSplitter dataSplitter;
	private ServerSocket serverSocket;
	private SSLSocketUtility sslSocketUtility; 
	
	private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	

	public OnionHopServer(ConfigFrame config, OnionAPInterface apiInterface) {
		this.config = config;
		this.dataSplitter = new DataSplitter(apiInterface);
		this.sslSocketUtility = new SSLSocketUtility(config.getSslConfig());
	}

	public void start(ConfigFrame config) throws NoSectionException, NoOptionException, InterpolationException, IOException, KnouflException {
		logger.info("Starting OnionHop at port " + config.getListenAddress().getPort());
		try {
			serverSocket = new ServerSocket(config.getListenAddress().getPort());
		} catch (NoSuchElementException | IOException e) {
			throw new KnouflException("Failed to start serverSocket in OnionHopServer: " + e.getMessage());
		}
		new Thread(new Runnable() {
			
			@Override
			public void run() {
					
				while (serverSocket != null && !serverSocket.isClosed()) {
					try {
						Socket client = OnionHopServer.this.sslSocketUtility.convertToSSLSocket(serverSocket.accept());
						try {
							logger.fine("Accepted client");
							ConnectionGlue c = new ConnectionGlue(client);
							allConnections.add(c);
							startClientThread(c);
						} catch (Exception e) {
							logger.warning("Failed to serve peer-client: " + e.getMessage());
						}
					} catch (Exception e1) {;}
				}
			}
		}).start();
		
	}
	
	public void stop() throws IOException {
		serverSocket.close();
	}

	private void startClientThread(ConnectionGlue c) {
		new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					while(true) {
						handleClient(c);
					}
				} catch (Exception e) {
					logger.warning("Error in handle client: " + e.getMessage());
					try {
						c.getSocket().close();
					} catch (IOException e1) {
						logger.warning("Failed to close connection: " + e1.getMessage());
					}
					try {
						if (c.getHusband() != null)
							c.getHusband().getSocket().close();
					} catch (Exception e2) {
						logger.warning("Failed to close husband connection: " + e2.getMessage());
					}
				}
			}
		}).start();

	}

	private void handleClient(ConnectionGlue client) throws Exception {
		byte[] buffer = new byte[OnionBaseMessage.ONION_MAX_LENGTH];
		int length = -1;
		length = client.getSocket().getInputStream().read(buffer);
		logger.fine(client.getCircID() + " Got first byte, starting to read");
		if (length == -1)
			throw new KnouflException("Stream closed");
		if (length != OnionBaseMessage.ONION_MAX_LENGTH)
			throw new KnouflException("packet too small");
		//TODO React to state for aes key
		OnionBaseMessage msg = OnionBaseMessage.parse(ByteBuffer.wrap(buffer), client.getAes(), config.getPrivateKey());
		logger.fine(client.getCircID() + "Got message");
		if(msg instanceof OnionKeyExchangeMessage) {
			handleOnionKeyExchangeMessage((OnionKeyExchangeMessage) msg, client);
		} else if(msg instanceof OnionExtendMessage) {
			handleOnionExtendedMessage((OnionExtendMessage) msg, client);
		} else if(msg instanceof OnionAESEncryptedMessage) {
			handleOnionAESEncryptedMessage((OnionAESEncryptedMessage) msg, client);
		} else if(msg instanceof OnionDataMessage) {
			handleOnionDataMessage((OnionDataMessage) msg, client);
		} else if(msg instanceof OnionSwitchMessage) {
			handleOnionSwitchMessage((OnionSwitchMessage) msg, client);
		} else if(msg instanceof OnionCoverTrafficMessage) {
			handleOnionCoverTrafficMessage((OnionCoverTrafficMessage) msg, client);
		} else if(msg instanceof OnionTunnelTeardownMessage) {
			handleOnionTunnelTeardownMessage((OnionTunnelTeardownMessage) msg, client);
		} else {
			throw new KnouflException(client.getCircID() + "Unknown MessageType");
		}
	}
	
	private void handleOnionSwitchMessage(OnionSwitchMessage msg, ConnectionGlue client) throws Exception {
		logger.fine("Got a OnionSwitchMessage");
		if(msg.getIsNew()){
			logger.fine("NEW TUNNEL" +  client.getCircID());
			ConnectionGlue oldConnection = uidMapping.get(msg.getUid());
			 if(oldConnection == null)
				 throw new KnouflException("Tunnelswitch failed because old tunnel could not be found");
			 
			 
			 short circID = circIdMapping.get(oldConnection.getCircID());
			 circIdMapping.remove(oldConnection.getCircID());
			 
			 circIdMapping.put(client.getCircID(), circID);
			 OnionAESEncryptedMessage encryptedMsg = SymmetricEncryption.encryptMessage(new OnionSwitchMessage(client.getCircID(), false, true, 0), client.getAes());
			 send(client.getSocket(), encryptedMsg);//respond with ACK
			 logger.fine("Responded to OnionSwitchMessage with ACK");
		}else{
			logger.fine("OLD TUNNEL" +  client.getCircID());
			uidMapping.put(msg.getUid(), client);
		}
	}

	private void handleOnionTunnelTeardownMessage(OnionTunnelTeardownMessage msg, ConnectionGlue client) throws IOException  {
		logger.fine("Got a OnionTunnelTeardownMessage for circId: " + msg.getCircId() );
		if(client.getHusband() != null){
			ConnectionGlue husband = client.getHusband();
			msg.setCircId(husband.getCircID());
			send(husband.getSocket(), msg);
			husband.getSocket().close();
			allConnections.remove(husband);
		}
		client.getSocket().close();
		allConnections.remove(client);
	}

	/**
	 * Is called from module-direction
	 */
	@Override
	public void destroyTunnel(short circId) throws IOException, KnouflException {
		circId = findCircIdToTunnelId(circId);
		OnionTunnelTeardownMessage msg = new OnionTunnelTeardownMessage(circId);
		handleOnionTunnelTeardownMessage(msg, findConnectionWithHusbandNotNull(circId));
		
	}

	private void handleOnionCoverTrafficMessage(OnionCoverTrafficMessage msg, ConnectionGlue client) {
		logger.fine("Got cover Message from " + client.getCircID());
	}

	/**
	 * Comming from tunnel-direction, going to module
	 * @param msg
	 * @param client
	 * @throws Exception
	 */
	private void handleOnionDataMessage(OnionDataMessage msg, ConnectionGlue client) throws Exception {
		msg.setCircId(client.getCircID());
		this.replaceCircIdWithTunnelID(msg);
		this.dataSplitter.receiveData(msg);
	}

	private void replaceCircIdWithTunnelID(OnionDataMessage msg) {
		circIdMapping.putIfAbsent(msg.getCircId(), Utility.getRandomShort());  
		msg.setCircId(circIdMapping.get(msg.getCircId()));
	}
	
	private void replaceTunnelWithCircuitID(OnionBaseMessage msg) throws KnouflException{
		msg.setCircId(findCircIdToTunnelId(msg.getCircId()));
	}

	private short findCircIdToTunnelId(short circId) throws KnouflException {
		for (Entry<Short, Short> entry : circIdMapping.entrySet()) {
			if(entry.getValue().equals(circId)){
				return entry.getKey();
			}
		}
		throw new KnouflException("No circID found for tunnelID");
	}

	private void handleOnionAESEncryptedMessage(OnionAESEncryptedMessage msg, ConnectionGlue client) throws Exception {
		logger.fine(" ----------- Got AESEncryptedMessage fromm " + msg.getCircId() + " " + client.getCircID() +"Forwarding to next hop " + (client.getHusband() == null ? "null" : ""+client.getHusband().getCircID()));
		if(client.isIncoming()){ 
			logger.fine(" ----------- Got AESEncryptedMessage from " + msg.getCircId() + " " + client.getCircID() + "Forwarding to next hop " + (client.getHusband() == null ? "null" : ""+client.getHusband().getCircID()));
			msg.setCircId(client.getHusband().getCircID());
			send(client.getHusband().getSocket(), msg);
		}else{
			if(msg.isMessageAtDestination()){
				throw new KnouflException("Unexpected behaviour!");
			}else{
				logger.fine(" ----------- Got AESEncryptedMessage from " + msg.getCircId() + " " + client.getCircID() +" Backwarding to prev hop " + (client.getHusband() == null ? "null" : ""+client.getHusband().getCircID()));
				msg.setCircId(client.getHusband().getCircID());
				OnionAESEncryptedMessage enc = SymmetricEncryption.encryptMessage(msg, client.getAes());
				enc = SymmetricEncryption.encryptMessage(enc, client.getAes());
				send(client.getHusband().getSocket(), enc);
			}
		}
	}

	private void handleOnionExtendedMessage(OnionExtendMessage msg, ConnectionGlue client) throws Exception {
		logger.fine("Received Onion Extend Message");
		createTCPConnection(msg, client);
		
	}

	private void createTCPConnection(OnionExtendMessage msg, ConnectionGlue client) throws Exception {
		Socket socket = sslSocketUtility.getSSLSocket(msg.getDestAddress(), msg.getDestPort()); 
		ConnectionGlue newConnection = new ConnectionGlue(socket, client);
		newConnection.setCircID(Utility.getRandomShort());
		allConnections.add(newConnection);
		
		OnionRSAEncryptedMessage encryptedMessage = new OnionRSAEncryptedMessage(newConnection.getCircID(), OnionPublicMessageType.KEY_EXCHANGE, msg.getRsaEncryptedSecretKey());
		send(socket, encryptedMessage);
		
		startClientThread(newConnection);
	}
	
	private void send(Socket socket, OnionBaseMessage msg) throws IOException{
		logger.fine(socket.getPort()+" Sent Message" );
		
		DataOutputStream out = new DataOutputStream(socket.getOutputStream());
		out.write(Utility.messageToArray(msg));
	}

	private void handleOnionKeyExchangeMessage(OnionKeyExchangeMessage exchangeMsg, ConnectionGlue client) throws Exception{
		client.setCircID(exchangeMsg.getCircId());
		client.setAes(exchangeMsg.getSecretKey());
		circIdMapping.putIfAbsent(client.getCircID(), client.getCircID());
		
		
		OnionKeyExchangeSuccessMessage response = new OnionKeyExchangeSuccessMessage(exchangeMsg.getCircId());
		byte[] msgBytes = Utility.messageToArray(response);
		
		logger.fine("Concstructing response message: OnionKeyExchangeSuccessMessage " + Arrays.toString(msgBytes) + "enc with " + Arrays.toString(exchangeMsg.getSecretKey().getEncoded()));
		OnionAESEncryptedMessage encryptedMsg = SymmetricEncryption.encryptMessage(response, exchangeMsg.getSecretKey());
		
		send(client.getSocket(), encryptedMsg);
	}
	
	/**
	 * Is called for module-direction
	 */
	@Override
	public void sendData(OnionDataMessage msg) throws Exception{
		replaceTunnelWithCircuitID(msg);
		ConnectionGlue glue = findConnectionWithHusbandNull(msg.getCircId());
		OnionAESEncryptedMessage encryptedMsg = SymmetricEncryption.encryptMessage(msg, glue.getAes());
		send(glue.getSocket(), encryptedMsg);
	}

	private ConnectionGlue findConnectionWithHusbandNotNull(short circId) throws KnouflException {
		for (ConnectionGlue connectionGlue : allConnections) {
			if(connectionGlue.getCircID() == circId) {
				return connectionGlue;
			}
		}
		throw new KnouflException("The connection with " + circId  + " as tunnelID was not found");
	}
	
	private ConnectionGlue findConnectionWithHusbandNull(short circId) throws KnouflException {
		for (ConnectionGlue connectionGlue : allConnections) {
			if(connectionGlue.getCircID() == circId && connectionGlue.getHusband() == null) {
				return connectionGlue;
			}
		}
		throw new KnouflException("The connection with " + circId  + " as tunnelID was not found");
	}
	
	@Override
	public boolean knowsTunnel(short circId) {
		try {
			return findConnectionWithHusbandNull(findCircIdToTunnelId(circId)) != null;
		} catch (KnouflException e) {
			return false;
		}
	}
	
	

}
