package onion.api;


import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import onion.ConfigFrame;
import onion.DataSplitter;
import onion.OnionCircuit;
import onion.Utility;
import onion.protocol.KnouflException;
import onion.protocol.OnionAESEncryptedMessage;
import onion.protocol.OnionBaseMessage;
import onion.protocol.OnionCoverTrafficMessage;
import onion.protocol.OnionDataMessage;
import onion.protocol.OnionExtendMessage;
import onion.protocol.OnionKeyExchangeMessage;
import onion.protocol.OnionKeyExchangeSuccessMessage;
import onion.protocol.OnionRSAEncryptedMessage;
import onion.protocol.OnionSwitchMessage;
import onion.protocol.OnionTunnelTeardownMessage;
import onion.protocol.interfaces.OnionBaseIv;
import onion.protocol.interfaces.OnionDataSender;
import onion.security.SSLSocketUtility;
import onion.security.SymmetricEncryption;
import onion.security.SymmetricKeyExchange;
import rps.RpsConfigurationImpl;
import rps.api.RpsPeerMessage;

public class OnionApiHandler implements OnionDataSender{

	DataSplitter dataSplitter;
	
	private Map<Short, OnionCircuit> circuits = new HashMap<>();
	private Map<Short, Short> tunnelIdToCircId = new ConcurrentHashMap<>();
	private ConfigFrame config;
	private OnionAPInterface apiInterface;
	private RpsConfigurationImpl rpsConfig;
	private SSLSocketUtility sslSocketUtility;
	
	private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

	public OnionApiHandler(ConfigFrame config, RpsConfigurationImpl rpsConfig, OnionAPInterface apiInterface) {
		this.config = config;
		this.apiInterface = apiInterface;
		this.rpsConfig = rpsConfig;
		this.dataSplitter = new DataSplitter(apiInterface);
	}
	
	private SSLSocketUtility getSslSocketUtility(){
		if(sslSocketUtility == null)
			this.sslSocketUtility = new SSLSocketUtility(config.getSslConfig());	
		return sslSocketUtility;
	}

	public short tunnelBuild(InetSocketAddress destinationAddress, RSAPublicKey destinationHostkey) throws Exception {
		short tunnelId = generateRandomCircId();
		this.tunnelIdToCircId.put(tunnelId, tunnelId);
		logger.info("Starting BuildTunnel. Tunnel will have ID " + tunnelId);
		
		RpsPeerMessage hop1 = apiInterface.getRandomHop();

		Socket hop1Socket = getSslSocketUtility().getSSLSocket(hop1.getAddress().getAddress(), hop1.getAddress().getPort());
		
		addCricuit(new OnionCircuit(tunnelId, hop1Socket, destinationAddress, destinationHostkey));
		
		SecretKey key1 = null;
		try {
			
			key1 = sendAESKeyToHop(hop1.getHostkey(), tunnelId);
		} catch (Exception e) {}
		getCircFromTunnelId(tunnelId).addKey(key1);
		logger.fine("Successfully exchanged key with fisrt hop: " + hop1.getAddress().toString());

		waitForExchangedSuccess(tunnelId);

		extendCircuit(config.getHopcount()-1, tunnelId);//-1 because we already contacted the first one
		logger.fine("Successfully exchanged keys with " + (config.getHopcount()-1) + " intermediate hops");
		
		RpsPeerMessage destinationHop = new RpsPeerMessage(destinationAddress, destinationHostkey);
		SecretKey key3 = extendToNextHop(destinationHop, tunnelId);
		getCircFromTunnelId(tunnelId).addKey(key3);
		waitForExchangedSuccess(tunnelId);
		logger.fine("Successfully exchanged key with destination: " + destinationHop.getAddress().toString());
		
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					startEventLoop(tunnelId);
				} catch (Exception e) {
					logger.warning("Error in eventloop: " + e.getMessage());
				}
			}
		}).start();
		
		startSwitchThread(tunnelId);
		
		return tunnelId;
	}
	
	private void startSwitchThread(short circId) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					Thread.sleep(config.getTimePeriod() * 1000);//TODO end when 
					switchTunnel(getTunnelIdFromCircId(circId));
				} catch (Exception e) {
					logger.warning("Error switching circuit : " + e.getMessage());
				}
			}
		}).start();
		
	}

	private void startEventLoop(short tunnelId) throws Exception {
		logger.fine("Starting eventloop");
		Socket client = getCircFromTunnelId(tunnelId).getSocket();
		//TODO stop when circuit destroyed
		while(true){
			byte[] buffer = new byte[OnionBaseMessage.ONION_MAX_LENGTH];
			int length = -1;
			length = client.getInputStream().read(buffer);
			if (length == -1)
				throw new KnouflException("Stream closed");
			if (length != OnionBaseMessage.ONION_MAX_LENGTH)
				throw new KnouflException("packet too small");
			
			OnionBaseMessage msg = decryptMessageLayers(ByteBuffer.wrap(buffer), tunnelId);
			msg.setCircId(tunnelId);
//			msg = mapCircIdToTunnelId(msg);
			if(msg instanceof OnionDataMessage) {
				this.dataSplitter.receiveData((OnionDataMessage) msg);
			} else if(msg instanceof OnionTunnelTeardownMessage) {
				cleanupTunnel(msg.getCircId());
			} else if(msg instanceof OnionSwitchMessage) {
				switchTunnelExecute((OnionSwitchMessage)msg);
			} else {
				throw new KnouflException("Unsupported type " + msg.getClass().toString());
			}
		}
	}

	private void extendCircuit(int numberOfHops, short tunnelId) throws Exception {
		for (int i = 0; i < numberOfHops; i++) {
			RpsPeerMessage hop = apiInterface.getRandomHop();
			logger.fine("Next hop is: " + hop.getAddress().toString());
			SecretKey key = extendToNextHop(hop, tunnelId);
			getCircFromTunnelId(tunnelId).addKey(key);
			waitForExchangedSuccess(tunnelId);
		}
	}

	private void waitForExchangedSuccess(short tunnelId) throws Exception {
		byte[] buffer = new byte[OnionBaseMessage.ONION_MAX_LENGTH];
		int length = getCircFromTunnelId(tunnelId).getSocket().getInputStream().read(buffer);
		if (length == -1)
			throw new KnouflException("Stream closed");
		if (length != OnionBaseMessage.ONION_MAX_LENGTH)
			throw new KnouflException("packet too small");

		OnionBaseMessage response = decryptMessageLayers(ByteBuffer.wrap(buffer), tunnelId);
		
		if (response instanceof OnionKeyExchangeSuccessMessage)
			return;
		throw new KnouflException("Hop is not following protocol");
	}

	private short generateRandomCircId() {
		short id = -1;
		while (id < 0 || circuits.containsKey(id)) {
			id = Utility.getRandomShort();
		}
		return id;
	}

	private SecretKey sendAESKeyToHop(RSAPublicKey rsaPublicKey, short tunnelId) throws Exception {

		SecretKey key = SymmetricKeyExchange.generateAESKey();

		OnionKeyExchangeMessage exchangeMsg = (OnionKeyExchangeMessage) mapTunnelIdToCircId(new OnionKeyExchangeMessage(tunnelId, key));

		byte[] encryptedPayload = SymmetricKeyExchange.encryptRSA(rsaPublicKey, key.getEncoded());

		OnionRSAEncryptedMessage encryptedMessage = new OnionRSAEncryptedMessage(exchangeMsg.getCircId(),
				exchangeMsg.getPublicType(), encryptedPayload);

		sendMessage(encryptedMessage);

		return key;
	}

	private SecretKey extendToNextHop(RpsPeerMessage hop, short tunnelId) throws Exception {
		SecretKey key = SymmetricKeyExchange.generateAESKey();

		byte[] encryptedAESKey = SymmetricKeyExchange.encryptRSA(hop.getHostkey(), key.getEncoded());

		OnionExtendMessage extendMsg = (OnionExtendMessage) mapTunnelIdToCircId(new OnionExtendMessage(tunnelId, encryptedAESKey, hop.getAddress().getAddress(), (short) hop.getAddress().getPort()));

		sendMessage(ecnryptMessageLayers(extendMsg));

		return key;
	}

	public OnionAESEncryptedMessage ecnryptMessageLayers(OnionBaseIv msg) throws Exception {
		List<SecretKey> keys = this.circuits.get(msg.getCircId()).getAesKeys();
		int i = keys.size() - 1;
		OnionAESEncryptedMessage encrypted = SymmetricEncryption.encryptMessage(msg, keys.get(i));
		i--;
		while (i >= 0) {
			encrypted = SymmetricEncryption.encryptMessage(encrypted, keys.get(i));
			i--;
		} ;
		return encrypted;
	}

	public OnionBaseMessage decryptMessageLayers(ByteBuffer buffer, short circId) throws Exception {
		List<SecretKey> keys = this.circuits.get(circId).getAesKeys();
		OnionBaseMessage decrypted = null;
		ByteBuffer b = ByteBuffer.wrap(buffer.array());
		for (int i = 0; i < keys.size(); i++) {
			decrypted = OnionBaseMessage.parse(b, keys.get(i), null); // rsa null because it can only
			b = ByteBuffer.allocate(buffer.capacity());
			decrypted.send(b);
			b.position(0);
		}
		return decrypted;
	}

	private void sendMessage(OnionBaseMessage msg) throws IOException {
		DataOutputStream out = new DataOutputStream(this.circuits.get(msg.getCircId()).getSocket().getOutputStream());
		out.write(Utility.messageToArray(msg));
	}
	
	@Override
	public void sendData(OnionDataMessage msg) throws Exception {
		msg = (OnionDataMessage) mapTunnelIdToCircId(msg);
		if(!knowsTunnel(msg.getCircId()))
			throw new KnouflException("Circuit ID unknown");
		sendMessage(ecnryptMessageLayers(msg));
	}
	
	public void sendCoverData(short tunnelId) throws Exception {
		OnionCoverTrafficMessage msg = (OnionCoverTrafficMessage) mapTunnelIdToCircId(new OnionCoverTrafficMessage(tunnelId));
		sendMessage(ecnryptMessageLayers(msg));
	}
	
	@Override
	public void destroyTunnel(short tunnelId) throws IOException, KnouflException {
		if(!knowsTunnel(tunnelId))
			throw new KnouflException("Cannot teardown unknown tunnel " + tunnelId);
		
		OnionTunnelTeardownMessage msg = (OnionTunnelTeardownMessage) mapTunnelIdToCircId(new OnionTunnelTeardownMessage(tunnelId));
		sendMessage(msg);
		cleanupTunnel(tunnelId);
	}
	
	private void cleanupTunnel(short tunnelId) throws IOException {
		short circId = this.tunnelIdToCircId.get(tunnelId);
		circuits.get(circId).getSocket().close();
		circuits.remove(circId);
		tunnelIdToCircId.remove(tunnelId);
	}
	
	@Override
	public boolean knowsTunnel(short tunnelId) {
		return this.tunnelIdToCircId.containsKey(tunnelId);
	}
	
	public OnionCircuit getCircuitFromCircId(short circId) {
		return this.circuits.get(circId);
	}
	
	public void addCricuit(OnionCircuit circuit) {
		this.circuits.put(circuit.getId(), circuit);
	}
	
	private OnionCircuit getCircFromTunnelId(short tunnelId) {
		short circId = this.tunnelIdToCircId.get(tunnelId);
		return getCircuitFromCircId(circId);
	}
	
	private short getTunnelIdFromCircId(short circId) throws KnouflException {
		for (Entry<Short, Short> pair : tunnelIdToCircId.entrySet()) {
			if(pair.getValue() == circId){
				return pair.getKey();
			}
		}
		throw new KnouflException("could not find any mapping from circId " + circId + " to tunnelId");
	}
	
	private OnionBaseMessage mapTunnelIdToCircId(OnionBaseMessage msg) throws KnouflException {
		Short circId = this.tunnelIdToCircId.get(msg.getCircId());
		if(circId == null)
			throw new KnouflException("could not find any mapping from tunnelID " + msg.getCircId() + " to circId");
		msg.setCircId(circId);
		return msg;
	}
	private OnionBaseMessage mapCircIdToTunnelId(OnionBaseMessage msg) throws KnouflException {
		msg.setCircId(getTunnelIdFromCircId(msg.getCircId()));
		return msg;
	}
	
	public void switchTunnel(short tunnelId) throws Exception {
		logger.fine("Starting tunnel switch process.");
		OnionCircuit currentCirc = getCircFromTunnelId(tunnelId);
		short newTunnelId = tunnelBuild(currentCirc.getDestinationAddress(), currentCirc.getDestinationHostkey());
		
		SecureRandom r = new SecureRandom();
		int uid = r.nextInt();

		OnionSwitchMessage msgOld = new OnionSwitchMessage(currentCirc.getId(), false, false, uid);
		OnionSwitchMessage msgNew = new OnionSwitchMessage(newTunnelId, true, false, uid);
		getCircuitFromCircId(newTunnelId).setOldCircuit(currentCirc);
		
		sendMessage(ecnryptMessageLayers(msgOld));
		Thread.sleep(100);
		sendMessage(ecnryptMessageLayers(msgNew));
		logger.fine("Sent tunnel switch messages.");
	}
	
	private void switchTunnelExecute(OnionSwitchMessage msg) throws KnouflException, IOException {
		logger.fine("Got tunnel switch ack. Starting to teardown old one.");
		if(!msg.getIsAck())
			return;
		OnionCircuit newCirc = getCircFromTunnelId(msg.getCircId());
		short oldCircId = newCirc.getOldCircuit().getId();
		//Set mapping of tunnel to new circ
		tunnelIdToCircId.put(getTunnelIdFromCircId(oldCircId), newCirc.getId());
		//Remove mapoping of new tunnel
		this.tunnelIdToCircId.remove(msg.getCircId());
		
		//mabye tunnelTeardown TODO
		circuits.get(oldCircId).getSocket().close();
		circuits.remove(oldCircId);
		logger.fine("Tunnel switch done.");
	}
}
