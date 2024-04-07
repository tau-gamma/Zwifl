package e2e;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import onion.api.OnionAPInterface;
import onion.api.OnionApiMessage;
import onion.api.OnionCoverMessage;
import onion.api.OnionErrorMessage;
import onion.api.OnionTunnelBuildMessage;
import onion.api.OnionTunnelDataMessage;
import onion.api.OnionTunnelDestroyMessage;
import onion.api.OnionTunnelIncomingMessage;
import onion.api.OnionTunnelReadyMessage;
import protocol.MessageParserException;
import protocol.Protocol;
import protocol.UnknownMessageTypeException;
import rps.RpsConfigurationImpl;
import rps.api.RpsPeerMessage;

public class EndToEndTest {
	
	static String peer1ConfigFile = "./config/bootstrap.conf";
	static String peer2ConfigFile = "./config/peer-2.conf";
	static String peer3ConfigFile = "./config/peer-3.conf";
	
	static OnionAPInterface peer1;
	static OnionAPInterface peer2;
	static OnionAPInterface peer3;
	
	static ServerSocket peer1RPS;
	static ServerSocket peer2RPS;
	static ServerSocket peer3RPS;
	
	Socket peer1API  = null;
	Socket peer2API = null;
	
	static List<Process> processList = new ArrayList<>();
	static SecureRandom random = new SecureRandom();
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		peer1RPS = startRPSMock(1, peer1ConfigFile);
		peer2RPS = startRPSMock(2, peer2ConfigFile);
		peer3RPS = startRPSMock(3, peer3ConfigFile);
	}
	
	@Before
	public void beforeEach() throws Exception {
		peer1 = startOnionModule(peer1ConfigFile);
		peer2 = startOnionModule(peer2ConfigFile);
		peer3 = startOnionModule(peer3ConfigFile);
		sleep(100);
		peer1API = new Socket("127.0.0.1", peer1.getConfig().getAPIAddress().getPort());
		peer2API = new Socket("127.0.0.1", peer2.getConfig().getAPIAddress().getPort());
	}
	
	@After
	public void afterEach() throws IOException {
		if(peer1API != null)
			peer1API.close();
		if(peer2API != null)
			peer2API.close();
		if(peer1 != null)
			peer1.stop();
		if(peer2 != null)
			peer2.stop();
		if(peer3 != null)
			peer3.stop();
		
	}
	
	@AfterClass
	public static void afterClass() throws IOException {
		peer1RPS.close();
		peer2RPS.close();
		peer3RPS.close();
	}
	
	@Test(timeout=30000)
	public void dataBeforeBuildTest() {
		
		try {
			OnionApiMessage tmpMsg = null;
			OnionErrorMessage errMsg = null;
			
			OnionTunnelDataMessage dataMsg = new OnionTunnelDataMessage(42, "Some message".getBytes());
			sendRequest(peer1API, dataMsg);
			
			tmpMsg = readFromConnection(peer1API);
			assertEquals("response should be API_ONION_ERROR", Protocol.MessageType.API_ONION_ERROR, tmpMsg.getType());
			errMsg = (OnionErrorMessage) tmpMsg;
			assertEquals("Error request type should be API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DATA, errMsg.getRequestType());
			
		} catch (Exception e) {
			fail();
		}
	}
	
	@Test(timeout=30000)
	public void tunnelBuildTest() {
		try {
			//From peer1 to peer2
			buildTunnel(peer2, peer1API);

			//From peer2 to peer1
			buildTunnel(peer1, peer2API);
		} catch (Exception e) {
			fail();
		}
	}
	
	public long buildTunnel(OnionAPInterface destinationPeer, Socket apiConnection) throws Exception {
		OnionTunnelBuildMessage buildMessage = new OnionTunnelBuildMessage(destinationPeer.getConfig().getListenAddress(), destinationPeer.getConfig().getPublicKey());
		
		sendRequest(apiConnection, buildMessage);
		
		OnionApiMessage tmpMsg = readFromConnection(apiConnection);
		assertEquals("response should be API_ONION_TUNNEL_READY", Protocol.MessageType.API_ONION_TUNNEL_READY, tmpMsg.getType());
		return ((OnionTunnelReadyMessage) tmpMsg).getId();
	}
	
	@Test(timeout=30000)
	public void tunnelDataTest() throws Exception {
		//Build tunnel from peer1 to peer2
		long tunnelId = buildTunnel(peer2, peer1API);
		long destTunnelId = tunnelData(peer1API, peer2API, tunnelId, "Hello world".getBytes(), true);
		tunnelData(peer1API, peer2API, tunnelId, "Another hello world".getBytes(), false);
		tunnelData(peer2API, peer1API, destTunnelId, "Hello world back to you".getBytes(), false);
	}
	
	public long tunnelData(Socket sender, Socket listener, long tunnelId, byte[] data, boolean firstTime) throws Exception {
		OnionTunnelDataMessage dataMsg = new OnionTunnelDataMessage(tunnelId, data);
		sendRequest(sender, dataMsg);
		
		if(listener != null) {
			if(firstTime) {
				OnionApiMessage tmpMsg = readFromConnection(listener);
				assertEquals("receiver should listen to API_ONION_TUNNEL_INCOMING", Protocol.MessageType.API_ONION_TUNNEL_INCOMING, tmpMsg.getType());
			}
			OnionApiMessage tmpMsg = readFromConnection(listener);
			assertEquals("receiver should listen to API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DATA, tmpMsg.getType());
			OnionTunnelDataMessage dataIncomingMsg = (OnionTunnelDataMessage) tmpMsg;
			assertArrayEquals("recieved data should equal sent data", data, dataIncomingMsg.getData());
			return dataIncomingMsg.getId();
		}
		return -1;
	}
	
	
	
	/**
	 * The following test case tests if a tunnel is destroyed correctly after every 
	 * API-module connected to the peer sent a ONION_TUNNEL_DESTROY, communicating 
	 * that it is not interested in the tunnel anymore
	 */
	@Test(timeout=30000)
	public void destroyIfEveryConnectionUnsubscribedTest() {
		
		try {
			OnionApiMessage tmpMsg = null;
			OnionErrorMessage errMsg = null;
			
			Socket apiConnection = new Socket("127.0.0.1", peer2.getConfig().getAPIAddress().getPort());
			
			//Build a tunnel from peer1 to peer2
			long tunnelId = buildTunnel(peer2, peer1API);
			
			//Send some data into the tunnel
			tunnelData(peer1API, peer2API, tunnelId, "Some data".getBytes(), true);
			
			//Receicve message on second API-module 
			tmpMsg = readFromConnection(apiConnection);
			assertEquals("receiver should listen to API_ONION_TUNNEL_INCOMING", Protocol.MessageType.API_ONION_TUNNEL_INCOMING, tmpMsg.getType());
			tmpMsg = readFromConnection(apiConnection);
			assertEquals("receiver should listen to API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DATA, tmpMsg.getType());
			OnionTunnelDataMessage dataIncomingMsg = (OnionTunnelDataMessage) tmpMsg;
			assertArrayEquals("recieved data should equal sent data", "Some data".getBytes(), dataIncomingMsg.getData());
			long incomingTunnelId = dataIncomingMsg.getId();
			
			
			//Send destroy message from first api-module to unsubscribe
			OnionTunnelDestroyMessage destroyMsg = new OnionTunnelDestroyMessage(incomingTunnelId);
			sendRequest(peer2API, destroyMsg);
			
			sleep(100);
			
			//Send another message, this time only one connection should be notified
			tunnelData(peer1API, apiConnection, tunnelId, "Another message!".getBytes(), false);
			assertEquals("No message should be sent to the first api-module", 0, peer2API.getInputStream().available());
			
			//Now also the second api-module sends a tunnel destroy
			sendRequest(apiConnection, destroyMsg);
			
			sleep(100);
			
			//As a result sending data over this tunnel should result in an error (from both sides)
			//First check the sender side
			sendRequest(peer1API, new OnionTunnelDataMessage(tunnelId, "Error message".getBytes()));
			tmpMsg = readFromConnection(peer1API);
			assertEquals("response should be API_ONION_ERROR", Protocol.MessageType.API_ONION_ERROR, tmpMsg.getType());
			errMsg = (OnionErrorMessage) tmpMsg;
			assertEquals("Error request type should be API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DATA, errMsg.getRequestType());
			assertEquals(tunnelId, errMsg.getId());
			//Then the receiver side
			sendRequest(peer2API, new OnionTunnelDataMessage(incomingTunnelId, "Response".getBytes()));
			tmpMsg = readFromConnection(peer2API);
			assertEquals("response should be API_ONION_ERROR", Protocol.MessageType.API_ONION_ERROR, tmpMsg.getType());
			errMsg = (OnionErrorMessage) tmpMsg;
			assertEquals("Error request type should be API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DATA, errMsg.getRequestType());
			assertEquals(incomingTunnelId, errMsg.getId());
			
			apiConnection.close();
		} catch (Exception e) {
			fail();
		}
	}
	
	
	/**
	 * The following test case tests if a tunnel is destroyed correctly by its creator
	 */
	@Test(timeout=30000)
	public void destroyTest() {
		
		try {
			OnionApiMessage tmpMsg = null;
			OnionErrorMessage errMsg = null;
			
			//Build a tunnel from peer1 to peer2
			long tunnelId = buildTunnel(peer2, peer1API);
			
			//Send some data into the tunnel to check if it works
			tunnelData(peer1API, peer2API, tunnelId, "Some message".getBytes(), true);
			
			//Send destroy tunnel
			OnionTunnelDestroyMessage destroyMsg = new OnionTunnelDestroyMessage(tunnelId);
			sendRequest(peer1API, destroyMsg);
			
			sleep(100);
			
			//Send some data to check if tunnel has really been destroyed
			sendRequest(peer1API, new OnionTunnelDataMessage(tunnelId, "Some data".getBytes()));
			
			//Expect peer1 to respond with error
			tmpMsg = readFromConnection(peer1API);
			assertEquals("response should be API_ONION_ERROR", Protocol.MessageType.API_ONION_ERROR, tmpMsg.getType());
			errMsg = (OnionErrorMessage) tmpMsg;
			assertEquals("Error request type should be API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DATA, errMsg.getRequestType());
			assertEquals(tunnelId, errMsg.getId());
			
			sleep(50);
			
			//Send destroy message again  to check if peer responds with error
			sendRequest(peer1API, destroyMsg);
			
			tmpMsg = readFromConnection(peer1API);
			assertEquals("response should be API_ONION_ERROR", Protocol.MessageType.API_ONION_ERROR, tmpMsg.getType());
			errMsg = (OnionErrorMessage) tmpMsg;
			assertEquals("Error request type should be API_ONION_TUNNEL_DATA", Protocol.MessageType.API_ONION_TUNNEL_DESTROY, errMsg.getRequestType());
			assertEquals(tunnelId, errMsg.getId());
			
		} catch (Exception e) {
			fail();
		}
	}
	
	
	
	@Test(timeout=30000)
	public void completeTunnelCommunicationTest() throws IOException {
		try {

			long tunnelId = buildTunnel(peer2, peer1API);
			
			long responseTunnelId = tunnelData(peer1API, peer2API, tunnelId, "Hello my friend!".getBytes(), true);
			
			byte[] randomData = new byte[400];
			random.nextBytes(randomData);
			tunnelData(peer2API, peer1API, responseTunnelId, randomData, false);
			
			//Sending the same long message back again
			tunnelData(peer1API, peer2API, tunnelId, randomData, false);


			//Simulate heavy communication
			for(int i=0; i<10; i++){
				random.nextBytes(randomData);
				tunnelData(peer1API, peer2API, tunnelId, randomData, false);
			}
			for(int i=0; i<10; i++){
				random.nextBytes(randomData);
				tunnelData(peer2API, peer1API, responseTunnelId, randomData, false);
			}

			//Send destroy tunnel
			OnionTunnelDestroyMessage destroyMsg = new OnionTunnelDestroyMessage(tunnelId);
			sendRequest(peer1API, destroyMsg);
			
			
			
		} catch (Exception e) {
			fail( "Test failed: " + e.getMessage() );
		}
	}
	
	@Test(timeout=30000)
	public void coveredTrafficTest(){
		sendRequest(peer1API, new OnionCoverMessage(1000));
	}
	
	@Test(timeout=30000)
	public void wrongProtocolTest() {
		byte[] randomMessage = new byte[256];
		random.nextBytes(randomMessage);
		
		try {
			Socket api = new Socket("127.0.0.1", peer1.getConfig().getAPIAddress().getPort());
			api.getOutputStream().write(randomMessage);
			try{
				assertEquals("peer should close connection", -1, api.getInputStream().read());
			}catch(SocketException e){
				//if socket exception (socket reset) is thrown test should pass
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	private static ByteBuffer readResponse(int length, DataInputStream dis) throws IOException {
		ByteBuffer buffer = ByteBuffer.allocate(length - 4);
		for (int i = 0; i < buffer.limit(); i++) {
			buffer.put(dis.readByte());
		}
		buffer.position(0);
		return buffer;
	}
	
	private void sendRequest(Socket socket, OnionApiMessage msg) {
		ByteBuffer buf = ByteBuffer.allocate(msg.getSize());
		if(msg instanceof OnionTunnelDataMessage) {
			((OnionTunnelDataMessage) msg).send(buf);
		}else if(msg instanceof OnionTunnelBuildMessage) {
			((OnionTunnelBuildMessage) msg).send(buf);
		}else if(msg instanceof OnionTunnelDestroyMessage) {
			((OnionTunnelDestroyMessage) msg).send(buf);
		}
		
		try {
			socket.getOutputStream().write(buf.array());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private OnionApiMessage readFromConnection(Socket socket) throws IOException, UnknownMessageTypeException, MessageParserException {
		DataInputStream dis = new DataInputStream(socket.getInputStream());
		int length = dis.readChar();
		char messageType = dis.readChar();
		ByteBuffer buf = readResponse(length, dis);

		switch (Protocol.MessageType.asMessageType(messageType)) {
		case API_ONION_TUNNEL_READY:
			return OnionTunnelReadyMessage.parse(buf);
		case API_ONION_TUNNEL_INCOMING:
			return OnionTunnelIncomingMessage.parser(buf);
		case API_ONION_TUNNEL_DATA:
			return OnionTunnelDataMessage.parse(buf);
		case API_ONION_ERROR:
			return OnionErrorMessage.parser(buf);
		default:
			throw new RuntimeException("Onion API not following protocol");
		}
	}
	
	
	private static void sleep(int millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private OnionAPInterface startOnionModule(String config) throws Exception {
		OnionAPInterface peer = new OnionAPInterface(config);
		peer.start();
		return peer;
	}
	
	public static ServerSocket startRPSMock(int peer, String peerConfigFile) throws Exception {
		RpsConfigurationImpl config = new RpsConfigurationImpl(peerConfigFile);
		
		ServerSocket server = new ServerSocket(config.getAPIAddress().getPort());
		startRPSThread(server, peer);
		
		return server;
	}
	
	/**
	 * Acts as mock RPS server. Receives RPS QUERY and returns a random peer.
	 */
	private static void startRPSThread(ServerSocket server, int peer) {
		new Thread(new Runnable() {
			
			@Override
			public void run() {
				while(server != null && !server.isClosed()) {
					try {
						Socket client = server.accept();
						DataInputStream dis = new DataInputStream(client.getInputStream());
						int length = dis.readChar();
						char messageType = dis.readChar();
						ByteBuffer buf = readResponse(length, dis);

						if(Protocol.MessageType.asMessageType(messageType) == Protocol.MessageType.API_RPS_QUERY){
							boolean random = Math.random() > 0.5;
							OnionAPInterface randomPeer = null;
							switch(peer) {
								case 1:
									randomPeer = random ? peer2 : peer3;
								case 2:
									randomPeer = random ? peer1 : peer3;
								case 3:
									randomPeer = random ? peer1 : peer2;
							}
							RpsPeerMessage response = new RpsPeerMessage(randomPeer.getConfig().getListenAddress(), randomPeer.getConfig().getPublicKey());
							ByteBuffer outBuf = ByteBuffer.allocate(response.getSize());
							response.send(outBuf);
							try {
								client.getOutputStream().write(outBuf.array());
								client.getOutputStream().flush();
							} catch (IOException e) {}
						}
						
					} catch (Exception e) {}
				}
			}
		}).start();

	}

}
