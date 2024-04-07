package onion;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

import onion.api.OnionTunnelDataMessage;
import onion.protocol.KnouflException;
import onion.protocol.OnionDataMessage;
import onion.protocol.interfaces.OnionDataReceiver;
import onion.protocol.interfaces.OnionDataSender;


public class DataSplitterTest {
	
	@Test
	public void test() throws Exception{
		byte [] buffer = new byte [63000];
		new Random().nextBytes(buffer);
		
		OnionTunnelDataMessage send = new OnionTunnelDataMessage(1, buffer);
		
		DataSplitter s = new DataSplitter(new OnionDataReceiver() {
			
			@Override
			public void notifyDataIncoming(OnionTunnelDataMessage msg) throws Exception {
				assertArrayEquals("Received message should equal sent message", msg.getData(), send.getData());				
			}
		});
		
		DataSplitter.sendData(send, new OnionDataSender() {
			
			@Override
			public void sendData(OnionDataMessage msg) throws Exception {
				s.receiveData(new OnionDataMessage(msg.getCircId(),msg.getFileIdentifier(),msg.getPosition(),msg.getData()));
			}
			
			@Override
			public boolean knowsTunnel(short tunnelId) {
				return false;
			}
			
			@Override
			public void destroyTunnel(short circId) throws IOException, KnouflException {
			}
		});
	}

	@Test
	public void test2() throws Exception{
		byte [] buffer = new byte [63000];
		new Random().nextBytes(buffer);
		
		OnionTunnelDataMessage send = new OnionTunnelDataMessage(1, buffer);
		
		DataSplitter s = new DataSplitter(new OnionDataReceiver() {
			
			@Override
			public void notifyDataIncoming(OnionTunnelDataMessage msg) throws Exception {
				assertArrayEquals("Received message should equal sent message", msg.getData(), send.getData());				
			}
		});
		
		DataSplitter.sendData(send, new OnionDataSender() {
			int i = 0;
			OnionDataMessage mix;
			
			@Override
			public void sendData(OnionDataMessage msg) throws Exception {
				if(i == 5 || i == 10){
					mix = new OnionDataMessage(msg.getCircId(),msg.getFileIdentifier(),msg.getPosition(),msg.getData());
				}else if (i == 6 || i == 11){
					s.receiveData(new OnionDataMessage(msg.getCircId(),msg.getFileIdentifier(),msg.getPosition(),msg.getData()));
					s.receiveData(mix);
				}else{
					s.receiveData(new OnionDataMessage(msg.getCircId(),msg.getFileIdentifier(),msg.getPosition(),msg.getData()));
				}
				i++;
			}
			
			@Override
			public boolean knowsTunnel(short tunnelId) {
				return false;
			}
			
			@Override
			public void destroyTunnel(short circId) throws IOException, KnouflException {
			}
		});
	}
}
