package onion;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import onion.api.OnionTunnelDataMessage;
import onion.protocol.KnouflException;
import onion.protocol.OnionBaseMessage;
import onion.protocol.OnionDataMessage;
import onion.protocol.interfaces.OnionDataReceiver;
import onion.protocol.interfaces.OnionDataSender;

public class DataSplitter {
	
	private OnionDataReceiver apiInterface;
	private Map<Short, List<OnionDataMessage>> mapOfFiles = new HashMap<Short, List<OnionDataMessage>>();
	
	private static final Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	
	public DataSplitter(OnionDataReceiver onionDataReceiver) {
		this.apiInterface = onionDataReceiver;
		
	}

	public void receiveData(OnionDataMessage msg) throws Exception{
		List<OnionDataMessage> list = mapOfFiles.get(msg.getFileIdentifier());
		if(list == null){
			list = new ArrayList<>();
			list.add(msg);
			mapOfFiles.put(msg.getFileIdentifier(), list);
		}else{
			list.add(msg);
		}
		if(msg.getPosition() == 0){
			startRoutine(msg.getFileIdentifier());
		}
	}


	private void startRoutine(short fileIdentifier) throws Exception {
		logger.fine("Starting routine");
		List<OnionDataMessage> list = mapOfFiles.get(fileIdentifier);
		if(list.get(0).getPosition()+1 != list.size())
			throw new KnouflException("Received incomplete File");
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		sortList(list);
		
		for (int i = 0; i < list.size(); i++) {
//			outputStream.write(searchPart(list, i).getData());
			outputStream.write(list.get(i).getData());
		}
		byte [] complete = outputStream.toByteArray();
		apiInterface.notifyDataIncoming(new OnionTunnelDataMessage(list.get(0).getCircId(), complete));
		mapOfFiles.remove(fileIdentifier);
		logger.fine("Received complete file. Number of Parts: " + list.size());
	}

	private void sortList(List<OnionDataMessage> list) {
		list.sort(new Comparator<OnionDataMessage>() {

			@Override
			public int compare(OnionDataMessage o1, OnionDataMessage o2) {
				return o2.getPosition() - o1.getPosition();
			}
		});
	}

	public static void sendData(OnionTunnelDataMessage msg, OnionDataSender sender) throws Exception {
		int size = OnionBaseMessage.ONION_MAX_LENGTH - new OnionDataMessage().getMessageLength();
		short numberOfPackets = (short) (msg.getData().length / size);
		short fileIdentifier = Utility.getRandomShort();
		short position = numberOfPackets;
		logger.fine("size "  + size);

		ByteBuffer byteBuffer = ByteBuffer.wrap(msg.getData());
		
		OnionDataMessage message = new OnionDataMessage((short) msg.getId(), fileIdentifier,  position, null); 
		int i = position;
		for ( ;i >= 0 && byteBuffer.remaining() >= size; i--) {
			byte [] buffer = new byte [size];
			byteBuffer.get(buffer);
			message.setData(buffer);
			message.setPosition((short) i);
			sender.sendData(message);
			Thread.sleep(10);
		}
		if(byteBuffer.remaining() > 0){
			byte [] buffer = new byte [byteBuffer.remaining()];
			byteBuffer.get(buffer);
			message.setData(buffer);
			message.setPosition((short) i);
			sender.sendData(message);
		}
	}
	
	public static void main(String[] args) throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] keyBytes = new byte[2000];
		random.nextBytes(keyBytes);
		OnionTunnelDataMessage s = new OnionTunnelDataMessage(10095, keyBytes);
		sendData(s, null);
	}
}
