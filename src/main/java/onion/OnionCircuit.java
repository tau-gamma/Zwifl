package onion;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

public class OnionCircuit {
	
	private short id;
	private List<SecretKey> aesKeys = new ArrayList<>();
	private Socket socket;
	private InetSocketAddress destinationAddress;
	private RSAPublicKey destinationHostkey;
	private OnionCircuit oldCircuit; 
	
	public OnionCircuit(short id, Socket socket, InetSocketAddress destinationAddress, RSAPublicKey destinationHostkey) {
		this.id = id;
		this.socket = socket;
		this.destinationAddress = destinationAddress;
		this.destinationHostkey = destinationHostkey;
	}

	public short getId() {
		return id;
	}

	public void setId(short id) {
		this.id = id;
	}

	public List<SecretKey> getAesKeys() {
		return aesKeys;
	}

	public void setAesKeys(List<SecretKey> aesKeys) {
		this.aesKeys = aesKeys;
	}

	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}
	
	public void addKey(SecretKey key) {
		this.aesKeys.add(key);
	}

	public InetSocketAddress getDestinationAddress() {
		return destinationAddress;
	}

	public void setDestinationAddress(InetSocketAddress destinationAddress) {
		this.destinationAddress = destinationAddress;
	}

	public RSAPublicKey getDestinationHostkey() {
		return destinationHostkey;
	}

	public void setDestinationHostkey(RSAPublicKey destinationHostkey) {
		this.destinationHostkey = destinationHostkey;
	}

	public OnionCircuit getOldCircuit() {
		return oldCircuit;
	}

	public void setOldCircuit(OnionCircuit oldCircuit) {
		this.oldCircuit = oldCircuit;
	}
	
	

}
