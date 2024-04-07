package onion;

import java.net.Socket;

import javax.crypto.SecretKey;

public class ConnectionGlue {
	private Socket socket;
	private short circID;
	private boolean incoming;
	private SecretKey aes;
	
	private ConnectionGlue husband;
	
	public ConnectionGlue() {
		// TODO Auto-generated constructor stub
	}

	public ConnectionGlue(Socket socket) {
		this.socket = socket;
		this.incoming = true;
	}

	public ConnectionGlue(Socket socket, ConnectionGlue c) {
		this.socket = socket;
		this.husband = c;
		c.husband = this;
		this.aes = c.aes;
		this.incoming = false;
	}

	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	public short getCircID() {
		return circID;
	}

	public void setCircID(short circID) {
		this.circID = circID;
	}

	public ConnectionGlue getHusband() {
		return husband;
	}

	public void setHusband(ConnectionGlue husband) {
		this.husband = husband;
	}

	public SecretKey getAes() {
		return aes;
	}

	public void setAes(SecretKey aes) {
		this.aes = aes;
	}

	public boolean isIncoming() {
		return incoming;
	}

	@Override
	public String toString() {
		return "ConnectionGlue [socket=" + socket + ", circID=" + circID + ", incoming=" + incoming + ", aes=" + aes + "]";
	}
}
