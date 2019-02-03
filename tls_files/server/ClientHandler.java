package tls_files.server;

import java.net.*;
import javax.net.*;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;

public class ClientHandler implements Runnable {
	//SSLSocket object to communicate with client:
	private SSLSocket sock=null;
	
	//Constructor:
	public ClientHandler(SSLSocket soc) {
		this.sock=soc;
	}
	
	public void run() {
		//TODO
	}
}
