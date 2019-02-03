package tls_files.server;

import java.net.*;
import javax.net.*;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.util.*;

public class ClientHandler implements Runnable {
	//SSLSocket object to communicate with client:
	private SSLSocket sock=null;
	
	//System time, used as salt for password:
	private String salt=null;
	//Hash of server password+salt:
	private String passHash64=null;
	
	//Constructor, if no password is used:
	public ClientHandler(SSLSocket soc) {
		this.sock=soc;
	}
	
	//MessageDigest for SHA-256 hash:
	private MessageDigest hasher256=null;
	
	//Constructor, if password is used:
	public ClientHandler(SSLSocket soc, String passw) throws NoSuchAlgorithmException {
		//Create hasher256:
		this.hasher256=MessageDigest.getInstance("SHA-256");
		
		//Get system time:
		this.salt=String.valueOf(System.currentTimeMillis());
		//Bytes in password+salt:
		byte[] pass=passw.concat(this.salt).getBytes();
		//Hash pass:
		byte[] passHash=this.hasher256.digest(pass);
		//Encode hash:
		this.passHash64=Base64.getEncoder().encodeToString(passHash);
		
		//Socket object:
		this.sock=soc;
	}
	
	//Data streams:
	DataInputStream in=null;
	DataOutputStream out=null;
	
	//Actual client handler:
	public void run() {
		//TODO
	}
}
