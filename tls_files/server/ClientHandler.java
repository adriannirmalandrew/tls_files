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
	//Directory path:
	private String dirPath=null;
	
	//System time, used as salt for password:
	private String salt=null;
	//Hash of server password+salt:
	private String passHash64=null;
	
	//Constructor, if no password is used:
	public ClientHandler(String dir, SSLSocket soc) {
		this.dirPath=dir;
		this.sock=soc;
	}
	
	//MessageDigest for SHA-256 hash:
	private MessageDigest hasher256=null;
	
	//Constructor, if password is used:
	public ClientHandler(String dir, SSLSocket soc, String passw) throws NoSuchAlgorithmException {
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
		
		this.dirPath=dir;
		this.sock=soc;
	}
	
	//Check if password is valid:
	private boolean checkPassword(String pa) {
		String tempPass=pa.concat(this.salt);
		byte[] tempHash=this.hasher256.digest(tempPass.getBytes());
		String tempHash64=Base64.getEncoder().encodeToString(tempHash);
		if(tempHash.equals(this.passHash64))
			return true;
		else
			return false;
	}
	
	//Data streams:
	DataInputStream in=null;
	DataOutputStream out=null;
	
	//Print out error message:
	private synchronized void printError(String err) {
		System.out.println("Thread " + Thread.currentThread().getId() + ": " + err);
	}
	
	private synchronized void printErrorAndDie(String err) {
		printError(err);
		Thread.currentThread().interrupt();
	}
	
	//Actual client handler:
	public void run() {
		//Is the client logged in?
		boolean isClientLoggedIn=false;
		
		try {
			//Open data streams:
			in=new DataInputStream(this.sock.getInputStream());
			out=new DataOutputStream(this.sock.getOutputStream());
		} catch(IOException ie) {
			printError(ie.toString());
		}
		
		//Request handling:
		for(;;) {
			//Read request string from client:
			String req=null;
			try {
				req=in.readUTF();
			} catch(IOException o) {
				printErrorAndDie(o.getMessage());
			}
			//Convert request to uppercase:
			req=req.toUpperCase();
			//Handle a LOGIN request:
			if(req.equals("LOGIN") && !isClientLoggedIn) {
				//Check if session requires password:
				if(this.passHash64==null)
					try {
						printError("Client at " + this.sock.getRemoteSocketAddress() + " logging in.");
						this.out.writeUTF("LOGIN_OK");
						printError("Client at " + this.sock.getRemoteSocketAddress() + " logged in.");
						this.out.flush();
						isClientLoggedIn=true;
						continue;
					} catch(IOException o1) {
						printErrorAndDie(o1.getMessage());
					}
				else {
					try {
						this.out.writeUTF("PASSWD");
						//Check password:
						if(this.checkPassword(this.in.readUTF())) {
							this.out.writeUTF("LOGIN_OK");
							printError("Client at " + this.sock.getRemoteSocketAddress() + " logged in.");
							isClientLoggedIn=true;
							continue;
						}
						else {
							this.out.writeUTF("LOGIN_BAD");
							printErrorAndDie("Client at " + this.sock.getRemoteSocketAddress() + " disconnected (bad login).");
						}
					} catch(IOException o2) {
						printErrorAndDie(o2.getMessage());
					}
				}
			}
			//Handle all other requests:
			if(isClientLoggedIn) {
				//Handle a LIST request:
				if(req.equals("LIST")) {
					try {
						String csvFileList=null;
						//Open directory at dirPath:
						//TODO
						this.out.writeUTF(csvFileList);
					} catch(IOException ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
				//Handle a DLOAD request:
				
				//Handle a ULOAD request:
				
				//Handle a LOGOUT request:
				if(req.equals("LOGOUT")) {
					try {
						printError("Client at " + this.sock.getRemoteSocketAddress() + " logging out.");
						this.out.writeUTF("LOGOUT_OK");
						this.out.flush();
						this.out.close();
						this.in.close();
					} catch(IOException ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
			}
		}
	}
}
