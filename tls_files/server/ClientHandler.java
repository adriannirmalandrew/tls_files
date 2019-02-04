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
		
		//Hash pass:
		byte[] passHash=this.hasher256.digest(passw.getBytes());
		//Encode hash:
		this.passHash64=Base64.getEncoder().encodeToString(passHash);
		
		this.dirPath=dir;
		this.sock=soc;
	}
	
	//Check if password is valid:
	private boolean checkPassword(String pa) {
		byte[] tempHash=this.hasher256.digest(pa.getBytes());
		String tempHash64=Base64.getEncoder().encodeToString(tempHash);
		if(tempHash64.equals(this.passHash64))
			return true;
		else
			return false;
	}
	
	//Data streams:
	DataInputStream in=null;
	DataOutputStream out=null;
	
	//Print out error message:
	private synchronized void printError(String err) {
		if(err!=null) System.out.println("Thread " + Thread.currentThread().getId() + ": " + err);
	}
	
	private synchronized void printErrorAndDie(String err) {
		printError(err);
		try {
			this.in.close();
			this.out.close();
		} catch(IOException I) {
			//Nothing to see here
		}
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
			//Convert request to uppercase. In case user logs out, exit the loop and print closing message:
			if(req!=null)
				req=req.toUpperCase();
			else
				break;
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
						String p=this.in.readUTF();
						if(this.checkPassword(p)) {
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
						//Open directory at dirPath:
						StringBuffer csvFileList=new StringBuffer();
						File dir=new File(this.dirPath);
						//Add files, exclude directories:
						for(File f: dir.listFiles()) {
							if(!(f.isDirectory()))
								csvFileList.append(f + ",");
						}
						this.out.writeUTF(csvFileList.toString());
						this.out.flush();
						
						//Wait for "RECV_OK":
						String resp1=this.in.readUTF();
						if(resp1.equals("RECV_OK")) {
							this.out.writeUTF("LIST_OK");
							this.out.flush();
						}
						else {
							this.out.writeUTF("NO_ACTION");
							this.out.flush();
						}
					} catch(IOException ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
				//Handle a DLOAD request:
				else if(req.equals("DLOAD")) {
					try {
						//Request file name:
						this.out.writeUTF("FNAME");
						this.out.flush();
						//Open requested file:
						String tempPath=this.dirPath + "/" + this.in.readUTF();
						File tempFile=new File(tempPath);
						printError(tempPath);
						if(!tempFile.exists()) {
							this.out.writeUTF("DLOAD_NO_TARGET");
							this.out.flush();
						}
						else {
							this.out.writeUTF("FNAME_OK");
							this.out.flush();
							//Wait for "RECV":
							String rep1=this.in.readUTF();
							if(rep1.equals("RECV")) {
								//Read file data:
								int fLen=(int)tempFile.length();
								byte[] tempFileBytes=new byte[fLen];
								FileInputStream fin=new FileInputStream(tempFile);
								fin.read(tempFileBytes, 0, fLen);
								//Encode to base64:
								String tempFile64=new String(Base64.getEncoder().encode(tempFileBytes), "UTF-8");
								//Send data:
								this.out.writeUTF(tempFile64);
								this.out.flush();
								//Wait for RECV_OK:
								rep1=this.in.readUTF();
								if(rep1.equals("RECV_OK")) {
									this.out.writeUTF("DLOAD_OK");
									this.out.flush();
									continue;
								}
								else {
									this.out.writeUTF("NO_ACTION");
									this.out.flush();
									continue;
								}
							}
							else {
								this.out.writeUTF("NO_ACTION");
								this.out.flush();
								continue;
							}
						}
					} catch(Exception ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
				//Handle a ULOAD request:
				else if(req.equals("ULOAD")) {
					try {
						//Request file name:
						this.out.writeUTF("FNAME");
						this.out.flush();
						//Read file name:
						String tempPath=this.dirPath + "/" + this.in.readUTF();
						File tempFile=new File(tempPath);
						//Check if file exists:
						if(tempFile.exists()) {
							this.out.writeUTF("FNAME_CONFLICT");
							this.out.flush();
							continue;
						}
						//Receive file data (encoded as Base64):
						this.out.writeUTF("FNAME_OK");
						this.out.flush();
						String tempData64=this.in.readUTF();
						//Decode data:
						byte[] tempData=Base64.getDecoder().decode(tempData64.trim().getBytes("UTF-8"));
						//Write data to disk:
						FileOutputStream fout=new FileOutputStream(tempFile);
						try {
							fout.write(tempData);
						} catch(IOException e1) {
							//In case of error:
							this.out.writeUTF("ULOAD_BAD");
							this.out.flush();
							continue;
						}
						//Say everything went ok:
						this.out.writeUTF("ULOAD_OK");
						this.out.flush();
					} catch(IOException ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
				//Handle a DEL request:
				else if(req.equals("DEL")) {
					
				}
				//Handle a LOGOUT request:
				else if(req.equals("LOGOUT")) {
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
				else {
					try {
						this.out.writeUTF("NO_ACTION");
						this.out.flush();
					} catch(IOException ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
			}
		}
		printErrorAndDie("Connection closed.");
	}
}
