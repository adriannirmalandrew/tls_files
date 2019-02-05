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
			printErrorAndDie(ie.toString());
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
			//If the user logs out req becomes null, so exit the loop and print closing message:
			if(req==null) break;
			//Convert req to uppercase:
			req=req.toUpperCase();
			//Handle a LOGIN request:
			if(req.equals("LOGIN") && !isClientLoggedIn) try {
				printError("Client at " + this.sock.getRemoteSocketAddress() + " logging in.");
				//If session does not require password, send LOGIN_OK and continue:
				if(this.passHash64==null) {
					this.out.writeUTF("LOGIN_OK");
					printError("Client at " + this.sock.getRemoteSocketAddress() + " logged in.");
					this.out.flush();
					isClientLoggedIn=true;
					continue;
				}
				//Request password:
				this.out.writeUTF("PASSWD");
				//Check password:
				String p=this.in.readUTF();
				if(this.checkPassword(p)) {
					//If ok, log client in and continue:
					this.out.writeUTF("LOGIN_OK");
					this.out.flush();
					printError("Client at " + this.sock.getRemoteSocketAddress() + " logged in.");
					isClientLoggedIn=true;
				}
				else {
					//Else, reject login attempt and disconnect client:
					this.out.writeUTF("LOGIN_BAD");
					this.out.flush();
					printErrorAndDie("Client at " + this.sock.getRemoteSocketAddress() + " disconnected (bad login).");
				}
			} catch(IOException o1) {
				printErrorAndDie(o1.getMessage());
			}
			//Handle all other requests:
			else try {
				//Handle a LIST request:
				if(req.equals("LIST")) {
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
				}
				//Handle a DLOAD request:
				else if(req.equals("DLOAD")) {
					//Request file name:
					this.out.writeUTF("FNAME");
					this.out.flush();
					//Open requested file:
					String tempPath=this.dirPath + "/" + this.in.readUTF();
					File tempFile=new File(tempPath);
					if(!tempFile.exists()) {
						this.out.writeUTF("DLOAD_NO_TARGET");
						this.out.flush();
						//continue
					}
					else {
						this.out.writeUTF("FNAME_OK");
						this.out.flush();
						//Wait for "RECV":
						String rep1=this.in.readUTF();
						if(rep1.equals("RECV")) {
							//Open file:
							int fLen=(int)tempFile.length();
							byte[] tempFileBytes=new byte[fLen];
							//Read file data:
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
							}
						}
						else {
							this.out.writeUTF("NO_ACTION");
							this.out.flush();
						}
					}
				}
				//Handle a ULOAD request:
				else if(req.equals("ULOAD")) {
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
					//Request file data (encoded as Base64):
					this.out.writeUTF("FNAME_OK");
					this.out.flush();
					//Read file data:
					String tempData64=this.in.readUTF();
					//Decode data:
					byte[] tempData=Base64.getDecoder().decode(tempData64.trim().getBytes("UTF-8"));
					//Write data to disk:
					FileOutputStream fout=new FileOutputStream(tempFile);
					try {
						fout.write(tempData);
						fout.close();
					} catch(IOException e1) {
						//In case of error:
						this.out.writeUTF("ULOAD_BAD");
						this.out.flush();
						printError("Warning: Disk I/O Error: " + e1.getMessage());
						continue;
					}
					//Say everything went ok:
					this.out.writeUTF("ULOAD_OK");
					this.out.flush();
				}
				//Handle a DEL request:
				else if(req.equals("DEL")) {
					//Request file name:
					this.out.writeUTF("FNAME");
					this.out.flush();
					//Get file name:
					String tempPath=this.dirPath + "/" + this.in.readUTF();
					//Open file:
					File tempFile=new File(tempPath);
					if(!tempFile.exists()) {
						//Send error if file does not exist:
						this.out.writeUTF("DEL_NO_TARGET");
						this.out.flush();
						continue;
					}
					//Delete file:
					tempFile.delete();
					this.out.writeUTF("DEL_OK");
					this.out.flush();
				}
				//Handle a LOGOUT request:
				else if(req.equals("LOGOUT")) {
					printError("Client at " + this.sock.getRemoteSocketAddress() + " logging out.");
					this.out.writeUTF("LOGOUT_OK");
					this.out.flush();
					this.out.close();
					this.in.close();
				}
				else {
					try {
						this.out.writeUTF("NO_ACTION");
						this.out.flush();
					} catch(IOException ie) {
						printErrorAndDie(ie.getMessage());
					}
				}
			} catch(IOException ie) {
				printErrorAndDie(ie.getMessage());
			}
		}
		printErrorAndDie("Connection closed.");
	}
}
