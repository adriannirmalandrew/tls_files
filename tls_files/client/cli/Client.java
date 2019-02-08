package tls_files.client.cli;

import java.util.*;
import java.io.*;
import javax.net.ssl.*;

public class Client {
	public static void main(String[] args) {
		//Check arguments:
		if(args.length!=3) {
			System.out.println("Usage: Client <ip address> <port> <path to truststore>");
			System.exit(1);
		}
		//Port number:
		final int portno=Integer.valueOf(args[1]);
		//SSLSocketCreator:
		SSLSocketCreator soc=new SSLSocketCreator(args[2], "TLSv1.2", args[0], portno);
		
		//Get TrustStore password:
		System.out.print("Enter password for truststore: ");
		Console con=System.console();
		char[] trustStorePassword=con.readPassword();
		//Initialize soc:
		try {
			soc.initialize(trustStorePassword);
			trustStorePassword=null;
		} catch(Exception e) {
			System.out.println("Error initializing TrustStore: " + e.getMessage());
		}
		
		//Socket object:
		SSLSocket sock=null;
		//Input, output streams:
		DataInputStream in=null;
		DataOutputStream out=null;
		
		//Get socket object and connect:
		try {
			sock=soc.getSocket();
			soc=null;
			//Open streams:
			in=new DataInputStream(sock.getInputStream());
			out=new DataOutputStream(sock.getOutputStream());
			System.out.println("Connection successful, logging in...");
			//Send login request:
			out.writeUTF("LOGIN");
			out.flush();
		} catch(IOException e) {
			System.out.println("Error connecting to server: " + e.getMessage());
			System.exit(1);
		}
		
		//Continue with login:
		String reply=null;
		try {
			reply=in.readUTF();
			//Check if a password is required:
			if(reply.equals("PASSWD")) {
				System.out.print("Enter login password: ");
				char[] pw=con.readPassword();
				//Convert pw to String:
				StringBuilder pwSb=new StringBuilder();
				for(char j: pw) pwSb.append(j);
				out.writeUTF(pwSb.toString());
				out.flush();
				//Get response:
				reply=in.readUTF();
				if(reply.equals("LOGIN_BAD"))
					throw new IOException("Incorrect password!");
				else if(!reply.equals("LOGIN_OK"))
					throw new IOException("Invalid server response!");
			}
			else if(!reply.equals("LOGIN_OK"))
				throw new IOException("Invalid server response!");
		} catch(NullPointerException n) {
			System.out.println("Error: Empty response from server!");
			try {
				in.close();
				out.close();
			} catch(IOException i) {}
			System.exit(1);
		} catch(IOException e) {
			System.out.println("Error logging in: " + e.getMessage());
			System.exit(1);
		}
		
		String ch=null;
		//Get user requests:
		for(;;) {
			//Read action:
			System.out.println("1. List files\n2. Download a file\n3. Upload a file\n4. Exit\nEnter option: ");
			ch=con.readLine();
			//Perform action:
			try {
				switch(Integer.valueOf(ch)) {
					//List files:
					case(1): {
						//Send LIST request:
						out.writeUTF("LIST");
						out.flush();
						//Read comma-delimited list:
						System.out.println("Receiving data...");
						String csvFileList=in.readUTF();
						
						//Send response:
						out.writeUTF("RECV_OK");
						out.flush();
						reply=in.readUTF();
						//Make sure our connection is still good:
						if(!reply.equals("LIST_OK")) throw new IOException("Invalid response from server!");
						
						//Parse and display list:
						int noOfFiles=0;
						StringTokenizer par=new StringTokenizer(csvFileList, ",");
						while(par.hasMoreTokens()) {
							//Print 2 file names in a line:
							System.out.print(par.nextToken() + '\t');
							++noOfFiles;
							if(noOfFiles%2==0) System.out.println("");
						}
						System.out.println("\n");
					}
					//Download a file:
					case(2): {
						
					}
					//Upload a file:
					case(3): {
						
					}
					//Logout:
					case(4): {
						System.out.println("Logging out...");
						//Send LOGOUT request:
						out.writeUTF("LOGOUT");
						out.flush();
						//Make sure our connection is still good:
						reply=in.readUTF();
						if(!reply.equals("LOGOUT_OK")) throw new IOException("Invalid response from server!");
						//Exit:
						in.close();
						out.close();
						System.out.println("Exiting...");
						System.exit(0);
					}
				}
			} catch(IOException e) {
				System.out.println("Communication error: " + e.getMessage());
				try {
					in.close();
					out.close();
				} catch(IOException e1) {}
				System.exit(1);
			}
		}
	}
}
