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
		SSLSocketCreator soc=new SSLSocketCreator(args[2], "TLS", args[0], portno);
		
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
		
		//Get user requests:
		for(;;) {
			
		}
	}
}
