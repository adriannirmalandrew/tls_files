package tls_files.server;

import java.net.*;
import javax.net.*;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.util.concurrent.*;

public class Server {
	public static void main(String[] args) {
		//Check arguments:
		if(args.length<3) {
			System.out.println("Usage: Server folder port keystore [password]");
			System.exit(1);
		}
		
		//Save port number:
		final int port=Integer.valueOf(args[1]);
		
		//Print warning if no password is given:
		if(args.length==3)
			System.out.println("Warning: No password provided. All connections will be accepted.");
		
		//Open folder:
		System.out.println("Checking directory...");
		File folder=new File(args[0]);
		if(!folder.exists() || !folder.isDirectory()) {
			System.out.println("Invalid directory: " + args[0]);
			System.exit(1);
		}
		if(folder.listFiles().length==0) {
			System.out.println("Directory " + args[0] + " is empty, exiting...");
			System.exit(1);
		}
		System.out.println("Directory loaded. Initializing connection...");
		
		//Prepare SSL Context:
		SSLServerSocketCreator soc=new SSLServerSocketCreator(args[2], "TLS", port);
		try {
			//Get password for KeyStore:
			System.out.print("Enter password for keystore: ");
			Console con=System.console();
			char[] pass=con.readPassword();
			//Initialize soc:
			soc.initialize(pass);
			//Kill pass:
			pass=null;
		} catch(IOException i) {
			System.out.println("Error loading keystore: " + i);
			System.exit(1);
		} catch(Exception e) {
			System.out.println("Exception caught: " + e);
			System.exit(1);
		}
		
		//Initialize Connection, to accept incoming connections:
		SSLServerSocket mainSock=null;
		try {
			mainSock=soc.getServerSocket();
			//Kill SSLSocketCreator:
			soc=null;
		} catch(IOException i) {
			System.out.println("I/O Error: " + i);
			System.exit(1);
		}
		
		//Multithreaded client handling:
		ExecutorService threadPool=Executors.newCachedThreadPool();
		for(;;) {
			//Accept a connection:
			SSLSocket tempSock=null;
			try {
				tempSock=(SSLSocket)mainSock.accept();
			} catch(IOException e) {
				System.out.println("I/O Error: " + e);
				continue;
			}
			//Create new ClientHandler:
			try {
				if(args.length==3)
					threadPool.execute(new ClientHandler(tempSock));
				else if(args.length==4)
					threadPool.execute(new ClientHandler(tempSock, args[3]));
			} catch(NoSuchAlgorithmException n) {
				System.out.println("Error: SHA-256 hashing algorithm not available, please check your Java installation.");
				System.exit(1);
			}
		}
	}
}
