package tls_files.client.cli;

import java.util.*;
import java.io.*;
import javax.net.ssl.*;

class BadResponseException extends IOException {
	public String getMessage() {
		return new String("Invalid response from server!");
	}
}

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
					throw new BadResponseException();
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
			System.out.print("1. List files\n2. Download a file\n3. Upload a file\n4. Delete a file\n5. Exit\nEnter option: ");
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
						if(!reply.equals("LIST_OK")) throw new BadResponseException();
						
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
						break;
					}
					//Download a file:
					case(2): {
						//Send DLOAD request:
						out.writeUTF("DLOAD");
						out.flush();
						//Get reply:
						reply=in.readUTF();
						if(!reply.equals("FNAME")) throw new BadResponseException();
						
						//Get and send filename:
						System.out.print("Enter file name: ");
						String fileName=con.readLine();
						out.writeUTF(fileName);
						out.flush();
						System.out.println("Requesting...");
						
						//Get and handle reply:
						reply=in.readUTF();
						if(reply.equals("DLOAD_NO_TARGET")) {
							System.out.println("Invalid filename!");
							continue;
						}
						else if(!reply.equals("FNAME_OK")) throw new BadResponseException();
						
						//Receive base64-encoded file data:
						out.writeUTF("RECV");
						System.out.print("Receiving data...");
						String fileData64=in.readUTF();
						System.out.print("done\n");
						out.writeUTF("RECV_OK");
						reply=in.readUTF();
						if(!reply.equals("DLOAD_OK")) throw new BadResponseException();
						
						//Get destination path from user:
						System.out.print("Save file as: ");
						String destPath=con.readLine();
						File dest=new File(destPath);
						//Check if file exists:
						if(dest.exists()) {
							System.out.print("File already exists. Overwrite? [y/N]: ");
							char ch1=con.readLine().charAt(0);
							if(!(ch1=='y' || ch1=='Y')) {
								System.out.println("Discarding file data...");
								fileData64=null;
								continue;
							}
							else dest.delete();
						}
						
						//Create target file:
						dest.createNewFile();
						//Decode downloaded data:
						byte[] fileData=Base64.getDecoder().decode(fileData64);
						//Write data to dest:
						FileOutputStream destOut=new FileOutputStream(dest);
						System.out.print("Writing file...");
						destOut.write(fileData);
						System.out.println("done\n");
						destOut.close();
						break;
					}
					//Upload a file:
					case(3): {
						//Send ULOAD request:
						out.writeUTF("ULOAD");
						out.flush();
						//Get reply:
						reply=in.readUTF();
						if(!reply.equals("FNAME")) throw new BadResponseException();
						
						//Get file name:
						System.out.print("Enter file name to save as: ");
						String fileName=con.readLine();
						//Send file name:
						out.writeUTF(fileName);
						out.flush();
						//Server checks if file already exists:
						reply=in.readUTF();
						if(reply.equals("FNAME_CONFLICT")) {
							System.out.println("File already exists, canceling...\n");
							continue;
						}
						else if(!reply.equals("FNAME_OK")) throw new BadResponseException();
						
						//Get file name:
						System.out.print("Enter name of source file: ");
						String upName=con.readLine();
						File upFile=new File(upName);
						//If file does not exist, cancel the operation:
						if(!upFile.exists()) {
							out.writeUTF("CANCEL");
							out.flush();
							System.out.println("File does not exist, canceling upload...");
							continue;
						}
						//Open file and read:
						System.out.print("Reading file...");
						FileInputStream upIn=new FileInputStream(upFile);
						byte[] upData=upIn.readAllBytes();
						System.out.print("done\n");
						//Encode data:
						System.out.print("Encoding...");
						String upData64=Base64.getEncoder().encodeToString(upData);
						System.out.print("done\n");
						
						//Send data:
						System.out.print("Sending...");
						out.writeUTF(upData64);
						out.flush();
						//Get reply:
						reply=in.readUTF();
						if(reply.equals("ULOAD_BAD"))
							System.out.println("\nThe server encountered an error, canceling...\n");
						else if(!reply.equals("ULOAD_OK"))
							throw new BadResponseException();
						else
							System.out.print("done\n\n");
						break;
					}
					//Delete a file:
					case(4): {
						//Send DEL request:
						out.writeUTF("DEL");
						out.flush();
						reply=in.readUTF();
						if(!reply.equals("FNAME")) throw new BadResponseException();
						
						//Get file name to be deleted:
						System.out.print("Enter name of file to be deleted: ");
						String delFile=con.readLine();
						
						//Send file name:
						System.out.println("Requesting...");
						out.writeUTF(delFile);
						reply=in.readUTF();
						if(reply.equals("DEL_NO_TARGET"))
							System.out.println("File does not exist!");
						else if(!reply.equals("DEL_OK"))
							throw new BadResponseException();
						else
							System.out.println("Done\n");
						break;
					}
					//Logout:
					case(5): {
						System.out.println("Logging out...");
						//Send LOGOUT request:
						out.writeUTF("LOGOUT");
						out.flush();
						//Make sure our connection is still good:
						reply=in.readUTF();
						if(!reply.equals("LOGOUT_OK")) throw new BadResponseException();
						
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
