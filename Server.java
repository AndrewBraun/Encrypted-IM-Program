import java.io.*;
import java.lang.*;
import java.security.*;
import java.net.*;
import java.util.*;

public class Server{

	public boolean Confidentaility;
	public boolean Integrity;
	public boolean Authentication;
	private ServerSocket serverSocket;
	private int port = 1000;
	private Key sharedKey;
	private Key clientPublicKey;
	private Key serverPrivateKey;
	private byte[] ServerPasswordHash;

	public Server() throws Exception{
		try{
			serverSocket = new ServerSocket(port);
			
			BufferedReader in = new BufferedReader(new FileReader("ServerPasswordHash.txt"));
			ServerPasswordHash = br.readLine().getBytes();
			in.close();
			
			in = new BufferedReader(new FileReader("ClientPublicKey.txt"));
			byte[] clientPublicKeyBytes = br.readLine().getBytes();
			KeyFactory kf = KeyFactory.getInstance("DSA");
			clientPublicKey = kf.generatePublic(new DESEncodedKeySpec(clientPublicKeyBytes));
			in.close();
			
			in = new BufferedReader(new FileReader("ServerPrivateKey.txt"));
			byte[] ServerPrivateKeyBytes = br.readLine().getBytes();
			serverPrivateKey = kf.generatePrivate(new DESEncodedKeySpec(serverPrivateKeyBytes));
			in.close();
			
		} catch (Exception e){
			throw e;
		}
		Confidentaility = false;
		Integrity = false;
		Authentication = false;
	}
	
	private boolean checkParameters(DataOutputStream out, DataOutputStream in){
		int i = 0;
		if(Confidentaility){
			i = i+4;
		}
		if(Integrity){
			i = i+2;
		}
		if(Authentication){
			i++;
		}
		out.writeInt(i);
		return in.readBoolean();
	}
	
	
	private void getParmeters(){
		
		Scanner scan = new Scanner(System.in);
		System.out.println("Hi! Please enter in which security options you want to use.");
		System.out.println("Do you want Confidentialty? (type y/n)");
		while(true){
			try{
				byte c = scan.nextByte();
				if(String.toString(c) == "y" || String.toString(c) == "Y"){
					System.out.println("Confidentiality set to on.");
					Confidentaility = true;
					break;
				}
				else if(String.toString(c) == "n" || String.toString(c) == "N"){
					System.out.println("Confidentiality set to off.");
					Confidentaility = false;
					break;
				}
				else{
					System.out.println("Input error: Please try again.");
				}
			}
			catch (Exception e) {
				System.out.println("Input error: Please try again.");
			}
		}
	
		System.out.println("Do you want Integrity? (type y/n)");
		while(true){
			try{
				byte c = scan.nextByte();
				if(String.toString(c) == "y" || String.toString(c) == "Y"){
					System.out.println("Integrity set to on.");
					Integrity = true;
					break;
				}
				else if(String.toString(c) == "n" || String.toString(c) == "N"){
					System.out.println("Integrity set to off.");
					Confidentaility = false;
					break;
				}
				else{
					System.out.println("Input error: Please try again.");
				}
			}
			catch (Exception e) {
				System.out.println("Input error: Please try again.");
			}
		}
			
		System.out.println("Do you want Authentication? (type y/n)");
		while(true){
			try{
				byte c = scan.nextByte();
				if(String.toString(c) == "y" || String.toString(c) == "Y"){
					System.out.println("Authentication set to on.");
					Authentication = true;
					break;
				}
				else if(String.toString(c) == "n" || String.toString(c) == "N"){
					System.out.println("Authentication set to off.");
					Authentication = false;
					break;
				}
				else{
					System.out.println("Input error: Please try again.");
				}
			}
			catch (Exception e) {
				System.out.println("Input error: Please try again.");
			}
		}
	}
	
	private void getPassword(){
		Scanner scan = new Scanner(System.in);
		System.out.println("Please enter your password");
		while(true){
			byte[] p = scan.nextLine().toBytes();
			if(Arrays.equals(p,ServerPasswordHash){
				System.out.println("Correct password!");
			}
			else System.out.println("Sorry, incorrect password.");
		}
	}
	
	private void operate() throws Exception{
		try{
			Socket sock = serverSocket.accept();
			System.out.println("Client has connected.");
			InputStream inputstream = clientSock.getInputStream();
			DataInputStream in = new DataInputStream(inputstream);
			OutputStream outputstream = clientSock.getOutputStream();
			DataOutputStream out = new DataOutputStream(outputstream);
			Scanner scan = new Scanner(System.in);
			
			if(checkParameters(out,in)==False){
				System.out.println("Error: Client has different parameters!");
				return;
			}
			
			//Somewhere below here, the system establishes a shared key.
			
			
			
			
			
			
			
			
			
			//Somewhere above here, the system establishes a shared key.
			
			
			/*
			while(true){
				String message = scan.nextLine();
				if(message != null){
					out.writeUTF(message);
				}
				String clientMessage = in.readUTF();
				if(clientMessage != null){
					System.out.println(clientMessage);
				}
			}
			*/
			
			if(Confidentiality){
				in = new CipherInputStream(inputStream,key);
				ReceiveInputEncrypted ri = new ReceiveInputEncrypted(in,Integrity);
				ri.start();
			}
			else{
				ReceiveInput ri = new ReceiveInput(in,Integrity);
				ri.start();
			}
			
			while(true){
				String message = scan.nextLine();
				if(message == null) continue;
				out.write(message.toBytes());
				if(Integrity){
					byte[] calculatedMAC = macCreator.doFinal(message.getBytes());
					out.write(calculatedMAC);
				}
			}
			
		} catch (Exception e){
			throw e;
		}
	}
	
	public static void main(String[] args){
		
		try{
			Server server = new Server();
			
			server.getParameters();
			
			if(server.Authentication){
				server.checkPassword();
			}
			while(true){
				server.operate();
			}
		} catch (Exception e){
			System.out.println("Something went wrong.");
		}
	}
}
