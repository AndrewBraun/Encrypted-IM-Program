import java.io.*;
import java.lang.*;
import java.security.*;
import java.net.*;
import java.util.*;

public class Server{

	private boolean Confidentaility;
	private boolean Integrity;
	private boolean Authentication;
	private ServerSocket serverSocket;
	private int port = 1000;
	private Key sharedKey;

	public Server() throws Exception{
		try{
			serverSocket = new ServerSocket(port);
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
			server.operate();
		} catch (Exception e){
			System.out.println("Something went wrong.");
		}
	}
}
