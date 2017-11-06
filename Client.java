import java.io.*;
import java.lang.*;
import java.security.*;
import java.net.*;
import java.util.*;

public class Client{

	private boolean Confidentaility;
	private boolean Integrity;
	private boolean Authentication;
	private Socket clientSock;
	private int port = 1000;

	public Client() throws Exception{
		try{
			clientSock = new Socket("127.0.0.1",port);
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
		int j = in.readInt();
		if(j==i){
			out.writeBoolean(true);
			return true;
		}
		else{
			out.writeBoolean(false);
			return false;
		}
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
			System.out.println("Connected to the server.");
			InputStream inputstream = clientSock.getInputStream();
			DataInputStream in = new DataInputStream(inputstream);
			OutputStream outputstream = clientSock.getOutputStream();
			DataOutputStream out = new DataOutputStream(outputstream);
			Scanner scan = new Scanner(System.in);
			
			if(checkParameters(out,in)==False){
				System.out.println("Error: Server has different parameters!");
				return;
			}
			
			if(Confidentiality){			
				ReceiveInputEncrypted ri = new ReceiveInputEncrypted(in,Integrity);
				ri.start();
			}
			else{
				ReceiveInput ri = new ReceiveInput(in,Integrity);
				ri.start();
			}
			
			macCreator = Mac.getInstance("HmacSHA256");
			macCreator.init(key);
			
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
			Client c = new Client();
			
			c.getParameters();	
			
			c.operate();
		} catch(Exception e){
			System.out.println("Something went wrong.");
		}
	}
}
