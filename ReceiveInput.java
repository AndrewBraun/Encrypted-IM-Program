import java.io.*;
import java.lang.*;
import java.security.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.nio.file.*;

public class ReceiveInput extends Thread{
	
	private boolean Confidentiality;
	private boolean Integrity;
	private DataInputStream in;
	private Key key;
	private Mac macCreator;
	private Cipher decryptCipher;
	
	public ReceiveInput(DataInputStream in, boolean Confidentiality, boolean Integrity, SecretKey key){
		this.in = in;
		this.Confidentiality = Confidentiality;
		this.Integrity = Integrity;
		this.key = key;
		try{
			decryptCipher = Cipher.getInstance("AES");
			decryptCipher.init(Cipher.DECRYPT_MODE,this.key);
			this.macCreator = Mac.getInstance("HmacSHA256");
			this.macCreator.init(key);
		} catch (Exception e){
			System.out.println("Something went wrong in ReceiveInput constructor.");
			System.out.println(e);
		}
	}
	
	public void run(){
		try{
			while(true){

				String incomingMessage = new String(in.readUTF());
				if(incomingMessage == null) continue;
				if(Confidentiality){
					incomingMessage = new String(decryptCipher.doFinal(incomingMessage.getBytes()));
				}
				if(Integrity){
					byte[] givenMAC = (in.readUTF()).getBytes();
					byte[] calculatedMAC = macCreator.doFinal(incomingMessage.getBytes());
					if(!Arrays.equals(givenMAC,calculatedMAC)){
						System.out.println("WARNING: The following message has been tampered with.");
					}
				}
				
				System.out.println(incomingMessage);

			}
		}
		catch (SocketException se){
			System.out.println("Client has disconnected.");
		}
		catch (Exception e){
			System.out.println("Something went wrong in ReceiveInput operate.");
			System.out.println(e);
		}
	}
}
