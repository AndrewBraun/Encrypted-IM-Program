import java.io.*;
import java.lang.*;
import java.security.*;
import java.net.*;
import java.util.*;

public class ReceiveInput extends Thread{
	
	private boolean Integrity;
	private DataInputStream in;
	private Key key;
	private Mac macCreator;
	
	public ReceiveInput(DataInputStream in, boolean Integrity, Key key){
		this.in = in;
		this.Integrity = Integrity;
		this.key = key;
		macCreator = Mac.getInstance("HmacSHA256");
		macCreator.init(key);
	}
	
	public void run(){
		try{
			while(true){

				String incomingMessage = String.toString(in.read());
				if(incomingMessage == null) continue;
				if(Integrity){
					byte[] givenMAC = in.read();
					byte[] calculatedMAC = macCreator.doFinal(incomingMessage.getBytes());
					if(!Arrays.equals(givenMAC,calculatedMAC)){
						System.out.println("WARNING: The following message has been tampered with.");
					}
				}
				
				System.out.println(incomingMessage);

			}
		} catch (Exception e){
			System.out.println("Something went wrong in ReceiveInput.");
		}
	}
}
