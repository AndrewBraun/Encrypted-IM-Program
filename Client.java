import java.io.*;
import java.lang.*;
import java.security.*;
import java.security.spec.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.nio.file.*;

public class Client{

	public boolean Confidentiality;
	public boolean Integrity;
	public boolean Authentication;
	private Socket clientSock;
	private int port = 1000;
	private SecretKey sharedKey;
	private PrivateKey clientPrivateKey;
	private PublicKey serverPublicKey;
	private byte[] ClientPasswordHash;

	public Client(){
		try{
			clientSock = new Socket("127.0.0.1",port);
			
			Path path = Paths.get("ClientPasswordHash.txt");
			ClientPasswordHash = Files.readAllBytes(path);

			path = Paths.get("ServerPublicKey.txt");
			byte[] serverPublicKeyBytes = Files.readAllBytes(path);
			KeyFactory kf = KeyFactory.getInstance("DSA");
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
			serverPublicKey = kf.generatePublic(pubKeySpec);

			path = Paths.get("ClientPrivateKey.txt");
			byte[] ClientPrivateKeyBytes = Files.readAllBytes(path);
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(ClientPrivateKeyBytes);
			clientPrivateKey = kf.generatePrivate(privKeySpec);
			
		} catch (Exception e){
			System.out.println("Something went wrong in the constructor.");
			System.out.println(e);
		}
		Confidentiality = false;
		Integrity = false;
		Authentication = false;	
	}
	
	private boolean checkParameters(DataOutputStream out, DataInputStream in){
		int i = 0;
		if(Confidentiality){
			i = i+4;
		}
		if(Integrity){
			i = i+2;
		}
		if(Authentication){
			i++;
		}
		try{
			int j = in.readInt();
			if(j==i){
				out.writeBoolean(true);
				return true;
			}
			else{
				out.writeBoolean(false);
				return false;
			}
		} catch (Exception e){
			System.out.println("Something went wrong in checkParameters.");
			System.out.println(e);
		}
		return false;
	}
	
	private void getParameters(){
		
		Scanner scan = new Scanner(System.in);
		System.out.println("Hi! Please enter in which security options you want to use.");
		System.out.println("Do you want Confidentiality? (type y/n)");
		while(true){
			try{
				String c = scan.next();
				char cChar = c.charAt(0);
				if(cChar=='y'|| cChar=='Y'){
					System.out.println("Confidentiality set to on.");
					Confidentiality = true;
					break;
				}
				else if(cChar=='n' || cChar=='N'){
					System.out.println("Confidentiality set to off.");
					Confidentiality = false;
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
				String c = scan.next();
				char cChar = c.charAt(0);
				if(cChar=='y'|| cChar =='Y'){
					System.out.println("Integrity set to on.");
					Integrity = true;
					break;
				}
				else if(cChar=='n' || cChar=='N'){
					System.out.println("Integrity set to off.");
					Confidentiality = false;
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
				String c = scan.next();
				char cChar = c.charAt(0);
				if(cChar=='y'|| cChar=='Y'){
					System.out.println("Authentication set to on.");
					Authentication = true;
					break;
				}
				else if(cChar=='n' || cChar=='N'){
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
	
	private void checkPassword(){
		Scanner scan = new Scanner(System.in);
		System.out.println("Please enter your password");
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			while(true){
				//Need to hash the incoming password
				byte[] p = scan.nextLine().getBytes();
				byte[] pHash = md.digest(p);
				if(Arrays.equals(pHash,ClientPasswordHash)){
					System.out.println("Correct password!");
					break;
				}
				else System.out.println("Sorry, incorrect password.");
			}
		} catch (Exception e){
			System.out.println("Something went wrong in checkPassword.");
			System.out.println(e);
			return;
		}
	}
	
	private void operate(){
		try{
			System.out.println("Connected to the server.");
			InputStream inputstream = clientSock.getInputStream();
			DataInputStream in = new DataInputStream(inputstream);
			OutputStream outputstream = clientSock.getOutputStream();
			DataOutputStream out = new DataOutputStream(outputstream);
			Scanner scan = new Scanner(System.in);
			
			if(checkParameters(out,in)==false){
				System.out.println("Error: Server has different parameters!");
				return;
			}
			
			//Somewhere below here, the system establishes a shared key.
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(256);
			sharedKey = kg.generateKey();
	
			Cipher dsaCipher = Cipher.getInstance("DES");
			dsaCipher.init(Cipher.WRAP_MODE,serverPublicKey);
			byte[] sharedKeyEncrypted = dsaCipher.doFinal(sharedKey.getEncoded());
			out.writeUTF(new String(sharedKeyEncrypted));
			
			
			Mac macCreator = Mac.getInstance("HmacSHA256");
			macCreator.init(sharedKey);
			
			
			
			//Somewhere above here, the system establishes a shared key.
			
			ReceiveInput ri = new ReceiveInput(in,Confidentiality,Integrity, sharedKey);
			ri.start();
			
			Cipher outputCipher = Cipher.getInstance("AES");
			outputCipher.init(Cipher.ENCRYPT_MODE,sharedKey);
			
			while(true){
				String message = scan.nextLine();
				if(message == null) continue;
				if(Confidentiality){
					message = new String(outputCipher.doFinal(message.getBytes()));
				}
				out.write(message.getBytes());
				if(Integrity){
					byte[] calculatedMAC = macCreator.doFinal(message.getBytes());
					out.write(calculatedMAC);
				}
			}
		} catch (Exception e){
			System.out.println("Something went wrong in operate.");
			System.out.println(e);
		}
	}
	
	public static void main(String[] args){
		
		try{
			Client c = new Client();
			
			c.getParameters();	
			
			if(c.Authentication){
				c.checkPassword();
			}
			
			c.operate();
		} catch(Exception e){
			System.out.println("Something went wrong.");
		}
	}
}
