import java.io.*;
import java.lang.*;
import java.security.*;
import java.security.spec.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.nio.file.*;

public class Server{

	public boolean Confidentiality;
	public boolean Integrity;
	public boolean Authentication;
	private ServerSocket serverSocket;
	private int port = 1000;
	private SecretKey sharedKey;
	private PublicKey clientPublicKey;
	private PrivateKey serverPrivateKey;
	private byte[] ServerPasswordHash;

	public Server(){
		try{
			serverSocket = new ServerSocket(port);
			
			Path path = Paths.get("ServerPasswordHash.txt");
			ServerPasswordHash = Files.readAllBytes(path);
			//BufferedReader in = new BufferedReader(new FileReader("ServerPasswordHash.txt"));
			//ServerPasswordHash = in.readLine().getBytes();
			//in.close();
			
			//in = new BufferedReader(new FileReader("ClientPublicKey.txt"));
			//byte[] clientPublicKeyBytes = in.readLine().getBytes();
			path = Paths.get("ClientPublicKey.txt");
			byte[] clientPublicKeyBytes = Files.readAllBytes(path);
			KeyFactory kf = KeyFactory.getInstance("DSA");
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
			clientPublicKey = kf.generatePublic(pubKeySpec);

			path = Paths.get("ServerPrivateKey.txt");
			byte[] ServerPrivateKeyBytes = Files.readAllBytes(path);
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(ServerPrivateKeyBytes);
			serverPrivateKey = kf.generatePrivate(privKeySpec);
			
			
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
			out.writeInt(i);
			return in.readBoolean();
		} catch(Exception e){
			System.out.println("Something went wrong in checkPaarameters.");
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
				if(cChar=='y'|| cChar=='Y'){
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
				if(Arrays.equals(pHash,ServerPasswordHash)){
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
			Socket sock = serverSocket.accept();
			System.out.println("Client has connected.");
			InputStream inputstream = sock.getInputStream();
			DataInputStream in = new DataInputStream(inputstream);
			OutputStream outputstream = sock.getOutputStream();
			DataOutputStream out = new DataOutputStream(outputstream);
			Scanner scan = new Scanner(System.in);
			
			if(checkParameters(out,in)==false){
				System.out.println("Error: Client has different parameters!");
				return;
			}
			

			byte[] sharedKeyEncrypted = in.readUTF().getBytes();
			Cipher dsaCipher = Cipher.getInstance("DES");
			dsaCipher.init(Cipher.UNWRAP_MODE,serverPrivateKey);
			sharedKey = (SecretKey) dsaCipher.unwrap(sharedKeyEncrypted, "AES",Cipher.SECRET_KEY);
			
			
			
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
			ReceiveInput ri = new ReceiveInput(in,Confidentiality,Integrity, sharedKey);
			ri.start();
			
			Cipher outputCipher = Cipher.getInstance("AES");
			outputCipher.init(Cipher.ENCRYPT_MODE,sharedKey);
			
			Mac macCreator = Mac.getInstance("HmacSHA256");
			macCreator.init(sharedKey);
			
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
