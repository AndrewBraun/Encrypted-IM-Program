import java.io.*;
import java.lang.*;
import java.security.*;
import java.net.*;
import java.util.*;

public class KeyCreator{
	
	public KeyCreator(){
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String ClientPassword = "password";
			byte[] ClientPasswordHash = md.digest(ClientPassword.getBytes());
			FileOutputStream out = new FileOutputStream("ClientPasswordHash.txt");
			out.write(ClientPasswordHash);
			out.close();
			String ServerPassword = "PASSWORD";
			byte[] ServerPasswordHash = md.digest(ServerPassword.getBytes());
			out = new FileOutputStream("ServerPasswordHash");
			out.write(ServerPasswordHash);
			out.close();
			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
			SecureRandom randy = new SecureRandom();
			kpg.initialize(1024,randy);
			KeyPair KP = kpg.generateKeyPair();
			PrivateKey ServerPrivateKey = KP.getPrivate();
			PublicKey ServerPublicKey = KP.getPublic();
			out = new FileOutputStream("ServerPrivateKey.txt");
			out.write(ServerPrivateKey.getEncoded());
			out.close();
			out = new FileOutputStream("ServerPublicKey.txt");
			out.write(ServerPublicKey.getEncoded());
			out.close();
			
			KP = kpg.generateKeyPair();
			PrivateKey ClientPrivateKey = KP.getPrivate();
			PublicKey ClientPublicKey = KP.getPublic();
			out = new FileOutputStream("ClientPrivateKey.txt");
			out.write(ClientPrivateKey.getEncoded());
			out.close();
			out = new FileOutputStream("ClientPublicKey");
			out.write(ClientPublicKey.getEncoded());
			out.close();
		} catch (Exception e){
			System.out.println(e);
		}
	}
	
	public static void main(String[] args){
		KeyCreator k = new KeyCreator();
		
	}
}
