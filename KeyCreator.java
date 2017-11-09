import java.io.*;
import java.lang.*;
import java.security.*;
import java.security.spec.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.nio.file.*;

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
			out = new FileOutputStream("ServerPasswordHash.txt");
			out.write(ServerPasswordHash);
			out.close();
			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
			kpg.initialize(512);
			
			KeyPair KP = kpg.generateKeyPair();
			PrivateKey ServerPrivateKey = KP.getPrivate();
			PublicKey ServerPublicKey = KP.getPublic();
			byte[] ServerPrivateKeyBytes = ServerPrivateKey.getEncoded();
			byte[] ServerPublicKeyBytes = ServerPublicKey.getEncoded();
			
			out = new FileOutputStream("ServerPrivateKey.txt");
			out.write(ServerPrivateKeyBytes);
			out.close();
			
			out = new FileOutputStream("ServerPublicKey.txt");
			out.write(ServerPublicKeyBytes);
			out.close();
			
			KP = kpg.generateKeyPair();
			PrivateKey ClientPrivateKey = KP.getPrivate();
			PublicKey ClientPublicKey = KP.getPublic();
			byte[] ClientPrivateKeyBytes = ClientPrivateKey.getEncoded();
			byte[] ClientPublicKeyBytes = ClientPublicKey.getEncoded();
			
			out = new FileOutputStream("ClientPrivateKey.txt");
			out.write(ClientPrivateKeyBytes);
			out.close();
			
			out = new FileOutputStream("ClientPublicKey.txt");
			out.write(ClientPublicKeyBytes);
			out.close();
			
		} catch (Exception e){
			System.out.println(e);
		}
	}
	
	public static void main(String[] args){
		KeyCreator k = new KeyCreator();
		
	}
}
