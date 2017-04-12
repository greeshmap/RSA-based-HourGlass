
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;



/**
 * @author Greeshma Reddy
 *
 */
public class Client {
	
	Socket clientSocket = null;
	String serverIP;
	int serverPort;
	File content;
	PublicKey PUBK;
	PrivateKey PRIK;
	byte[] message1, message2;
	
	public Client(String serverIP, int serverPort, File content, PublicKey PUBK, PrivateKey PRIK)
	{
		this.serverIP = serverIP;
		this.serverPort = serverPort;		
		this.content = content;
		this.PUBK=PUBK;
		this.PRIK=PRIK;
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException
	{
		KeyPairGeneration keypairs= new KeyPairGeneration();
		keypairs.generateKeyPairClient();
		PublicKey PUBK = keypairs.loadPublicKey(new File("./clientpublic.txt"));
		PrivateKey PRIK= keypairs.loadPrivateKey(new File("./clientprivate.txt"));
		Scanner s= new Scanner(System.in);
		System.out.println("Enter server IP");
		String serverIP=s.next();
		System.out.println("Enter the server's port");
		int serverport=s.nextInt();
		System.out.println("Enter text file path");
		String content=s.next();
		Client client=new Client(serverIP, serverport, new File(content), PUBK, PRIK);
		client.clientProcess();
		s.close();
	}
	
	
	
	/**
	 * Client method responsible for sharing keys and random numbers. Sends the file content to server
	 */
	void clientProcess()
	{		
	    try {
	    	clientSocket = new Socket();
	        SocketAddress SA= new InetSocketAddress("localhost", 4555);
	    	clientSocket.bind(SA);
	    	clientSocket.connect(new InetSocketAddress(serverIP, serverPort));
	    	System.out.println("client started on"+ clientSocket.getLocalPort());
	    	
 	
	    	
	    	BufferedReader br= new BufferedReader(new FileReader(content));
	    	char[] buf= new char[32];
	    	int length;
	    	ArrayList<byte[]> Fi= new ArrayList<byte[]>();
	    	while((length=br.read(buf))!=-1)
	    	{
//	    		Fi.add(Charset.forName("UTF-8").encode(CharBuffer.wrap(buf)).array());
	    		Fi.add(new String(buf).getBytes("UTF-8"));
	    	}
	    	System.out.println("There are "+Fi.size()+" blocks");
	    	byte[] randomkey=BigInteger.valueOf(new SecureRandom().nextLong()).toByteArray();
	    	randomkey = Arrays.copyOf(randomkey, 16);
	    	SecretKeySpec key_AES = new SecretKeySpec(randomkey, "AES");
			Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    	LinkedHashMap<byte[], byte[]> hm= new LinkedHashMap<byte[], byte[]>();
	    	ArrayList<byte[]> Mac= new ArrayList<byte[]>();
	    	for(byte[] i:Fi)
	    	{
	    		aesCipher.init(Cipher.ENCRYPT_MODE, key_AES);
	    		byte[] temp= aesCipher.doFinal(i);
	    		Cipher cipher = Cipher.getInstance("RSA");
	            cipher.init(Cipher.ENCRYPT_MODE, PRIK);
	            byte[] Hi=cipher.doFinal(temp);
	            hm.put(i,Hi);
	            Mac.add(calculateMac(randomkey,Hi));
	    	}
	    	OutputStream os = clientSocket.getOutputStream();
	    	ObjectOutputStream oos = new ObjectOutputStream(os);
	    	oos.writeObject(key_AES);
	    	oos.writeObject(PUBK);
	    	oos.writeObject(hm);
	    	oos.reset();
	    	
	    	
	    	System.out.println("Data outsourced to the server");
	    	Scanner s= new Scanner(System.in);
			ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());

	    	while(true)
	    	{
	    		System.out.println("Enter the command: Check i or Retrieve i");
	    		String str=s.nextLine();
	    		String[] command= str.split("\\s");
	    		oos.writeObject(Integer.parseInt(command[1]));
	    		oos.writeObject(command[0].getBytes());
	    		System.out.println("sent command");
	    		
    			
    			

	    		if(command[0].equalsIgnoreCase("check"))
	    		{

	    			message1= (byte[])ois.readObject();
	    			
	    			if(Arrays.equals(Mac.get(Integer.parseInt(command[1])), calculateMac(randomkey, message1)))
	    			{
	    				System.out.println("Success");
	    			}
	    			else
	    			{
	    				System.out.println("Failure");
	    			}
	    		}
	    		else if(command[0].equalsIgnoreCase("retrieve"))
	    		{
//	    			InputStream is = clientSocket.getInputStream();	
//					ObjectInputStream ois = new ObjectInputStream(is);
	    			message2= (byte[])ois.readObject();	    			
	    			String result= new String(message2);
	    			System.out.println(result);
	    		}
	    		else
	    		{
	    			System.out.println("Invalid command..");
	    		}
	    		
	    	} 		    	
	    	
//			clientSocket.close();
			
		} catch (Exception e) {
			System.out.println("Error occured"+ e.getMessage());
			e.printStackTrace();
		}

	}

	
	
	private byte[] calculateMac(byte[] aESKey, byte[] content) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac hMAC = Mac.getInstance("HmacSHA256");
		final SecretKeySpec key = new SecretKeySpec(aESKey, "HmacSHA256");
		hMAC.init(key);
		return hMAC.doFinal(content);
	}

}
