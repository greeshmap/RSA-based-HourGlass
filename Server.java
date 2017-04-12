
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Greeshma Reddy
 *
 */
public class Server {
	
	ServerSocket serverSocket=null;
	String serverIP;
	int serverPort;
	
	public Server(String serverIP, int serverPort) 
	{
		this.serverIP = serverIP;
		this.serverPort = serverPort;
	}
	public static void main(String[] args)
	{
		Scanner s= new Scanner(System.in);
		System.out.println("enter server IP");
		String serverIP=s.next();
		System.out.println("Enter the port you want to use for server");
		int serverport=s.nextInt();
		Server server=new Server(serverIP, serverport);
		server.serverProcess();
		s.close();
		
	}

//	serverProcess() is responsible for socket creation and sharing random number, reciving actual file content
	
	public void serverProcess() 
	{
		LinkedHashMap<byte[], byte[]> hm= new LinkedHashMap<byte[], byte[]>();
		SecretKeySpec key_AES=null;
		PublicKey PUBK=null;
		byte[] message=null;
		try {
	        serverSocket = new ServerSocket();
	        serverSocket.bind(new InetSocketAddress(serverIP, serverPort));
	        System.out.println("Starting server on "+serverSocket.getLocalPort());
	        ArrayList<byte[]> indices= new ArrayList<byte[]>();
	        Socket clientSocket=null;
			while(true)
			{
				clientSocket = serverSocket.accept();
				ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());
				
				key_AES= (SecretKeySpec) ois.readObject();
				System.out.println(key_AES);
				PUBK= (PublicKey) ois.readObject();
				hm= (LinkedHashMap) ois.readObject();
				System.out.println(hm);

				
				Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				Cipher cipher = Cipher.getInstance("RSA");
	            cipher.init(Cipher.DECRYPT_MODE, PUBK);
				for (Map.Entry<byte[],byte[]> entry : hm.entrySet()) {
					
		            byte[] Gi=cipher.doFinal(entry.getValue());
		            aesCipher.init(Cipher.DECRYPT_MODE, key_AES);
		    		byte[] Fi= aesCipher.doFinal(Gi);
		    		if(!Arrays.equals(Fi, entry.getKey()))
		    		{
		    			System.out.println("Fi and Hi not matching...exiting the server");
		    			System.exit(0);
		    		}
		            
				    indices.add(entry.getKey());
				}
				for (Map.Entry<byte[],byte[]> entry : hm.entrySet()) {
					
		            System.out.println(new String(entry.getKey())+"   "+entry.getValue());
				}
				
				System.out.println("Received data from Client..");
				ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());

				while(true)
				{
					int i=(int)ois.readObject();
					System.out.println("i value is "+ i);		
					message= (byte[]) ois.readObject();
					

					if(message!=null)
					{
						String command= new String(message);
						if(command.equalsIgnoreCase("check"))
						{
							oos.writeObject(hm.get(indices.get(i)));
						}
						else if(command.equalsIgnoreCase("retrieve"))
						{						
				            cipher.init(Cipher.DECRYPT_MODE, PUBK);
				            aesCipher.init(Cipher.DECRYPT_MODE, key_AES);

				            byte[] Gi=cipher.doFinal(hm.get(indices.get(i)));
				    		byte[] Fi= aesCipher.doFinal(Gi);
							oos.writeObject(Fi);
						}
					}
					
				}
				
			}
			
			
		} catch (Exception e) {
			System.out.println("Error occured"+ e.getMessage());
			e.printStackTrace();
		}
	}
	
}