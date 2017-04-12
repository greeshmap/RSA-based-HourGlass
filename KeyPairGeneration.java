import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Greeshma Reddy
 *
 */
public class KeyPairGeneration {
	
	String 	clientPublicKeyFile = "./clientpublic.txt",
			clientPrivateKeyFile = "./clientprivate.txt";	

	public KeyFactory keyFactory;
	public PublicKey PUBK;
	public PrivateKey PRIK;
	public byte[] encodedClientPrivateKey, encodedClientPublicKey;

	
	public KeyPairGeneration() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		//initialize all variables that store keys
		
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    KeyPair keypair = keyGen.genKeyPair();
	    this.PRIK = keypair.getPrivate();
	    this.PUBK = keypair.getPublic();
		this.keyFactory = KeyFactory.getInstance("RSA");		
		this.encodedClientPrivateKey = this.PRIK.getEncoded();
	    this.encodedClientPublicKey = this.PUBK.getEncoded();
	}

	
	/**
	 * generate client's key pair (RSA)
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	
	public  void generateKeyPairClient() throws InvalidKeySpecException, IOException {
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedClientPublicKey);
		PUBK = keyFactory.generatePublic(publicKeySpec);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedClientPrivateKey);
		PRIK = keyFactory.generatePrivate(privateKeySpec);
		
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(PUBK.getEncoded());
		FileOutputStream fos = new FileOutputStream(clientPublicKeyFile);
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(PRIK.getEncoded());
		FileOutputStream fos1 = new FileOutputStream(clientPrivateKeyFile);
		fos1.write(pkcs8EncodedKeySpec.getEncoded());
		fos1.close();
	}
	
	/**
	 * load's client's public key from the file
	 * @param sPublicKey
	 * @return server's public key
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	public PublicKey loadPublicKey(File cPublicKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(cPublicKey.toPath());
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}
	
	/**
	 * loads private key from file
	 * @param cPrivateKey
	 * @return client's private key
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	
	public PrivateKey loadPrivateKey(File cPrivateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(cPrivateKey.toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}
}
