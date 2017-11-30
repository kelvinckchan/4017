import java.io.File;
import java.security.KeyPair;
import java.security.Security;
import java.security.SignatureException;
import java.util.*;

import javax.crypto.SecretKey;

import Algorithm.*;
import Object.*;

public class PSV {

	List<User> userList = new ArrayList<User>();
	List<AsyKey> asyList = new ArrayList<AsyKey>();
	List<SymKey> symList = new ArrayList<SymKey>();

	private void run() {
		PBE();
		// Sym();
		// RSA();
		// CheckSum();

		System.out.println("Done.");
	}

	public void PBE() {
		// Generate new secret for password base encryption,
		String password = "12345";
		PBEncrypt.genSecret(password);

		// Create User
		User u1 = new User().setID("id").setName("Name").setPassword("Password").setRemark("Remark");
		userList.add(u1);

		// Use PBE to encrypt
		PBEncrypt.encryptTo(new File("Data/PBEneedEncrypt.txt"), new File("Data/PBEEncrpted.txt"));
		System.out.println("encrypted");
		// No need Password if set when start
		PBEncrypt.setSecret(password);
		PBEncrypt.decryptTo(new File("Data/PBEEncrpted.txt"), new File("Data/PBEEncrptedDecrypted.txt"));
		System.out.println("decrypted with password set earlier");
		// Use Password to decrypt
		PBEncrypt.decryptTo(new File("Data/PBEEncrpted.txt"), new File("Data/PBEEncrptedDecrypted.txt"), password);
		System.out.println("decrypted with password");

		// Use wrong Password to decrypt, can not decrypt
		PBEncrypt.decryptTo(new File("Data/PBEEncrpted.txt"), new File("Data/PBEWrongDecrypted.txt"), "Wrongpw");
		System.out.println("decrypted with wrong password");

	}

	public void Sym() {
		// Generate Sym Key, enter KeyTyp(AES/DES/DESese) and KeySize:
		// AES: 128/192/256
		// DES: 56
		// DEsede: 112/168
		SecretKey DESede168 = SymEncrypt.genSymKey("DESede", 168);

		// put key in key Object contain other info
		SymKey symk1 = new SymKey("keyName", "keyInfo", SymEncrypt.genSymKey("AES", 128));
		SymKey symk2 = new SymKey("keyName", "keyInfo", SymEncrypt.genSymKey("DES", 56));
		SymKey symk3 = new SymKey("keyName", "keyInfo", DESede168);
		// Save generated key Object to list
		symList.add(symk1);
		symList.add(symk2);
		symList.add(symk3);

		// select method and SecretKey to Encrypt File and save To smwhere
		// Method:
		// "/ECB/PKCS5Padding"
		// "/CBC/PKCS5Padding"
		// "/CFB/PKCS5Padding"
		// "/OFB/PKCS5Padding"
		// "/CTR/PKCS5Padding"

		String method = "/ECB/PKCS5Padding";
		SymEncrypt.encryptTo(method, symk1.getSeckey(), new File("Data/FileNeedEncrypt.txt"),
				new File("Data/SaveToEncrypted.txt"));
		System.out.println("encrypted");
		// Use same method and SecretKey to Decrypt
		SymEncrypt.decryptTo(method, symk1.getSeckey(), new File("Data/SaveToEncrypted.txt"),
				new File("Data/SaveToEncryptedDecrypted.txt"));
		System.out.println("decrypted");
	}

	public void RSA() {
		// Generate RSA KeyPair, set keysize (1024/2048/4096-bit) RSA key
		int RSAkeySize = 1024;
		KeyPair rsaKeypair1 = AsymEncrypt.genRSAKeyPair(RSAkeySize);

		// put key in key Object contain other info
		AsyKey keypair1 = new AsyKey("keyName", "keyInfo", rsaKeypair1.getPublic(), rsaKeypair1.getPrivate());
		AsyKey pubkey1 = new AsyKey("keyName", "keyInfo", rsaKeypair1.getPublic(), null);
		AsyKey prikey1 = new AsyKey("keyName", "keyInfo", null, rsaKeypair1.getPrivate());
		// Save generated key Object to list
		asyList.add(keypair1);
		asyList.add(pubkey1);
		asyList.add(prikey1);

		// Digital Signature, hash method "MD5withRSA"/"SHA1withRSA", select file needs
		// signing, where the signature save to
		String SigningMethod = "SHA1withRSA";
		// sign with private key
		boolean TrueIfSignSucess = AsymEncrypt.sign(new File("Data/FileNeedSigning.txt"),
				new File("Data/SignatureSaveTo.txt"), SigningMethod, keypair1.getPrivateKey());
		System.out.println("Signed> " + TrueIfSignSucess);

		// verify with public key, need to be same keypair of the private key that
		// signed the file
		boolean isVerifyMatch = AsymEncrypt.verify(new File("Data/FileNeedSigning.txt"),
				new File("Data/SignatureSaveTo.txt"), SigningMethod, keypair1.getPublicKey());
		System.out.println("isVerifyMatch> " + isVerifyMatch);

		// Fake Sign cannot Verify
		boolean isFakeVerifyMatch = AsymEncrypt.verify(new File("Data/FileNeedSigning.txt"),
				new File("Data/FakeSign.txt"), SigningMethod, keypair1.getPublicKey());
		System.out.println("isFakeVerifyMatch> " + isFakeVerifyMatch);
	}

	public void CheckSum() {
		// Select a File, generate a String of CheckSum, Select HashMode MD5/SHA-1
		// Just Show the Hash String is ok
		String HashMode = "MD5";
		String hash = CryptoHash.getCheckSum(HashMode, new File("Data/FileNeedSigning.txt"));

		System.out.println("The CheckSum> " + hash);
	}

	public static void main(String[] args) {
		Security.setProperty("crypto.policy", "unlimited");
		PSV psv = new PSV();
		psv.run();

	}
}
