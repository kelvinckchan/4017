package Algorithm;

import java.io.File;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import Tools.PSVutility;

public class PBEncrypt {

	private static char[] secret = null;
	final static int noIterations = 65536;
	final static int keyLength = 256;

	public static void setSecret(String s) {
		secret = s.toCharArray();
	}

	public static byte[] encrypt(byte[] data, char[] password, byte[] salt) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			PBEKeySpec spec = new PBEKeySpec(password, salt, noIterations, keyLength);
			SecretKey secretkey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			AlgorithmParameters params = cipher.getParameters();
			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			cipher.init(Cipher.ENCRYPT_MODE, secretkey, new IvParameterSpec(iv));
			byte[] cipherText = cipher.doFinal(data);

			return PSVutility.addByte(salt, iv, cipherText);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] decrpyt(byte[] data, char[] password) {
		try {
			byte[] salt = Arrays.copyOfRange(data, 0, 128);
			byte[] iv = Arrays.copyOfRange(data, 128, 128 + 16);
			byte[] ciphertext = Arrays.copyOfRange(data, 128 + 16, data.length);

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			PBEKeySpec spec = new PBEKeySpec(password, salt, noIterations, keyLength);
			SecretKey secretkey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretkey, new IvParameterSpec(iv));
			byte[] plaintext = cipher.doFinal(ciphertext);

			return plaintext;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] decrpyt(File file) {
		return decrpyt(PSVutility.ReadFile(file), secret);
	}

	public static byte[] encrypt(File pbe) {
		return encrypt(PSVutility.ReadFile(pbe), secret);
	}

	public static byte[] encrypt(byte[] byteArray) {
		return encrypt(byteArray, secret);
	}

	public static byte[] encrypt(byte[] data, char[] password) {
		return encrypt(data, password, PSVutility.GetSalt(128));
	}

	public static void genSecret(String newsecret) {
		File sec = new File("sessionKey");
		setSecret(newsecret);
		PSVutility.SaveFile(sec, encrypt(PSVutility.GetSalt(256)));
	}

	public static void encryptTo(File file, File saveTo) {
		PSVutility.SaveFile(saveTo, encrypt(file));
	}

	public static void decryptTo(File file, File saveTo, String secret) {
		PSVutility.SaveFile(saveTo, decrpyt(PSVutility.ReadFile(file), secret.toCharArray()));
	}

	public static void decryptTo(File file, File saveTo) {
		PSVutility.SaveFile(saveTo, decrpyt(file));
	}
}
