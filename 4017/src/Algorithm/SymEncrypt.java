package Algorithm;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Object.SymKey;
import Tools.PSVutility;

public class SymEncrypt {

	public static SecretKey genSymKey(String method, int keysize) {
		try {
			KeyGenerator keygen = KeyGenerator.getInstance(method);
			keygen.init(keysize);
			return keygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void encryptTo(String method, SecretKey seckey, File file, File saveTo) {
		PSVutility.SaveFile(saveTo, encrypt(method, seckey, PSVutility.ReadFile(file)));
	}

	public static void decryptTo(String method, SecretKey seckey, File file, File saveTo) {
		PSVutility.SaveFile(saveTo, decrypt(method, seckey, PSVutility.ReadFile(file)));
	}

	public SecretKey readKey(String type, byte[] rawkey) throws Exception {
		switch (type) {
		case "DES":
			return readDESKey(rawkey);
		case "DESede":
			return readDESedeKey(rawkey);
		case "AES":
			return readAESKey(rawkey);
		default:
			return null;
		}
	}

	public SecretKey readDESKey(byte[] rawkey) throws Exception {
		SecretKeyFactory f = SecretKeyFactory.getInstance("DES");
		SecretKey skey = f.generateSecret(new DESKeySpec(rawkey));
		return skey;
	}

	public SecretKey readDESedeKey(byte[] rawkey) throws Exception {
		SecretKeyFactory f = SecretKeyFactory.getInstance("DESede");
		SecretKey skey = f.generateSecret(new DESedeKeySpec(rawkey));
		return skey;
	}

	public SecretKey readAESKey(byte[] rawkey) throws Exception {
		SecretKey skey = new SecretKeySpec(rawkey, "AES");
		return skey;
	}

	public static boolean needIV(String algo) {
		if (algo.contains("CBC") || algo.contains("CFB") || algo.contains("OFB") || algo.contains("CTR"))
			return true;
		return false;
	}

	public static byte[] encrypt(String method, SecretKey sKey, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance(sKey.getAlgorithm() + method);
			if (needIV(cipher.getAlgorithm())) {
				cipher.init(Cipher.ENCRYPT_MODE, sKey, PSVutility.GetIVSpec(cipher.getBlockSize()));
			} else {
				cipher.init(Cipher.ENCRYPT_MODE, sKey);
			}
			byte[] iv = cipher.getIV();
			return iv != null ? PSVutility.concateByte(iv, cipher.doFinal(data)) : cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] decrypt(String method, SecretKey sKey, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance(sKey.getAlgorithm() + method);
			if (needIV(cipher.getAlgorithm())) {
				byte[] iv = Arrays.copyOfRange(data, 0, cipher.getBlockSize());
				data = Arrays.copyOfRange(data, cipher.getBlockSize(), data.length);
				cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(iv));
			} else {
				cipher.init(Cipher.DECRYPT_MODE, sKey);
			}
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return null;
	}

}
