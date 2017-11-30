package Algorithm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import Object.AsyKey;
import Tools.PSVutility;

public class AsymEncrypt {

	public static KeyPair genRSAKeyPair(int keySize) {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(keySize);
			KeyPair keypair = keyGen.genKeyPair();
			return keypair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] storeKeyPairToByteArray(KeyPair keypair) throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream o = new ObjectOutputStream(b);
		o.writeObject(keypair);
		byte[] kpb = b.toByteArray();
		return kpb;
	}

	public KeyPair readKeyPairFromByteArray(byte[] kpb) throws IOException {
		ByteArrayInputStream bi = new ByteArrayInputStream(kpb);
		ObjectInputStream oi = new ObjectInputStream(bi);
		try {
			KeyPair keypair = (KeyPair) oi.readObject();
			return keypair;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		}
	}

	//////////////////////////////////////////////////
	public static boolean sign(File file, File saveTo, String method, PrivateKey privateKey) {
		try {
			PSVutility.SaveFile(saveTo, sign(PSVutility.ReadFile(file), method, privateKey));
			return true;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		}
	}

	public static byte[] sign(byte[] data, String method, PrivateKey privateKey) throws InvalidKeyException {
		try {
			Signature privateSignature = Signature.getInstance(method);
			privateSignature.initSign(privateKey);
			privateSignature.update(data);
			return privateSignature.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static boolean verify(File file, File sig, String method, PublicKey pub) {
		try {
			return verify(PSVutility.ReadFile(file), method, PSVutility.ReadFile(sig), pub);
		} catch (InvalidKeyException | SignatureException e) {
			e.printStackTrace();
			return false;
		}
	}

	public static boolean verify(byte[] data, String method, byte[] signature, PublicKey publicKey)
			throws InvalidKeyException, SignatureException {
		try {
			Signature publicSignature = Signature.getInstance(method);
			publicSignature.initVerify(publicKey);
			publicSignature.update(data);
			return publicSignature.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public static void savePublicKey(PublicKey k, File file) {
		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(k, RSAPublicKeySpec.class);
			saveToFile(file.getAbsolutePath(), pub.getModulus(), pub.getPublicExponent());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}

	public static void savePrivateKey(PrivateKey k, File file) {
		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPrivateKeySpec priv = fact.getKeySpec(k, RSAPrivateKeySpec.class);
			saveToFile(file.getAbsolutePath(), priv.getModulus(), priv.getPrivateExponent());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}

	public static void saveKeyPair(KeyPair keypair) {
		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(keypair.getPublic(), RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = fact.getKeySpec(keypair.getPrivate(), RSAPrivateKeySpec.class);
			saveToFile("public.key", pub.getModulus(), pub.getPublicExponent());
			saveToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}

	public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

	public static Key readKeyFromFile(String keyFileName, String Type) {
		try {
			InputStream in = new FileInputStream(keyFileName);
			ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
			try {
				BigInteger m = (BigInteger) oin.readObject();
				BigInteger e = (BigInteger) oin.readObject();
				KeyFactory keyFact = KeyFactory.getInstance("RSA");
				if (Type.equals("Private")) {
					return keyFact.generatePrivate(new RSAPrivateKeySpec(m, e));
				} else if (Type.equals("Public")) {
					return keyFact.generatePublic(new RSAPublicKeySpec(m, e));
				}
			} catch (Exception e) {
				throw new RuntimeException("Spurious serialisation error", e);
			} finally {
				oin.close();
			}
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return null;
	}

}
