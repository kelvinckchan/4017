package Algorithm;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import Tools.PSVutility;

public class CryptoHash {

	public static byte[] getCheckSum(String mode, byte[] data) {
		try {
			MessageDigest md = MessageDigest.getInstance(mode);
			md.update(data);
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String getCheckSum(String mode, File file) {
		return new HexBinaryAdapter().marshal(getCheckSum(mode, PSVutility.ReadFile(file)));
	}

}
