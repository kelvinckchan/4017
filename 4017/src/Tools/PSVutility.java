package Tools;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

import javax.crypto.spec.IvParameterSpec;

public class PSVutility {

	public static byte[] ReadFile(File file) {
		try {
			return Files.readAllBytes(Paths.get(file.getAbsolutePath()));
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void SaveFile(File file, byte[] data) {
		try {
			if (!file.exists())
				file.createNewFile();
			Files.write(Paths.get(file.getAbsolutePath()), data);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static byte[] addByte(byte[]... b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		for (byte[] byt : b)
			try {
				outputStream.write(byt);
			} catch (IOException e) {
				e.printStackTrace();
			}
		return outputStream.toByteArray();
	}

	public static byte[] GetSalt(int saltSize) {
		Random r = new SecureRandom();
		byte[] salt = new byte[saltSize];
		r.nextBytes(salt);
		return salt;
	}

	public static IvParameterSpec GetIVSpec(int ivSize) {
		byte iv[] = new byte[ivSize];
		SecureRandom ivsecRandom = new SecureRandom();
		ivsecRandom.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
}
