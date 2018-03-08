package main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Launcher {
	public static void main(String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] data = "Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! ".getBytes();
		Random r = new Random();
		byte[] key = new byte[16];
		r.nextBytes(key);
		Encryptor e = new Encryptor("CFB", key);
		System.out.println("Data: \"Hello World!\"");
		byte[] encrypted = e.encrypt(data);
		String encryptedString = new String(encrypted);
		System.out.printf("Encrypted Data: %s\n", encryptedString);
		String decrypted = new String(e.decrypt(encrypted));
		System.out.printf("Decrypted Data: %s\n", decrypted);
		
	}
}
