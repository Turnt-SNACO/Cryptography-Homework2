package main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {
	String mode;
	byte[] key, iv;
	Cipher c, d;
	private final int BLOCK_SIZE = 16;

	/**
	 * Initializes the Encryptor with no padding and a random IV
	 * 
	 * The Cipher is initialized with ECB
	 * mode but the mode will not do anything since blocks will be handled manually
	 * by the Encryptor
	 * 
	 * @param mode
	 * @param key
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @author James Anderson
	 */
	public Encryptor(String mode, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		this.mode = mode;
		c = Cipher.getInstance("AES/ECB/NoPadding");
		d = Cipher.getInstance("AES/ECB/NoPadding");
		c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
		this.key = key;
		iv = new byte[BLOCK_SIZE];
		Random r = new Random();
		r.nextBytes(iv);
	}
	
	/**
	 * Initializes the Encryptor with no padding with a specified IV
	 * 
	 * The Cipher is initialized with ECB
	 * mode but the mode will not do anything since blocks will be handled manually
	 * by the Encryptor
	 * 
	 * @param mode
	 * @param key
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @author James Anderson
	 */
	public Encryptor(String mode, byte[] key, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this(mode,key);
		iv = new byte[BLOCK_SIZE];
		this.iv=iv;
	}

	/**
	 * Encrypts data using AES
	 * 
	 * @param data
	 * @param key
	 * @return byte[]
	 * @throws InvalidKeyException
	 * @author James Anderson
	 * @throws BadPaddingException 
	 */
	public byte[] encrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException {
		int blockCount = data.length / 16;
		byte[][] blocks = toBlocks(data);
		byte[] feedback;
		switch (mode) {
			case "ECB":
				System.out.println("Mode: ECB");
				for (int block = 0; block < blockCount; block++) {
					blocks[block] = c.doFinal(blocks[block]);
				}
				break;
			case "CBC":
				for (int byt = 0; byt < BLOCK_SIZE; byt++){
					blocks[0][byt]= (byte) (blocks[0][byt] ^ iv[byt]);
				}
				blocks[0] = c.doFinal(blocks[0]);
				for (int block = 1; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ blocks[block-1][byt]);
					}
					blocks[block] = c.doFinal(blocks[block]);
				}
				break;
			case "CFB":
				feedback = c.doFinal(iv);
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
					}
					feedback = blocks[block];
				}
				break;
			case "OFB":
				feedback = c.doFinal(iv);
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
						feedback=c.doFinal(feedback);
					}
				}
				break;
		}
		return toData(blocks);
	}

	/**
	 * Decrypts data using AES
	 * 
	 * @param data
	 * @return byte[], null if unsuccessfull
	 * @throws IllegalBlockSizeException
	 * @author James Anderson
	 */
	public byte[] decrypt(byte[] data) throws IllegalBlockSizeException {
		int blockCount = data.length / 16;
		byte[][] blocks = toBlocks(data);
		try {
		switch (mode) {
			case "ECB":
				System.out.println("Mode: ECB");
				for (int block = 0; block < blockCount; block++) {
					blocks[block] = d.doFinal(blocks[block]);
				}
				break;
			case "CBC":
				byte[] prev = new byte[BLOCK_SIZE];
				prev=blocks[0];
				blocks[0] = d.doFinal(blocks[0]);
				for (int byt = 0; byt < BLOCK_SIZE; byt++) {
					blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
				}
				for (int block = 1; block < blockCount; block++) {
					byte[] nextPrev = blocks[block];
					blocks[block]= d.doFinal(blocks[block]);
					for (int byt = 0; byt < 16; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ prev[byt]);
					}
					prev=nextPrev;
				}
				break;
			case "CFB":
				byte[][] ciphertext = blocks;
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						if (block == 0) {
							byte[] temp = c.doFinal(iv);
							blocks[block][byt] = (byte) (ciphertext[block][byt] ^ temp[byt]);
						}
						else {
							blocks[block][byt] = (byte) (ciphertext[block][byt] ^ c.doFinal(ciphertext[block-1])[byt]);
						}
					}
				}
				break;
			case "OFB":
				byte[] feedback = c.doFinal(iv);
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
						feedback=c.doFinal(feedback);
					}
				}
				break;
		}
		return toData(blocks);
		}	catch (BadPaddingException e) {
			System.out.println("BAD KEY");
			return null;
		}
	}

	/**
	 * Transforms byte[] to byte[][] (Array of blocks)
	 * 
	 * @param data
	 * @return byte[][]
	 * @author James Anderson
	 */
	private byte[][] toBlocks(byte[] data) {
		int blockCount = data.length / 16;
		byte[][] blocks = new byte[blockCount][BLOCK_SIZE];
		for (int block = 0; block < blockCount; block++) {
			for (int byt = 16 * block, dataByte = 0; byt < 16 * block + 16; byt++, dataByte++) {
				blocks[block][dataByte] = data[byt];
			}
		}
		return blocks;
	}

	/**
	 * Transforms byte[][] (Array of blocks) to byte[]
	 * 
	 * @param blocks
	 * @return byte[]
	 * @author James Anderson
	 */
	private byte[] toData(byte[][] blocks) {
		int blockCount = blocks.length;
		byte[] data = new byte[blockCount * 16];
		for (int block = 0; block < blockCount; block++) {
			for (int byt = 16 * block, dataByte = 0; byt < 16 * block + 16; byt++, dataByte++) {
				data[byt] = blocks[block][dataByte];
			}
		}
		return data;
	}
}
