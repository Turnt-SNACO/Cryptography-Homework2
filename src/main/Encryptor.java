package main;

import java.awt.Point;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.Raster;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

public class Encryptor {
	private final int BLOCK_SIZE = 16;

	private String mode;
	private byte[] key, iv;
	private Cipher c, d;

	/**
	 * Initializes the Encryptor with no padding and a random IV
	 * 
	 * The Cipher is initialized with ECB mode but the mode will not do anything
	 * since blocks will be handled manually by the Encryptor
	 * 
	 * @param mode
	 * @param key
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @author James Anderson
	 */
	public Encryptor(String mode, byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
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
	 * The Cipher is initialized with ECB mode but the mode will not do anything
	 * since blocks will be handled manually by the Encryptor
	 * 
	 * @param mode
	 * @param key
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @author James Anderson
	 */
	public Encryptor(String mode, byte[] key, byte[] iv)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this(mode, key);
		iv = new byte[BLOCK_SIZE];
		this.iv = iv;
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
		System.out.println("Blocks: " + ((double) data.length / 16.0));
		int blockCount = data.length / 16;
		// if (((double)data.length / 16.0) % 16 != 0) {
		// blockCount+=1;
		// }
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
				System.out.println("Mode: CBC");
				for (int byt = 0; byt < BLOCK_SIZE; byt++) {
					blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
				}
				blocks[0] = c.doFinal(blocks[0]);
				for (int block = 1; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ blocks[block - 1][byt]);
					}
					blocks[block] = c.doFinal(blocks[block]);
				}
				break;
			case "CFB":
				System.out.println("Mode: CFB");
				byte[][] ciphertext = blocks;
				feedback = iv;
				for (int block = 0; block < blockCount; block++) {
					feedback = c.doFinal(feedback);
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						ciphertext[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);

					}
					feedback = ciphertext[block];
				}
				blocks = ciphertext;
				break;

			case "OFB":
				System.out.println("Mode: OFB");
				feedback = c.doFinal(iv);
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
						feedback = c.doFinal(feedback);
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
					prev = blocks[0];
					blocks[0] = d.doFinal(blocks[0]);
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
					}
					for (int block = 1; block < blockCount; block++) {
						byte[] nextPrev = blocks[block];
						blocks[block] = d.doFinal(blocks[block]);
						for (int byt = 0; byt < 16; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ prev[byt]);
						}
						prev = nextPrev;
					}
					break;
				case "CFB":
					byte[][] ciphertext = new byte[blockCount][BLOCK_SIZE];
					for (int x = 0; x < blockCount; x++) {
						for (int y = 0; y < BLOCK_SIZE; y++) {
							ciphertext[x][y] = blocks[x][y];
						}
					}
					byte[] backfeed = iv;
					for (int block = 0; block < blockCount; block++) {
						backfeed = c.doFinal(backfeed);
						for (int byt = 0; byt < BLOCK_SIZE; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ backfeed[byt]);
						}
						backfeed = ciphertext[block];
					}
					break;
				case "OFB":
					byte[] feedback = c.doFinal(iv);
					for (int block = 0; block < blockCount; block++) {
						for (int byt = 0; byt < BLOCK_SIZE; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
							feedback = c.doFinal(feedback);
						}
					}
					break;
			}
			return toData(blocks);
		} catch (BadPaddingException e) {
			System.out.println("BAD KEY");
			return null;
		}
	}
	/**
	 * Encrypts an image located at pathToInput while preserving the header and saves to pathToOutput.
	 * Returns false if unsuccessful.
	 * @param pathToInput
	 * @param pathToOutput
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @return boolean
	 */
	public boolean encryptImage(String pathToInput, String pathToOutput) throws IllegalBlockSizeException, BadPaddingException {
		File input = new File(pathToInput);
		File output = new File(pathToOutput);
		try {
		BufferedImage image = ImageIO.read(input);
		byte[] pixels = ( (DataBufferByte) image.getRaster().getDataBuffer() ).getData();
		byte[] encrypted = encrypt(pixels);
		BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
		outImage.setData(Raster.createRaster(outImage.getSampleModel(), new DataBufferByte(encrypted, encrypted.length), new Point()));
		ImageIO.write(outImage, "jpg", output);
		}catch (IOException e) {
			System.out.println("Error with image path!");
			return false;
		}
		return true;
	}
	/**
	 * Decrypts an image located at pathToInput while preserving the header and saves to pathToOutput.
	 * Returns false if unsuccessful.
	 * @param pathToInput
	 * @param pathToOutput
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @return boolean
	 */
	public boolean decryptImage(String pathToInput, String pathToOutput) throws IllegalBlockSizeException, BadPaddingException {
		File input = new File(pathToInput);
		File output = new File(pathToOutput);
		try {
		BufferedImage image = ImageIO.read(input);
		byte[] pixels = ( (DataBufferByte) image.getRaster().getDataBuffer() ).getData();
		byte[] decrypted = decrypt(pixels);
		BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
		outImage.setData(Raster.createRaster(outImage.getSampleModel(), new DataBufferByte(decrypted, decrypted.length), new Point()));
		ImageIO.write(outImage, "jpg", output);
		}catch (IOException e) {
			System.out.println("Error with image path!");
			return false;
		}
		return true;
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
		// if (((double)data.length / 16.0) % 16 != 0) {
		// blockCount+=1;
		// }
		byte[][] blocks = new byte[blockCount][BLOCK_SIZE];
		for (int block = 0; block < blockCount; block++) {
			for (int byt = 16 * block, dataByte = 0; byt < 16 * block + 16; byt++, dataByte++) {
				try {
					blocks[block][dataByte] = data[byt];
				} catch (ArrayIndexOutOfBoundsException e) {
					blocks[block][dataByte] = (byte) 0x00;
				}
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

	public byte[] getKey() {
		return key;
	}
}
