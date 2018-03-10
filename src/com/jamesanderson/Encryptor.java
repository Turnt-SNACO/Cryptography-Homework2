/*
	Author: James Anderson
	Using: AES.java and Util.java from http://www.devkb.org/java/50-AES-256-bits-encrypter-decrypter-Java-source-code
	Class: ICSI 426
	Semester: Spring 2018
 */

package com.jamesanderson;

import org.jetbrains.annotations.Contract;

import java.awt.Point;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.Raster;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;

class Encryptor {
	private final int BLOCK_SIZE = 16;
	private int postfix;
	private String mode;
	//private byte[] key;
	private byte[] iv;
	private AES c, d;

	/**
	 * Constructs the Encryptor with specified Key and IV
	 *
	 * @param mode - ECB, CBC, CFB, OFB
	 * @param key - byte[16]
	 * @param iv - byte[16]
	 * @throws NoSuchAlgorithmException ignore
	 * @throws NoSuchPaddingException ignore
	 * @throws InvalidKeyException ignore
	 * @author James Anderson
	 */
	Encryptor(String mode, byte[] key, byte[] iv)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.mode = mode;
		//this.key = key;
		this.iv = iv;
		c = new AES();
		d = new AES();
		//c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		//d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
		c.setKey(key);
		d.setKey(key);
	}

	/**
	 * Encrypts data using AES
	 *
	 * @param data - byte[] containing data to encrypt
	 * @return byte[]
	 * @throws BadPaddingException ignore
	 * @throws IllegalBlockSizeException ignore
	 * @author James Anderson
	 */
	byte[] encrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException {

		byte[][] blocks = toBlocks(data);
		int blockCount = blocks.length;
		byte[] feedback;
		switch (mode) {
			case "ECB":
				for (int block = 0; block < blockCount; block++) {
					blocks[block] = c.encrypt(blocks[block]);
				}
				break;
			case "CBC":
				for (int byt = 0; byt < BLOCK_SIZE; byt++) {
					blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
				}
				blocks[0] = c.encrypt(blocks[0]);
				for (int block = 1; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ blocks[block - 1][byt]);
					}
					blocks[block] = c.encrypt(blocks[block]);
				}
				break;
			case "CFB":
				byte[][] ciphertext = blocks;
				feedback = iv;
				for (int block = 0; block < blockCount; block++) {
					feedback = c.encrypt(feedback);
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						ciphertext[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);

					}
					feedback = ciphertext[block];
				}
				blocks = ciphertext;
				break;

			case "OFB":
				feedback = c.encrypt(iv);
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
						feedback = c.encrypt(feedback);
					}
				}
				break;
		}
		return toData(blocks);
	}
	
	/**
	 * Encrypts data using AES
	 *
	 * @param data - byte[] containing data to encrypt
	 * @return byte[]
	 * @throws BadPaddingException ignore
	 * @throws IllegalBlockSizeException ignore
	 * @author James Anderson
	 */
	private byte[] encryptWithError(byte[] data, boolean plaintextError) throws IllegalBlockSizeException, BadPaddingException {
		byte[][] blocks = toBlocks(data);
		int blockCount = blocks.length;
		System.out.print("\t\tIntroducing error in block "+blockCount/3+" of ");
		if (plaintextError)
			System.out.println("plaintext...");
		else
			System.out.println("ciphertext...");
		byte[] feedback;
		byte[] error = {0,3,4,1,2,6,2,9,6,7,1,5,0,6,3,8};
		switch (mode) {
			case "ECB":
				for (int block = 0; block < blockCount; block++) {
					if (block==blockCount/3){
						if (plaintextError) {
							blocks[block] = c.encrypt(error);
						}else {
							blocks[block] = error;
						}
					}
					else
						blocks[block] = c.encrypt(blocks[block]);
				}
				break;
			case "CBC":
				for (int byt = 0; byt < BLOCK_SIZE; byt++) {
					blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
				}
				blocks[0] = c.encrypt(blocks[0]);
				for (int block = 1; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						if (block==blockCount/3){
							if (plaintextError) {
								blocks[block] = c.encrypt(error);
							}
							else{
								blocks[block] = error;
							}
						}
						else
							blocks[block][byt] = (byte) (blocks[block][byt] ^ blocks[block - 1][byt]);
					}
					blocks[block] = c.encrypt(blocks[block]);
				}
				break;
			case "CFB":
				byte[][] ciphertext = blocks;
				feedback = iv;
				for (int block = 0; block < blockCount; block++) {
					feedback = c.encrypt(feedback);
					if (block==blockCount/3){
						if (plaintextError) {
							blocks[block] = c.encrypt(error);
						}
						else{
							blocks[block] = error;
						}
					}
					else {
						for (int byt = 0; byt < BLOCK_SIZE; byt++) {
							ciphertext[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
						}
					}
					feedback = ciphertext[block];
				}
				blocks = ciphertext;
				break;

			case "OFB":
				feedback = c.encrypt(iv);
				for (int block = 0; block < blockCount; block++) {
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						if (block==blockCount/3){
							if (plaintextError) {
								blocks[block] = c.encrypt(error);
							}
							else {
								blocks[block] = error;
							}
						}
						else
							blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
						feedback = c.encrypt(feedback);
					}
				}
				break;
		}
		return toData(blocks);
	}

	/**
	 * Decrypts data using AES
	 *
	 * @param data - byte[] to be decrypted
	 * @return byte[], null if unsuccessful
	 * @throws IllegalBlockSizeException ignore
	 * @author James Anderson
	 */
	byte[] decrypt(byte[] data) throws IllegalBlockSizeException {
		// int blockCount = data.length / 16;
		byte[][] blocks = toBlocks(data);
		int blockCount = blocks.length;
		try {
			switch (mode) {
				case "ECB":
					for (int block = 0; block < blockCount; block++) {
						blocks[block] = d.decrypt(blocks[block]);
					}
					break;
				case "CBC":
					byte[] prev = new byte[BLOCK_SIZE];
					System.arraycopy(blocks[0],0,prev,0,BLOCK_SIZE);
					blocks[0] = d.decrypt(blocks[0]);
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
					}
					for (int block = 1; block < blockCount; block++) {
						byte[] nextPrev = blocks[block];
						blocks[block] = d.decrypt(blocks[block]);
						for (int byt = 0; byt < 16; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ prev[byt]);
						}
						prev = nextPrev;
					}
					break;
				case "CFB":
					byte[][] ciphertext = new byte[blockCount][BLOCK_SIZE];
					for (byte[] block : blocks) {
						System.arraycopy(block, 0, ciphertext[Arrays.asList(blocks).indexOf(block)], 0, BLOCK_SIZE);
					}
					byte[] backfeed = iv;
					for (int block = 0; block < blockCount; block++) {
						backfeed = c.encrypt(backfeed);
						for (int byt = 0; byt < BLOCK_SIZE; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ backfeed[byt]);
						}
						backfeed = ciphertext[block];
					}
					break;
				case "OFB":
					byte[] feedback = c.encrypt(iv);
					for (int block = 0; block < blockCount; block++) {
						for (int byt = 0; byt < BLOCK_SIZE; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
							feedback = c.encrypt(feedback);
						}
					}
					break;
			}
			return toData(blocks);
		} catch (Exception e) {
			System.out.println("BAD KEY");
			return null;
		}
	}

	/**
	 * Encrypts an image located at pathToInput while preserving the header and
	 * saves to pathToOutput. Returns false if unsuccessful.
	 * @param inputURL String containing url to input file.
	 * @param outputURL String containing url to output file.
	 * @return boolean
	 * @throws IllegalBlockSizeException ignore
	 * @throws BadPaddingException ignore
	 */
	boolean encryptImage(String inputURL, String outputURL)
			throws IllegalBlockSizeException, BadPaddingException {
		try {
			BufferedImage image = ImageIO.read(new File(inputURL));
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] encrypted = encrypt(pixels);
			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(encrypted, encrypted.length), new Point()));
			ImageIO.write(outImage, "jpg", new File(outputURL));
		} catch (IOException e) {
			System.out.println("Error with image path!");
			return false;
		}
		return true;
	}


	/**
	 * Decrypts an image located at pathToInput while preserving the header and
	 * saves to pathToOutput. Returns false if unsuccessful.
	 *
	 * @param pathToInput - String with URL to input file
	 * @param pathToOutput - String with URL to output file
	 * @throws IllegalBlockSizeException ignore
	 * @throws BadPaddingException ignore
	 * @return boolean
	 */
	boolean decryptImage(String pathToInput, String pathToOutput)
			throws IllegalBlockSizeException, BadPaddingException {
		File input = new File(pathToInput);
		File output = new File(pathToOutput);
		try {
			BufferedImage image = ImageIO.read(input);
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] decrypted = decrypt(pixels);
			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(decrypted, decrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", output);
		} catch (IOException e) {
			System.out.println("Error with image path!");
			return false;
		}
		return true;
	}
	public void encryptAndDecryptImageWithPtError(String inputURL, String outputUrlEnc, String outputUrlDec){
		encryptAndDecryptImageWithError(inputURL, outputUrlEnc, outputUrlDec, true);
	}
	public void encryptAndDecryptImageWithCtError(String inputURL, String outputUrlEnc, String outputUrlDec){
		encryptAndDecryptImageWithError(inputURL, outputUrlEnc, outputUrlDec, false);
	}


	public void encryptAndDecryptImageWithError(String inputURL, String outputUrlEnc, String outputUrlDec, boolean ptError) {
		File input = new File(inputURL);
		File outputEnc = new File(outputUrlEnc);
		File outputDec = new File(outputUrlDec);
		try {
			BufferedImage image = ImageIO.read(input);
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] encrypted = encryptWithError(pixels, ptError);
			byte[] decrypted = decrypt(encrypted);

			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(encrypted, encrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputEnc);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(decrypted, decrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputDec);
		} catch (IOException e) {
			System.out.println("Error with image path!");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

	}


	public void encryptAndDecryptImage(String inputURL, String outputUrlEnc, String outputUrlDec) {
		File input = new File(inputURL);
		File outputEnc = new File(outputUrlEnc);
		File outputDec = new File(outputUrlDec);
		try {
			BufferedImage image = ImageIO.read(input);
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] encrypted = encrypt(pixels);
			byte[] decrypted = decrypt(encrypted);

			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(encrypted, encrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputEnc);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(decrypted, decrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputDec);
		} catch (IOException e) {
			System.out.println("Error with image path!");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}



	/**
	 * Transforms byte[] to byte[][] (Array of blocks)
	 *
	 * @param data - data to be transformed into array of 16 byte blocks
	 * @return byte[][]
	 * @author James Anderson
	 */
	private byte[][] toBlocks(byte[] data) {
		int blockCount = data.length / 16;
		postfix = 0;
		if (((double) data.length / 16.0) % 16 != 0) {
			blockCount += 1;
		}
		byte[][] blocks = new byte[blockCount][BLOCK_SIZE];
		for (int block = 0; block < blockCount; block++) {
			for (int byt = 16  *block, dataByte = 0; byt < 16 *  block + 16; byt++, dataByte++) {
				try {
					blocks[block][dataByte] = data[byt];
				} catch (ArrayIndexOutOfBoundsException e) {
					postfix++;
					if (dataByte == 15)
						blocks[block][dataByte] = (byte) postfix;
					else
						blocks[block][dataByte] = (byte) 0x00;
				}
			}
		}
		return blocks;
	}

	/**
	 * Transforms byte[][] (Array of blocks) to byte[]
	 *
	 * @param blocks - array of 16 byte blocks to be transformed to byte array
	 * @return byte[]
	 * @author James Anderson
	 */
	@Contract(pure = true)
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
