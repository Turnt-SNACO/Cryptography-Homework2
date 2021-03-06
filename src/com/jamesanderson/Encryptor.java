/*
	Author: James Anderson
	Using: AES.java and Util.java from http://www.devkb.org/java/50-AES-256-bits-encrypter-decrypter-Java-source-code
	Class: ICSI 426
	Semester: Spring 2018
 */

package com.jamesanderson;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.Raster;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

class Encryptor {
	private final int BLOCK_SIZE = 16;
	private String mode;
	//private byte[] key;
	private byte[] iv;
	private AES c;

	/**
	 * Constructs the Encryptor with specified Key and IV
	 *
	 * @param mode - ECB, CBC, CFB, OFB
	 * @param key - byte[16]
	 * @param iv - byte[16]
	 * @throws NoSuchAlgorithmException ignore
	 * @throws NoSuchPaddingException ignore
	 * @throws InvalidKeyException ignore
	 *
	 */
	Encryptor(String mode, byte[] key, byte[] iv)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.mode = mode;
		this.iv = iv;
		c = new AES();
		c.setKey(key);
	}

	/**
	 * Encrypts data using AES block cipher
	 *
	 * @param data - byte[] containing data to encrypt
	 * @return byte[]
	 * @throws BadPaddingException ignore
	 * @throws IllegalBlockSizeException ignore
	 *
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
				byte[][] ciphertext = new byte[blockCount][BLOCK_SIZE];
				for (int i = 0; i < blockCount; i++){
					System.arraycopy(blocks[i],0,ciphertext[i],0,BLOCK_SIZE);
				}
				feedback = new byte[BLOCK_SIZE];
				System.arraycopy(iv,0,feedback,0,BLOCK_SIZE);
				for (int block = 0; block < blockCount; block++) {
					feedback = c.encrypt(feedback);
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						ciphertext[block][byt] = (byte) (blocks[block][byt] ^ feedback[byt]);
					}
					System.arraycopy(ciphertext[block],0,feedback,0,BLOCK_SIZE);
				}
				for (int i = 0; i < blockCount; i++){
					System.arraycopy(ciphertext[i],0,blocks[i]  ,0,BLOCK_SIZE);
				}
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
	 * Encrypts data using AES block cipher
	 *
	 * @param data - byte[] containing data to encrypt
	 * @return byte[]
	 * @throws BadPaddingException ignore
	 * @throws IllegalBlockSizeException ignore
	 *
	 */
	private byte[] encryptWithError(byte[] data, boolean plaintextError) throws IllegalBlockSizeException, BadPaddingException, NullPointerException {
		Random r = new Random();
		if (plaintextError){
			byte[][] blocks = toBlocks(data);
			r.nextBytes(blocks[45540]);
			return encrypt(toData(blocks));
		}
		else {
			byte[] encrypted = encrypt(data);
			byte[][] blocks = toBlocks(encrypted);
			r.nextBytes(blocks[45540]);
			encrypted = toData(blocks);
			return encrypted;
		}
	}

	/**
	 * Gets the number of blocks affected by data corruption
	 * @param original - the original data before encryption
	 * @param corrupted - the decrypted data after encryption
	 * @return int
	 */
	private int corruptedBlocks(byte[] original, byte[] corrupted){
		int count = 0;
		for (int x = 0; x < original.length; x++) {
			if (original[x]!=corrupted[x]){
				count++;
			}
		}
		int blocksCorrupted=count/16;
		if (count%16!=0){
			blocksCorrupted+=1;
		}
		return blocksCorrupted;
	}

	/**
	 * Decrypts data using AES
	 *
	 * @param data - byte[] to be decrypted
	 * @return byte[], null if unsuccessful
	 * @throws IllegalBlockSizeException ignore
	 *
	 */
	@Nullable
	private byte[] decrypt(byte[] data) throws IllegalBlockSizeException {
		// int blockCount = data.length / 16;
		byte[][] blocks = toBlocks(data);
		int blockCount = blocks.length;
		try {
			switch (mode) {
				case "ECB":
					for (int block = 0; block < blockCount; block++) {
						blocks[block] = c.decrypt(blocks[block]);
					}
					break;
				case "CBC":
					byte[] prev = new byte[BLOCK_SIZE];
					System.arraycopy(blocks[0],0,prev,0,BLOCK_SIZE);
					blocks[0] = c.decrypt(blocks[0]);
					for (int byt = 0; byt < BLOCK_SIZE; byt++) {
						blocks[0][byt] = (byte) (blocks[0][byt] ^ iv[byt]);
					}
					for (int block = 1; block < blockCount; block++) {
						byte[] nextPrev = new byte[BLOCK_SIZE];
						System.arraycopy(blocks[block],0,nextPrev,0,BLOCK_SIZE);
						blocks[block] = c.decrypt(blocks[block]);
						for (int byt = 0; byt < 16; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ prev[byt]);
						}
						System.arraycopy(nextPrev,0,prev,0,BLOCK_SIZE);
					}
					break;
				case "CFB":
					byte[][] ciphertext = new byte[blockCount][BLOCK_SIZE];
					for (byte[] block : blocks) {
						System.arraycopy(block, 0, ciphertext[Arrays.asList(blocks).indexOf(block)], 0, BLOCK_SIZE);
					}
					byte[] backfeed = new byte[BLOCK_SIZE];
					System.arraycopy(iv,0,backfeed,0,BLOCK_SIZE);
					for (int block = 0; block < blockCount; block++) {
						backfeed = c.encrypt(backfeed);
						for (int byt = 0; byt < BLOCK_SIZE; byt++) {
							blocks[block][byt] = (byte) (blocks[block][byt] ^ backfeed[byt]);
						}
						System.arraycopy(ciphertext[block],0,backfeed,0,BLOCK_SIZE);
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
	boolean encryptImage(URL inputURL, String outputURL)
			throws IllegalBlockSizeException, BadPaddingException {
		try {
			BufferedImage image = ImageIO.read(inputURL);
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

	boolean encryptText(String inputurl, String outputURL) throws BadPaddingException, IllegalBlockSizeException {
		try{
			Path p = Paths.get(inputurl);
			byte[] data = Files.readAllBytes(p);
			byte[] e = encrypt(data);
			FileOutputStream f = new FileOutputStream(outputURL);
			f.write(e);
			f.close();
		} catch (IOException e) {
			return false;
		}
		return true;
	}
	boolean decryptText(String inputurl, String outputURL) throws IllegalBlockSizeException {
		try{
			Path p = Paths.get(inputurl);
			byte[] data = Files.readAllBytes(p);
			byte[] e = decrypt(data);
			FileOutputStream f = new FileOutputStream(outputURL);
			f.write(e);
			f.close();
		} catch (IOException e) {
			return false;
		}
		return true;
	}

	/**
	 * Decrypts an image located at pathToInput while preserving the header and
	 * saves to pathToOutput. Returns false if unsuccessful.
	 *
	 * @param inputURL - String with URL to input file
	 * @param outputURL - String with URL to output file
	 * @throws IllegalBlockSizeException ignore
	 * @throws BadPaddingException ignore
	 * @return boolean
	 */
	boolean decryptImage(URL inputURL, String outputURL)
			throws IllegalBlockSizeException, BadPaddingException {
		//File input = new File(pathToInput);
		File output = new File(outputURL);
		try {
			BufferedImage image = ImageIO.read(inputURL);
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] decrypted = decrypt(pixels);
			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			assert decrypted != null;
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(decrypted, decrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", output);
		} catch (IOException e) {
			System.out.println("Error with image path!");
			return false;
		}
		return true;
	}

	/**
	 * Calls encryptAndDecryptImageWithError for plaintext error
	 * @param inputURL - URL to input file
	 * @param outputUrlEnc - String URL to encrypted output file
	 * @param outputUrlDec - String URL to decrypted output file
	 */
	void encryptAndDecryptImageWithPtError(URL inputURL, String outputUrlEnc, String outputUrlDec){
		encryptAndDecryptImageWithError(inputURL, outputUrlEnc, outputUrlDec, true);
	}

	/**
	 * Calls encryptAndDecryptImageWithError for ciphertext error
	 * @param inputURL - URL to input file
	 * @param outputUrlEnc - String URL to encrypted output file
	 * @param outputUrlDec - String URL to decrypted output file
	 */
	void encryptAndDecryptImageWithCtError(URL inputURL, String outputUrlEnc, String outputUrlDec){
		encryptAndDecryptImageWithError(inputURL, outputUrlEnc, outputUrlDec, false);
	}

	/**
	 * Encrypts and decrypts images and introduces specified error
	 * @param inputURL - URL to input file
	 * @param outputUrlEnc - String URL to encrypted output file
	 * @param outputUrlDec - String URL to decrypted output file
	 * @param ptError - true for plaintext error, false for ciphertext error
	 */
	private void encryptAndDecryptImageWithError(URL inputURL, String outputUrlEnc, String outputUrlDec, boolean ptError) {
		//File input = new File(inputURL);
		File outputEnc = new File(outputUrlEnc);
		File outputDec = new File(outputUrlDec);
		try {
			BufferedImage image = ImageIO.read(inputURL);
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] encrypted = encryptWithError(pixels, ptError);
			byte[] decrypted = decrypt(encrypted);
			int lost = corruptedBlocks(pixels,decrypted);
			System.out.println("\t\t\tBytes lost: "+lost);
			System.out.println("\t\t\t%Corrupted = "+getPercentCorrupted(pixels.length,lost));

			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(encrypted, encrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputEnc);
			assert decrypted != null;
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(decrypted, decrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputDec);
		} catch (IOException e) {
			System.out.println("Error with image path!");
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

	}
	@Contract(pure = true)
	private double getPercentCorrupted(int dataLength, int lost){
		double dl = dataLength+0.0/16;
		return lost/dl*100;
	}
	public void encryptAndDecryptImage(URL inputURL, String outputUrlEnc, String outputUrlDec) {
		//File input = new File(inputURL);
		File outputEnc = new File(outputUrlEnc);
		File outputDec = new File(outputUrlDec);
		try {
			BufferedImage image = ImageIO.read(inputURL);
			byte[] pixels = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
			byte[] encrypted = encrypt(pixels);
			byte[] decrypted = decrypt(encrypted);

			BufferedImage outImage = new BufferedImage(image.getWidth(), image.getHeight(),
					BufferedImage.TYPE_3BYTE_BGR);
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(encrypted, encrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputEnc);
			assert decrypted != null;
			outImage.setData(Raster.createRaster(outImage.getSampleModel(),
					new DataBufferByte(decrypted, decrypted.length), new Point()));
			ImageIO.write(outImage, "bmp", outputDec);
		} catch (IOException e) {
			System.out.println("Error with image path!");
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Transforms byte[] to byte[][] (Array of blocks)
	 *
	 * @param data - data to be transformed into array of 16 byte blocks
	 * @return byte[][]
	 *
	 */
	private byte[][] toBlocks(byte[] data) {
		int blockCount = data.length / 16;
		int postfix = 0;
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
	 *
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
