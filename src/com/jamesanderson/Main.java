/*
	Author: James Anderson
	Course: ICSI 426
	Semester: Spring 2018
 */

package com.jamesanderson;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class Main {
	private  boolean imageMode = false, stringMode = false, decryptMode = false, demoMode=false, bmode=false;
	private  String input = null, output = null, mode = null, key = null, iv = null;
	private  Encryptor e;
	private  byte[] byteKey, byteIV;
    public static void main(String[] args)
            throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	Main m = new Main();
    	m.readArgs(args);
        if (m.imageMode) {
            m.doImage();
        } else if (m.stringMode) {
            m.doString();
        } else if (m.demoMode) {
            m.doDemo();
        } else if (m.bmode) {
        	m.doBmode();
		} else{
            System.out.println("Unexpected error occurred: Could not discern execution mode.");
        }

    }
	private void doBmode(){
		try {
			e = new Encryptor(mode, byteKey, byteIV);
			if (!decryptMode) e.encryptText(input, output);
			else e.decryptText(input, output);
		} catch (InvalidKeyException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (BadPaddingException e1) {
			e1.printStackTrace();
		} catch (IllegalBlockSizeException e1) {
			e1.printStackTrace();
		}
	}
    private  void doString() throws NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
	    try {
		    e = new Encryptor(mode, byteKey, byteIV);
		    byte[] encrypted = e.encrypt(input.getBytes());
		    if (output == null)
			    System.out.println(new String(encrypted));
		    else {
			    FileOutputStream w = new FileOutputStream(output);
			    w.write(encrypted);
			    w.close();
		    }
	    } catch (NoSuchAlgorithmException n) {
		    System.out.println("Invalid operation mode.  Use ECB, CFB, CFB, or OFB.");
	    } catch (InvalidKeyException i) {
		    System.out.println("Invalid key!");
	    } catch (FileNotFoundException e1) { // nothing? } catch (IOException e1) {
		    System.out.println("IO Error occurred.");
	    } catch (IOException e1) {
		    System.out.println("Error writing to file!");
	    }
    }

    private  void doImage() throws NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
	    try {
		    e = new Encryptor(mode, byteKey, byteIV);
		    if (decryptMode && e.decryptImage(new URL(input), output)) {
			    System.out.println(
					    "Successfully decrypted " + input + " to " + output + " using " + mode + " mode.");
		    }
		    else if (e.encryptImage(new URL(input), output)) {
			    System.out.println(
					    "Successfully encrypted " + input + " to " + output + " using " + mode + " mode.");
		    }
		    System.out.println("Key used: " + key);
		    if (mode.equals("CFB") || mode.equals("OFB")) {
			    System.out.println("IV used: " + iv);
		    }
	    } catch (NoSuchAlgorithmException n) {
		    System.out.println("Invalid operation mode. Use ECB, CFB, CFB, or OFB.");
	    } catch (InvalidKeyException i) {
		    System.out.println("Invalid key!");
	    } catch (MalformedURLException e1) {
		    System.out.println("Invalid file path.");
	    }
    }


    private  void doDemo() throws NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
	    System.out.println("Starting demo mode...\n");
	    byte[] bkey = "JAMESANDERSON123".getBytes();
	    byte[] biv = "ANDERSON123JAMES".getBytes();
	    System.out.println("Key set to JAMESANDERSON123 -> "+new String(bkey));
	    System.out.println("IV set to ANDERSON123JAMES -> "+new String(biv)+"\n");
	    Encryptor m;
	    try {
		    String[] dirs = {"PropagationTests","EncryptionTests"};
		    String[] subdirs = {"ecb","cbc","cfb","ofb"};
		    String[] tests = {"CipherTextError","PlainTextError"};
		    for (String dir : dirs){
			    for (String subdir : subdirs){
				    File path = new File(dir+"/"+subdir);
				    if (dir.equals(dirs[0])){
					    for (String test : tests){
						    path = new File(dir+"/"+subdir+"/"+test);
						    if ( ! path.exists()) {
							    boolean b = path.mkdirs();
							    if (b)
								    System.out.println("Creating missing directory: "+dir+"/"+subdir+"/"+test);
						    }
					    }
				    }
				    else if ( ! path.exists() ){
					    boolean b = path.mkdirs();
					    if (b)
						    System.out.println("Creating missing directory: "+dir+"/"+subdir);
				    }
			    }
		    }

		    String[] opmodes = {"ECB","CBC","CFB","OFB"};
		    String[] files = {"rectangle.jpg","land1.jpg","land2.jpg","land3.jpg"};
		    System.out.println("Encryption tests:");
		    for (String op : opmodes){
			    m = new Encryptor(op,bkey,biv);
			    System.out.println("\t"+op+" Op. Mode:");
			    String dir = op.toLowerCase();
			    for (String file : files) {
				    System.out.println("\t\tEncrypting " + file +
						    " -> EncryptionTests/" + dir + "/enc_"+file);
				    java.net.URL imgURL = getClass().getResource("/res/"+file);
				    m.encryptImage(imgURL, "EncryptionTests/"
						    + dir + "/enc_" + file);
			    }
		    }


		    for (String test : tests) {
			    System.out.println("\nError Propagation Tests (" + test + "):");
			    for (String op : opmodes) {
				    String dir = op.toLowerCase();
				    System.out.println("\t" + op + " Mode:");
				    m = new Encryptor(op, bkey, biv);

				    for (String file : files){
					    java.net.URL imgURL = getClass().getResource("/res/"+file);
					    System.out.println("\t\tEncrypting " + file + " -> PropagationTests/"
							    + dir + "/" + test + "/enc_"+file);
					    System.out.println("\t\tDecrypting PropagationTests/ecb/enc_" + file + " -> PropagationTests/"
							    + dir + "/" + test + "/dec_"+file);
					    if (test.equals(tests[0])) {
						    m.encryptAndDecryptImageWithCtError(imgURL, "PropagationTests/"
								    + dir + "/" + test + "/enc_" + file, "PropagationTests/" + dir + "/"
								    + test + "/dec_" + file);
					    }
					    else {
						    m.encryptAndDecryptImageWithPtError(imgURL, "PropagationTests/"
								    + dir + "/" + test + "/enc_" + file, "PropagationTests/" + dir + "/"
								    + test + "/dec_" + file);
					    }
				    }
			    }
		    }

	    }
	    catch (InvalidKeyException | NoSuchAlgorithmException e1) {
		    System.out.println("Error initializing Encryptor");
	    }
    }

	private  void readArgs(String [] args){
		try {
			switch (args[0]) {
				case "-D":
					demoMode = true;
					break;
				case "-i":
					imageMode = true;
					input = args[1];
					output = args[2];
					for (String arg : args) {
						switch (arg) {
							case "-m": mode = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-k": key = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-iv": iv = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-d": decryptMode = true; break;
						}
					}
					break;
				case "-s":
					stringMode = true;
					input = args[1];
					for (String arg : args) {
						switch (arg) {
							case "-m": mode = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-k": key = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-iv": iv = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-o": output = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-d": decryptMode = true; break;
						}
					}
					break;
				case "-b":
					input = args[1];
					bmode=true;
					for (String arg : args) {
						switch (arg) {
							case "-m": mode = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-k": key = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-iv": iv = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-o": output = args[Arrays.asList(args).indexOf(arg) + 1]; break;
							case "-d": decryptMode = true; break;
						}
					}
					break;
				case "-h": printHelpMessage(); break;
				default: printErrorMessage(); break;
			}
		} catch (ArrayIndexOutOfBoundsException e) {
			printErrorMessage();
		}
		if (key == null) {
			Random r = new Random();
			byteKey = new byte[16];
			r.nextBytes(byteKey);
			key = new String(byteKey);
		} else {
			byteKey = new byte[16];
			char[] keyChars = key.toCharArray();
			for (int i = 0; i < 16; i++) {
				try {
					byteKey[i] = (byte) keyChars[i];
				} catch (ArrayIndexOutOfBoundsException a) {
					System.out.println("Invalid key size.  Use a 128-bit key (16 character).");
					imageMode = false;
					stringMode = false;
				}
			}
		}
		if (mode == null)
			mode = "OFB";
		if (iv == null) {
			byteIV = new byte[16];
			Random r = new Random();
			r.nextBytes(byteIV);
		} else {
			byteIV = new byte[16];
			char[] ivChars = iv.toCharArray();
			for (int i = 0; i < 16; i++) {
				try {
					byteIV[i] = (byte) ivChars[i];
				} catch (ArrayIndexOutOfBoundsException a) {
					System.out.println("Invalid iv size.  Use a 128-bit key (16 character).");
					imageMode = false;
					stringMode = false;
				}
			}
		}
	}
    private  void printErrorMessage(){
	    System.out.println("Invalid arguments given.");
	    System.out.println("Valid execution arguments are:");
	    System.out.println("\t-D");
	    System.out.println("\t-h");
	    System.out.println("\t-i input [output] [-m mode] [-k key] [-iv init_vector]");
	    System.out.println("\t-s input [output] [-m mode] [-k key] [-iv init_vector]");
	    System.out.println("For more information use -h execution.");
    }
    private  void printHelpMessage(){
	    System.out.println("Valid execution arguments are:");
	    System.out.println("\t-D");
	    System.out.println("\t\truns the demo mode of the program.");
	    System.out.println("\t-i input output [-m mode] [-k key] [-iv init_vector]");
	    System.out.println("\t\tinput: path to input image");
	    System.out.println("\t\toutput: path to output image");
	    System.out.println(
			    "\t\t-m: use to set AES mode of operation (ECB, CBC, CFB, OFB).  If unspecified will default to OFB");
	    System.out.println(
			    "\t\t-k: use to manualy set encryption key (128-bits).  If not used a key will be auto-generated printed to stdout.");
	    System.out.println(
			    "\t\t-iv: use to manually set initialization vector (128-bits). If not used an iv will be auto-generated printed to stdout.");
	    System.out.println("\t-s input [-o output] [-m mode] [-k key] [-iv init_vector]");
	    System.out.println("\t\tinput: String to be encrypted.");
	    System.out.println(
			    "\t\toutput: path to output file. Will write as txt.  If not used will print output to stdout.");
	    System.out.println(
			    "\t\t-m: use to set AES mode of operation (ECB, CBC, CFB, OFB).  If unspecified will default to OFB");
	    System.out.println(
			    "\t\t-k: use to manually set encryption key (128-bits).  If not used a key will be auto-generated printed to stdout.");
	    System.out.println(
			    "\t\t-iv: use to manually set initialization vector (128-bits). If not used an iv will be auto-generated printed to stdout.");
	    System.out.println("\t Add -d flag to decrypt.");
    }
}
