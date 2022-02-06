package com.company;

import java.awt.image.BufferedImage;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Vector;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.imageio.ImageIO;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.IOUtils;

import java.security.*;
import java.util.*;


public class TripleDES{

    static public void main(String[] argv){

        Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.addProvider(prov);

        try{

            if(argv.length>0){
                // Create a TripleDES object
                TripleDES the3DES = new TripleDES();

                if(argv[0].compareTo("-ECB")==0){
                    // ECB mode
                    // encrypt ECB mode
                    Vector Parameters=
                            the3DES.encryptECB(
                                    new FileInputStream(new File(argv[1])),  	// clear text file
                                    new FileOutputStream(new File(argv[2])), 	// file encrypted
                                    "DES", 										// KeyGeneratorName
                                    "DES/ECB/NoPadding"); 						// CipherName
                    // decrypt ECB mode
                    the3DES.decryptECB(Parameters,				 			// the 3 DES keys
                            new FileInputStream(new File(argv[2])),  	// the encrypted file
                            new FileOutputStream(new File(argv[3])),	// the decrypted file
                            "DES/ECB/NoPadding"); 		  				// CipherName
                }
                else if(argv[0].compareTo("-CBC")==0){
                    // decryption
                    // encrypt CBC mode
                    Vector Parameters =
                            the3DES.encryptCBC(
                                    new FileInputStream(new File(argv[1])),  	// clear text file
                                    new FileOutputStream(new File(argv[2])), 	// file encrypted
                                    "DES", 										// KeyGeneratorName
                                    "DES/CBC/NoPadding"); 						// CipherName
                    //"DES/CBC/PKCS5Padding"); 					// CipherName
                    // decrypt CBC mode
                    the3DES.decryptCBC(
                            Parameters,				 					// the 3 DES keys
                            new FileInputStream(new File(argv[2])),  	// the encrypted file
                            new FileOutputStream(new File(argv[3])),	// the decrypted file
                            "DES/CBC/NoPadding"); 						// CipherName
                    //"DES/CBC/PKCS5Padding"); 		  			// CipherName
                }

            }

            else{
                System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
                System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
            }
        }catch(Exception e){
            e.printStackTrace();
            System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
            System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
        }
    }



    /**
     * 3DES ECB Encryption
     */
    private Vector encryptECB(FileInputStream in,
                              FileOutputStream out,
                              String KeyGeneratorInstanceName,
                              String CipherInstanceName){
        try{

            // GENERATE 3 DES KEYS
            KeyGenerator keygenerator = KeyGenerator.getInstance(KeyGeneratorInstanceName);
            SecretKey k1 = keygenerator.generateKey();
            SecretKey k2 = keygenerator.generateKey();
            SecretKey k3 = keygenerator.generateKey();

            Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
            cipher1.init(Cipher.ENCRYPT_MODE, k1);

            Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
            cipher2.init(Cipher.DECRYPT_MODE, k2);

            Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
            cipher3.init(Cipher.ENCRYPT_MODE, k3);

            byte[] message = IOUtils.readAllBytes(in);
            byte[] encryptedMessage = cipher3.doFinal(cipher2.doFinal(cipher1.doFinal(message)));

            out.write(encryptedMessage);

            Vector<SecretKey> list_keys = new Vector<SecretKey>();
            list_keys.add(k1);
            list_keys.add(k2);
            list_keys.add(k3);

            return list_keys;

        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }


    /**
     * Mariella - Mohamed
     * 3DES ECB Decryption
     */
    private void decryptECB(Vector Parameters,
                            FileInputStream in,
                            FileOutputStream out,
                            String CipherInstanceName) {
        try {

            Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
            cipher3.init(Cipher.DECRYPT_MODE, (SecretKey)Parameters.get(2));

            Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
            cipher2.init(Cipher.ENCRYPT_MODE, (SecretKey)Parameters.get(1));

            Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
            cipher1.init(Cipher.DECRYPT_MODE, (SecretKey)Parameters.get(0));

            byte[] message = IOUtils.readAllBytes(in);
            byte[] decryptedMessage = cipher1.doFinal(cipher2.doFinal(cipher3.doFinal(message)));

            // WRITE THE DECRYPTED DATA IN OUT
            out.write(decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 3DES CBC Encryption
     */
    private Vector encryptCBC(FileInputStream in,
                              FileOutputStream out,
                              String KeyGeneratorInstanceName,
                              String CipherInstanceName){
        try{

            // GENERATE 3 DES KEYS
            KeyGenerator keyGen = KeyGenerator.getInstance(KeyGeneratorInstanceName);
            SecureRandom secRandom = new SecureRandom();
            keyGen.init(secRandom);

            Key key1 = keyGen.generateKey();
            Key key2 = keyGen.generateKey();
            Key key3 = keyGen.generateKey();

            // GENERATE THE IV
            IvParameterSpec ivector1 = new IvParameterSpec(new byte[8]);
            IvParameterSpec ivector2 = new IvParameterSpec(new byte[8]);
            IvParameterSpec ivector3 = new IvParameterSpec(new byte[8]);

            Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
            cipher1.init(Cipher.ENCRYPT_MODE, key1, ivector1);

            Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
            cipher2.init(Cipher.DECRYPT_MODE, key2, ivector2);

            Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
            cipher3.init(Cipher.ENCRYPT_MODE, key3, ivector3);

            // GET THE DATA TO BE ENCRYPTED FROM IN
            byte[] data = IOUtils.readAllBytes(in);
            byte[] encryptedMessage = cipher3.doFinal(cipher2.doFinal(cipher1.doFinal(data)));

            out.write(encryptedMessage);

            Vector list_k_iv = new Vector();
            list_k_iv.add(key1);
            list_k_iv.add(key2);
            list_k_iv.add(key3);
            list_k_iv.add(ivector1);
            list_k_iv.add(ivector2);
            list_k_iv.add(ivector3);

            return list_k_iv;

        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 3DES CBC Decryption
     */
    private void decryptCBC(Vector<Key> Parameters,
                            FileInputStream in,
                            FileOutputStream out,
                            String CipherInstanceName){
        try{
            Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
            cipher3.init(Cipher.DECRYPT_MODE, (Key) Parameters.get(2), (IvParameterSpec) Parameters.get(5));

            Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
            cipher2.init(Cipher.ENCRYPT_MODE, (Key) Parameters.get(1), (IvParameterSpec) Parameters.get(5));

            Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
            cipher1.init(Cipher.DECRYPT_MODE, (Key) Parameters.get(0), (IvParameterSpec) Parameters.get(5));

            byte[] message = IOUtils.readAllBytes(in);
            byte[] decryptedMessage = cipher1.doFinal(cipher2.doFinal(cipher3.doFinal(message)));

            // WRITE THE DECRYPTED DATA IN OUT
            out.write(decryptedMessage);

        }catch(Exception e){
            e.printStackTrace();
        }
    }


}


