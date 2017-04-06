package cs4780Midterm;

import java.util.Arrays;

public class TripleSDES {
	
	

	public static byte[] Encrypt( byte[] rawkey1, byte[] rawkey2, byte[] plaintext ){
		byte[] encrypted;
		
		byte[] stage_1 = SDES.Encrypt(rawkey1, plaintext);
		byte[] stage_2 = SDES.Decrypt(rawkey2, stage_1);
		encrypted = SDES.Encrypt(rawkey1, stage_2);
		
		
		return encrypted;
		
	}
	public static byte[] Decrypt( byte[] rawkey1, byte[] rawkey2, byte[] ciphertext ){
		byte[] encrypted;
		
		byte[] stage_1 = SDES.Decrypt(rawkey1, ciphertext);
		byte[] stage_2 = SDES.Encrypt(rawkey2, stage_1);
		encrypted = SDES.Decrypt(rawkey1, stage_2);
		
		
		return encrypted;
	}
	
	
	public static void main(String args[]){


		byte[] key1 = SDES.stringToByteArray("1111111111");
		byte[] key2 = SDES.stringToByteArray("1111111111");
		byte[] plaintext =  SDES.stringToByteArray("10101010");


		byte[] ciphertext = Encrypt(key1, key2, plaintext);
		byte[] decrypted = Decrypt(key1, key2, ciphertext);


		System.out.println("Keys: " + Arrays.toString(key1) + " : " + Arrays.toString(key2));
		
		System.out.println("Plaintext: " + Arrays.toString(plaintext));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext));
		System.out.println("Decrypted Ciphertext: " + Arrays.toString(decrypted));

	}
	
}
