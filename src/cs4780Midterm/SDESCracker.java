package cs4780Midterm;

import java.util.Arrays;

public class SDESCracker {
	public static void main(String args[]){
				
		//part1();
		
		 String msg1 = "1011011001111001001011101111110000111110100000000001110111010001111011111101101100010011000000101101011010101000101111100011101011010111100011101001010111101100101110000010010101110001110111011111010101010100001100011000011010101111011111010011110111001001011100101101001000011011111011000010010001011101100011011110000000110010111111010000011100011111111000010111010100001100001010011001010101010000110101101111111010010110001001000001111000000011110000011110110010010101010100001000011010000100011010101100000010111000000010101110100001000111010010010101110111010010111100011111010101111011101111000101001010001101100101100111001110111001100101100011111001100000110100001001100010000100011100000000001001010011101011100101000111011100010001111101011111100000010111110101010000000100110110111111000000111110111010100110000010110000111010001111000101011111101011101101010010100010111100011100000001010101110111111101101100101010011100111011110101011011";
		crack(msg1);
		
	}
	
	public static void part1(){
		byte[] key = SDES.stringToByteArray("0111001101");
		String toEncrypt = "CRYPTOGRAPHY";
		byte[] plaintext = CASCII.Convert(toEncrypt);
		
		
		byte[] ciphertext = longEncrypt(key, plaintext);
		byte[] decoded = longDecrypt(key, ciphertext);
		
		System.out.println(toEncrypt);
		
		System.out.println("Plain: \t\t "+ Arrays.toString(plaintext));
		System.out.println("Cipher: \t"+ Arrays.toString(ciphertext));
		System.out.println("Decoded: \t"+ Arrays.toString(decoded));
		
		System.out.println(CASCII.toString(decoded));
		
	}
	
	public static byte[] crack(String encrypted){
		byte[] key = {};
		byte[] first = SDES.stringToByteArray("0000000000");
		byte[] last = SDES.stringToByteArray("1111111111");	
		
		int upperlimit = SDES.getDecimal(last);
		
		
		for(int i = 0; i < upperlimit; i++){
			
			key = SDES.getByte(i, 10);
			
			byte[] decoded = longDecrypt(key, SDES.stringToByteArray(encrypted));
			String sDecoded = CASCII.toString(decoded);
			if(containsWords(sDecoded, 0.85))
				System.out.println(CASCII.toString(decoded)+ " : "+Arrays.toString(key));
		}
		
		return key;	
	}
	

	public static boolean containsWords(String s, double cutoff_percent){
		s = s.toUpperCase();
		String[] words = s.split("\\s+");
		int count = 0;
		int total = 0;
		
		for(String word: words){
			if(word.matches("^\\w+$"))
				count++;
			total++;
		}
		
		double percentCorrect = ((double)count / total);
				
		if(percentCorrect < cutoff_percent)
			return false;
		else
			return true;
		
	}
	
	
	public static byte[] longEncrypt(byte[] key, byte[] plaintext){
		byte[] cipher = {};
		
		int n = 8;
		
		byte[][] arrays = groupByN(plaintext, n);

		for(byte[] group: arrays){
			cipher = SDES.concatenateByteArrays(cipher, SDES.Encrypt(key, group));
		}
		
		return cipher;
	}
	
	public static byte[] longDecrypt(byte[] key, byte[] cipher){
		byte[] text = {};
				
		byte[][] arrays = groupByN(cipher, 8);
		
		for(byte[] group: arrays){
			text = SDES.concatenateByteArrays(text, SDES.Decrypt(key, group));
		}
		
		return text;
	}
	
	public static int byteArrayCount(byte[] arr){
		int count = 0;
		for(byte b: arr){
			count++;
		}
		return count;
	}
	
	public static byte[][] groupByN(byte[] arr, int n){
		int totalCount = byteArrayCount(arr);
		int groupCount = (int)Math.ceil(totalCount/n);
		
		byte[][] groups = new byte[groupCount][n];
		
		for(int x = 0; x <  groupCount; x++){
			byte[] grouped = new byte[n];
			for(int y = 0; y < n; y++){
				int index = y + (x * n);
				grouped[y] = arr[index];
			}
			groups[x] = grouped;
			
		}
		return groups;
	}
	
	
}
