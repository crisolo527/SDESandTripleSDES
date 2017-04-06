package cs4780Midterm;

import java.util.Arrays;

public class TripleSDESCracker {
	public static void main(String args[]){
				
		
		
		 String msg2 = "00011111100111111110011111101100111000000011001011110010101010110001011101001101000000110011010111111110000000001010111111000001010010111001111001010101100000110111100011111101011100100100010101000011001100101000000101111011000010011010111100010001001000100001111100100000001000000001101101000000001010111010000001000010011100101111001101111011001001010001100010100000";

		crack(msg2);
		
		
	}
	
	public static byte[][] crack(String encrypted){
		byte[] key1 = {};
		byte[] key2 = {};
		byte[] first = SDES.stringToByteArray("0000000000");
		byte[] last = SDES.stringToByteArray("1111111111");
		
		byte[] encryptedBytes = SDES.stringToByteArray(encrypted);
		
		int upperlimit = SDES.getDecimal(last);
		
		
		for(int i = 0; i < upperlimit; i++){
			
			
			
			key1 = SDES.getByte(i, 10);
			
			for(int j = 0; j < upperlimit; j++){
				
				key2 = SDES.getByte(j, 10);
				
				byte[] decoded = longDecrypt(key1, key2, encryptedBytes );
				String sDecoded = CASCII.toString(decoded);
				if(containsWords(sDecoded, 0.85))
					System.out.println(i+":"+j+": "+sDecoded + " : "+Arrays.toString(key1)+ " : "+Arrays.toString(key2));
				
			}
		}
		
		byte[][] returnable = {key1, key2};
		
		return returnable;
		
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
	
	
	
	
	public static byte[] longDecrypt(byte[] key1, byte[] key2, byte[] cipher){
		byte[] text = {};
		
		int length = byteArrayCount(cipher);
		
		
		byte[][] arrays = groupByN(cipher, 8);
		
		for(byte[] group: arrays){
			text = SDES.concatenateByteArrays(text, TripleSDES.Decrypt(key1, key2, group));
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
