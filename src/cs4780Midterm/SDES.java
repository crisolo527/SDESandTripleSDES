package cs4780Midterm;

import java.util.Arrays;

public class SDES {


	public static void main(String args[]){

		
///*Test 1: CIPHER: 0, 0, 0, 1, 0, 0, 0, 1
		byte[] key = SDES.stringToByteArray("0000000000");
		byte[] plaintext =  SDES.stringToByteArray("00000000");
//*/
/*Test 2 CIPHER: 0, 1, 1, 1, 0, 0, 0, 0
		byte[] key = SDES.stringToByteArray("1110001110");
		byte[] plaintext =  SDES.stringToByteArray("10101010");
*/ 
/*Test 3 CIPHER: 0, 1, 1, 1, 0, 0, 0, 0
		byte[] key = SDES.stringToByteArray("1110001110");
		byte[] plaintext =  SDES.stringToByteArray("01010101");
*/ 
/*Test 4 CIPHER: 0, 0, 0, 0, 0, 1, 0, 0
		byte[] key = SDES.stringToByteArray("1111111111");
		byte[] plaintext =  SDES.stringToByteArray("10101010");
*/ 
		


		byte[] ciphertext = Encrypt(key, plaintext);
		byte[] decrypted = Decrypt(key, ciphertext);


		System.out.println("Key: " + Arrays.toString(key));
		System.out.println("Plaintext: " + Arrays.toString(plaintext));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext));
		System.out.println("Decrypted Ciphertext: " + Arrays.toString(decrypted));
		
		
		
		
	}
	
	

	public static byte[] Encrypt(byte[] rawkey, byte[] plaintext){


		byte[][] subkeys = SDES.subkeyGenerator(rawkey);

		int[] initial_P_Box = {2,6,3,1,4,8,5,7};
		int[] inverse_P_Box = {4,1,3,5,7,2,8,6};

		byte[] ciphertext = SDES.permutator(false, plaintext, initial_P_Box);
		ciphertext = SDES.functionFK(ciphertext, subkeys[0], subkeys[1]);
		ciphertext = SDES.permutator(false, ciphertext, inverse_P_Box);

		return ciphertext;
	}

	public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext){

		byte[][] subkeys = SDES.subkeyGenerator(rawkey);

		int[] initial_P_Box = {2,6,3,1,4,8,5,7};
		int[] inverse_P_Box = {4,1,3,5,7,2,8,6};

		byte[] plaintext = SDES.permutator(false, ciphertext, initial_P_Box);
		plaintext = SDES.inverseFunctionFK(plaintext, subkeys[0], subkeys[1]);
	  plaintext = SDES.permutator(false, plaintext, inverse_P_Box);

		return plaintext;

	}


  public static byte[][] subkeyGenerator(byte[] rawkey){


    int[] p10 = {3,5,2,7,4,10,1,9,8,6};
    int[] p8 = {6, 3, 7, 4, 8, 5, 10, 9};

    byte[] key = SDES.permutator(false, rawkey, p10);

    byte[] left_key = getLeftHalf(key);
    byte[] right_key = getRightHalf(key);

    left_key = SDES.left_shift(false, left_key, 1);
    right_key = SDES.left_shift(false, right_key, 1);
    key = SDES.concatenateByteArrays(left_key, right_key);
    byte[] subkey_a = SDES.permutator(false, key, p8);

    left_key = SDES.left_shift(false, left_key, 2);
    right_key = SDES.left_shift(false, right_key, 2);
    key = SDES.concatenateByteArrays(left_key, right_key);
    byte[] subkey_b = SDES.permutator(false, key, p8);


    byte[][] subkeys = { subkey_a, subkey_b };

    return subkeys;

  }

  public static byte[] functionFK(byte[] text, byte[] subkey_a, byte[] subkey_b){


    byte[] left_text = getLeftHalf(text);
    byte[] right_text = getRightHalf(text);

//  Expand the right half of the text with p4 P-Box
    int[] expansion_P_Box = {4,1,2,3,2,3,4,1};
    byte[] expanded_right_text = permutator(false, right_text, expansion_P_Box);

//  XOR the expanded right half with the first subkey
    byte[] right_text_XOR = exclusiveOR(expanded_right_text, subkey_a);

//  Use the result and run it through the S-Boxes to get 4 bits
//  Permutate the 4-bit result
		byte[] sub_per_result = substitutionBoxes(right_text_XOR);

// Take the permutated 4 bits and XOR it with the left half of the text
		byte[] left_text_XOR = exclusiveOR(left_text, sub_per_result);

//  Concatenate the XOR result with the original right half that was passed into the function
		byte[] concatHalves = concatenateByteArrays(left_text_XOR, right_text);

//  Swap the halves to prepare to do the function again with the second subkey
		byte[] swapped = swapHalves(concatHalves);

//  Get left and right halves of swapped text
		byte[] left_swapped = getLeftHalf(swapped);
		byte[] right_swapped = getRightHalf(swapped);

//  Do the same thing as above but with the second subkey
		expanded_right_text = permutator(false, right_swapped, expansion_P_Box);
		right_text_XOR = exclusiveOR(expanded_right_text, subkey_b);
		sub_per_result = substitutionBoxes(right_text_XOR);
		left_text_XOR = exclusiveOR(left_swapped, sub_per_result);
		concatHalves = concatenateByteArrays(left_text_XOR, right_swapped);

    return concatHalves;
  }

	public static byte[] inverseFunctionFK(byte[] text, byte[] subkey_a, byte[] subkey_b){

		byte[] left_text = SDES.getLeftHalf(text);
		byte[] right_text = SDES.getRightHalf(text);

//  start with the second subkey because its the inverse
		int[] expansion_P_Box = {4,1,2,3,2,3,4,1};
		byte[] expanded_right_text = SDES.permutator(false, right_text, expansion_P_Box);
		byte[] right_text_XOR = exclusiveOR(expanded_right_text, subkey_b);
		byte[] sub_per_result = SDES.substitutionBoxes(right_text_XOR);
		byte[] left_text_XOR = exclusiveOR(left_text, sub_per_result);
		byte[] concatHalves = SDES.concatenateByteArrays(left_text_XOR, right_text);

		byte[] swapped = SDES.swapHalves(concatHalves);
		byte[] left_swapped = SDES.getLeftHalf(swapped);
		byte[] right_swapped = SDES.getRightHalf(swapped);

//  Do the same thing as above but with the first subkey
		expanded_right_text = SDES.permutator(false, right_swapped, expansion_P_Box);
		right_text_XOR = exclusiveOR(expanded_right_text, subkey_a);
		sub_per_result = SDES.substitutionBoxes(right_text_XOR);
		left_text_XOR = exclusiveOR(left_swapped, sub_per_result);
		concatHalves = SDES.concatenateByteArrays(left_text_XOR, right_swapped);

		return concatHalves;
	}

  public static byte[] substitutionBoxes(byte[] right_text_XOR){

    byte[] substituted = new byte[4];

    byte[] oneFour = new byte[2];
    oneFour[0] = right_text_XOR[0];
    oneFour[1] = right_text_XOR[3];

    byte[] twoThree = new byte[2];
    twoThree[0] = right_text_XOR[1];
    twoThree[1] = right_text_XOR[2];

    byte[] fiveEight = new byte[2];
    fiveEight[0] = right_text_XOR[4];
    fiveEight[1] = right_text_XOR[7];

    byte[] sixSeven = new byte[2];
    sixSeven[0] = right_text_XOR[5];
    sixSeven[1] = right_text_XOR[6];


    byte[] firstTwo = sBoxTable1(oneFour, twoThree);
    byte[] lastTwo = sBoxTable2(fiveEight, sixSeven);

    substituted = concatenateByteArrays(firstTwo, lastTwo);

    int[] p4 = {2,4,3,1};
    substituted = permutator(false, substituted, p4);

    //  returns 4-bit byte Array bot Substituted and Permutated
    return substituted;
  }

  public static byte[] sBoxTable1(byte[] oneFour, byte[] twoThree){

	  int[][] box = {
			  {1, 0, 3, 2},
			  {3, 2, 1, 0},
			  {0, 2, 1, 3},
			  {3, 1, 3, 2}
			  };
	  
	  int row = getDecimal(oneFour);
	  int col = getDecimal(twoThree);
	  
	 return getByte(box[row][col],2);
  }

  public static byte[] sBoxTable2(byte[] fiveEight, byte[] sixSeven){

	  int[][] box = {
			  {0, 1, 2, 3},
			  {2, 0, 1, 3},
			  {3, 0, 1, 0},
			  {2, 1, 0, 3}
			  };
	  
	  int row = getDecimal(fiveEight);
	  int col = getDecimal(sixSeven);
	  
	  return getByte(box[row][col],2);

  }
  
  public static int getDecimal(byte[] arr){
		int total = 0;
		int count = arr.length - 1;
		
		for(byte b: arr){
			if(b == 1)
				total += Math.pow(2, count);	
			count--;
		}
		
		return total;
  }
  

	public static byte[] getByte(int decimal, int binary_size){
		byte[] binary = new byte[binary_size];
		
		while(binary_size > 0){
			binary[binary_size-1] = (byte) (decimal % 2);
			decimal = decimal >> 1;
			binary_size--;
		}
		
		return binary;
	}

  public static byte[] exclusiveOR(byte[] a, byte[] b){

    byte[] result = new byte[a.length];
    byte value = 0;

    for (int i = 0; i < result.length; i++) {
      value = (byte)(a[i]^b[i]);
      result[i] = value;
    }

    return result;
  }


  public static byte[] swapHalves(byte[] text){


    byte[] left_text = new byte[text.length/2];
    byte[] right_text = new byte[text.length/2];

    int count = 0;
    for(byte b: text){
      if(count < text.length/2 ){
        right_text[count ] = b;
      }
      else{
        left_text[count - text.length / 2] = b;
      }
      count++;
    }

    byte[] swapped = concatenateByteArrays(left_text, right_text);

    return swapped;
  }

//Gets left half of byte array
	public static byte[] getLeftHalf(byte[] text){


		byte[] left_text = new byte[text.length/2];
		byte[] right_text = new byte[text.length/2];

		int count = 0;
		for(byte b: text){
			if(count < text.length/2 ){
				left_text[count ] = b;
			}
			else{
				right_text[count - text.length / 2] = b;
			}
			count++;
		}

		return left_text;
	}

//Gets right half of byte array
	public static byte[] getRightHalf(byte[] text){


		byte[] left_text = new byte[text.length/2];
		byte[] right_text = new byte[text.length/2];

		int count = 0;
		for(byte b: text){
			if(count < text.length/2 ){
				left_text[count ] = b;
			}
			else{
				right_text[count - text.length / 2] = b;
			}
			count++;
		}

		return right_text;
	}

//Permutes raw byte array based on order array
	public static byte[] permutator(boolean isInverse, byte[] raw, int[] order){

		byte[] permutated = new byte[order.length];

		if(!isInverse){
			for(int index = 0; index < permutated.length ; index++){
				permutated[index] = raw[order[index]-1];
			}
		}
		else{

		}

		return permutated;
	}

//Shift byte array left based on given shift_count
	public static byte[] left_shift(boolean isInverse, byte[] raw, int shift_count){
		byte[] shifted = raw;

		for(int x = 0; x< shift_count; x++){
			byte first = raw[0];

			for(int i = 0; i < raw.length - 1; i++){
				shifted[i] = raw[i+1];
			}
			shifted[shifted.length-1] = first;
		}
		return shifted;

	}

//Concatenate two byte arrays
	public static byte[] concatenateByteArrays(byte[] arr1, byte[] arr2){
		byte[] concated = new byte[arr1.length + arr2.length];

		int count = 0;
		for(byte b : arr1){
			concated[count]=b;
			count++;
		}

		for(byte b : arr2){
			concated[count]=b;
			count++;
		}


		return concated;
	}
	
//String to byte array
	public static byte[] stringToByteArray(String s){
		byte[] array = new byte[s.length()];

		for (int i = 0; i < s.length(); i++){
		    char c = s.charAt(i);        
		    array[i] = (byte) Character.getNumericValue(c);
		}
		return array;
	}


}
