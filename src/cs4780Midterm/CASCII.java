package cs4780Midterm;

//CASCII.java
//A simplified version of ASCII for encryption and decryption needs

/**
* <p>Title: CASCII</p>
* <p>Description: A Compact ASCII data format</p>
* <p>Copyright: Copyright (c) 2003</p>
* <p>Company: University of Pennsylvania</p>
* @author Michael May
* @version 1.0
*/

/**
* A class that contains the Compact ASCII representation of text.
* The total size of the alphabet is 5 bits - 32 total possibilities.
*/

public class CASCII {
public CASCII() {
}

/**
* Takes a single ASCII encoded character and returns its CASCII equivalent.
* All characters must be in the set { A-Z, '\'', ':', ',', '.', '?', ' ' }
*
* @param c The ASCII encoded character
* @return The CASCII byte encoded equivalent.
*/
public static byte Convert(char c)
{
 // substitute the old char for our CASCII value
 switch ( c )
 {
   case 'A':
     return A;

   case 'B':
     return B;

   case 'C':
     return C;

   case 'D':
     return D;

   case 'E':
     return E;

   case 'F':
     return F;

   case 'G':
     return G;

   case 'H':
     return H;

   case 'I':
     return I;

   case 'J':
     return J;

   case 'K':
     return K;

   case 'L':
     return L;

   case 'M':
     return M;

   case 'N':
     return N;

   case 'O':
     return O;

   case 'P':
     return P;

   case 'Q':
     return Q;

   case 'R':
     return R;

   case 'S':
     return S;

   case 'T':
     return T;

   case 'U':
     return U;

   case 'V':
     return V;

   case 'W':
     return W;

   case 'X':
     return X;

   case 'Y':
     return Y;

   case 'Z':
     return Z;

   case '?':
     return Question;

   case '\'':
     return Apostrophe;

   case ':':
     return Colon;

   case ',':
     return Comma;

   case '.':
     return Period;

   case ' ':
     return Space;

   default:
     throw new java.lang.IllegalArgumentException(
         "Character must be upper case A-Z or { '\'', ':', ',', '.', '?', ' '} -- found: " + c);
 }

}
/**
* Converts an array of bits from zeros and ones to a single ASCII character.
* If the Array isn't exactly 5 slots large, an exception is raised.
* @param bits A 5 member arrray that contains the bits to be examined
* @return ASCII character that is represented by the bits.
*/
public static char Convert(byte[] bits)
{
 // just a general case of the bounded one
 return Convert(bits, 0, bits.length-1);
}
/**
* Converts an array of bits from zeroes and ones to a single ASCII character.
* The indexes must reference a five slot series in the array or else an exception
* is raised.
* @param bits The array of bits to be converted
* @param start The first index in the series
* @param end The last index in the series
* @return ASCII character representation of the bits
*/
public static char Convert( byte[] bits, int start, int end)
{
 // check that it's 5 bits long only
 if ( end - start != 4 )
 {
   throw new java.lang.IllegalArgumentException("Argument must only be five bits long");
 }

 // now find out what number this is
 int val = 0;
 for ( int i = start; i <= end; i++)
 {
   // each bit over is a raising of the power of two
   // multiply it by the bit value - one or zero
   val += java.lang.Math.pow(2, i-start) * bits[i];
 }

 // now value is the number for the letter
 switch ( val )
 {
   case 0:
     return ' ';
   case 1:
     return 'A';
   case 2:
     return 'B';
   case 3:
     return 'C';
   case 4:
     return 'D';
   case 5:
     return 'E';
   case 6:
     return 'F';
   case 7:
     return 'G';
   case 8:
     return 'H';
   case 9:
     return 'I';
   case 10:
     return 'J';
   case 11:
     return 'K';
   case 12:
     return 'L';
   case 13:
     return 'M';
   case 14:
     return 'N';
   case 15:
     return 'O';
   case 16:
     return 'P';
   case 17:
     return 'Q';
   case 18:
     return 'R';
   case 19:
     return 'S';
   case 20:
     return 'T';
   case 21:
     return 'U';
   case 22:
     return 'V';
   case 23:
     return 'W';
   case 24:
     return 'X';
   case 25:
     return 'Y';
   case 26:
     return 'Z';
   case 27:
     return ',';
   case 28:
     return '?';
   case 29:
     return ':';
   case 30:
     return '.';
   case 31:
     return '\'';

   default:
     throw new java.lang.IllegalArgumentException("Argument must be be on interval [0, 31]");
   }
}

/**
* Takes an ASCII encoded character string and returns a CASCII encoded
* byte array.  All characters must be in the set { A-Z, '\'', ':', ',', '.', '?', ' ' }
*
* @param text The ASCII text to convert
* @return The CASCII encoded byte array
*/
public static byte[] Convert( char[] text )
{
 // make an output array of bytes that is the converted text
 byte out[] = new byte[text.length];

 // go through each character in the text and convert it
 for ( int i = 0; i < text.length; i ++ )
 {
   out[i] = Convert(text[i]);
 }

 // send back the new byte array
 return out;
}

/**
* Takes an ASCII encoded String and returns a CASCII encoded
* byte array.  All characters must be in the set { A-Z, '\'', ':', ',', '.', '?', ' ' }
* The resulting byte array is padded to a length that is a multiple of 8.
*
* @param s The ASCII String to convert
* @return The CASCII encoded byte array
*/
public static byte[] Convert( String s )
{
 // make this String into a byte array in CASCII form
 byte cas[] = new byte[s.length()];

 // convert it to CASCII byte encoding
 for ( int i=0; i < s.length(); i++)
 {
   cas[i] = CASCII.Convert(s.charAt(i));
 }

 // now expand the bytes to be just bits
 int size = 5 * s.length();
 // pad it to be a multiple of 8
 size = size + ( 8 - (size % 8) );
 byte bits[] = new byte[size];
 // set them to be zero to begin
 for ( int i = 0; i < bits.length; i++)
 {
   bits[i] = 0;
 }

 // expand the character out into bits
 byte b;
 for ( int j = 0; j < cas.length; j++)
 {
   b = cas[j];
   // make this 5 bit number into real bits
   for (int i = 0; b != 0; i++) {
     if (b % 2 == 0) {
       bits[j*5 + i] = 0;
     }
     else {
       bits[j*5 + i] = 1;
     }

     b /= 2;
   }
 }

 // send back the new byte array
 return bits;
}


/**
* Takes an array of CASCII bits and returns an ASCII encoded
* String.  If cas.length is not a multiple of 5, the remaining
* bits are discarded.
*
* @param cas The CASCII text to convert
* @return The ASCII encoded string
*/
public static String toString( byte[] cas )
{
 // make an output array of bytes that is the converted text
 char output[] = new char[cas.length/5];

 // go through each character in the text and convert it
 for ( int block = 0; block < cas.length; block += 5 )
 {
   // if it's reached the end of the 5-bit strings, quit
   if ( block + 5 > cas.length ) break;

   output[block/5] = CASCII.Convert(cas, block, block+4);
 }

 // send back the new byte array
 return new String(output);
}


//Make up the letters that will be in the enumeration
public static byte Space = 0;
public static byte A = 1;
public static byte B = 2;
public static byte C = 3;
public static byte D = 4;
public static byte E = 5;
public static byte F = 6;
public static byte G = 7;
public static byte H = 8;
public static byte I = 9;
public static byte J = 10;
public static byte K = 11;
public static byte L = 12;
public static byte M = 13;
public static byte N = 14;
public static byte O = 15;
public static byte P = 16;
public static byte Q = 17;
public static byte R = 18;
public static byte S = 19;
public static byte T = 20;
public static byte U = 21;
public static byte V = 22;
public static byte W = 23;
public static byte X = 24;
public static byte Y = 25;
public static byte Z = 26;
public static byte Comma = 27;
public static byte Question = 28;
public static byte Colon = 29;
public static byte Period = 30;
public static byte Apostrophe = 31;

}