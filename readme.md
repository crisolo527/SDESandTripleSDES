Running Direction: 
Pre-Run:
	-Place all files in the same package so there are no import errors. 
	-Every class has a main function so you can just run each file in eclipse. 	
	-To change inputs(keys, plaintext, ciphers) you must edit the code.

1- SDES:
	-Run SDES.java
	-The main method calls Encrypt and Decrypt.
	-A helper method converts strings of 0’s and 1’s to byte arrays to test quickly.

2- TripleSDES:
	-Run TripleSDES.java
	-The main method calls Encrypt and Decrypt
	-A helper method converts strings of 0’s and 1’s to byte arrays to test quickly. -The Encrypt and Decrypt use SDES’s static functions.
	-The SDES class must be in the same package or imported properly.

3- SDESCracker:
	-Run SDESCracker.java
	-The main method calls 2 methods.
	-part1(): encrypts “CRYPTOGRAPHY”. -crack(): cracks the given string of bits.

4- TripleSDESCracker:
	-Run TripleSDESCracker.java -The main method calls 1 method.
	-crack(): cracks the given string of bits.
