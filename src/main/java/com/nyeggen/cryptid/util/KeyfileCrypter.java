package com.nyeggen.cryptid.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyfileCrypter {
	//If you encrypt 1000 bytes, output will be length IVS_LENGTH + 1000 + STREAM_PAD_LENGTH
	private static final int STREAM_PAD_LENGTH = 16;
	//The SunJCE providers only support processing 2GB of data before they throw,
	//regardless of the underlying cipher semantics.  Therefore we need to reset them
	//with new IVs and new ciphers every N bytes.  N must be somewhat small, due to the
	//need to fit the buffer in memory to call doFinal() on the entire buffer instead of
	//update() on segments; the former is far faster.
	private static final int RESET_ENC_CIPHER_EVERY = 500 * 1000 * 1000; //500M bytes
	private static final int RESET_DEC_CIPHER_EVERY = RESET_ENC_CIPHER_EVERY + STREAM_PAD_LENGTH;
	private static final int IVS_LENGTH = 16;
	private static final int KEY_ROUNDS = 65536; //This is major performance bottleneck for small files
	private static final int AES_BITS = 256;
	private static final int SALT_LENGTH = 16;
	private static final int GCM_TAG_LENGTH = 16; //num bytes
	
	private static final String CRYPT_MODE = "AES/GCM/NoPadding";
	private static final String KEY_SPEC = "PBKDF2WithHmacSHA256";
	
	//This passphrase is used to encrypt the underlying key, to support changing passphrases
	private final char[] password;
	//This is the raw underlying key, encrypted on the backend via the passphrase
	private final byte[] key;
		
	private final SecureRandom rng;
	private final SecretKeySpec secretKeySpec;
	
	private SecretKey secretKeyFromPassword(final byte[] salt, final char[] pw) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_SPEC);
			KeySpec spec = new PBEKeySpec(pw, salt, KEY_ROUNDS, AES_BITS);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			return secret;
		} catch(GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
	
	private AlgorithmParameterSpec getAlgoParamSpec(byte[] ivs) {
		return new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivs);
	}
	
	private Cipher encryptionCipherForSecret(byte[] ivs) {
		try {
			final AlgorithmParameterSpec aps = getAlgoParamSpec(ivs);
			
			Cipher cipher = Cipher.getInstance(CRYPT_MODE);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, aps);
			return cipher;
		} catch(GeneralSecurityException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	private Cipher decryptionCipherForSecret(byte[] ivs) {
		try {
			final AlgorithmParameterSpec aps = getAlgoParamSpec(ivs);
			
			Cipher cipher = Cipher.getInstance(CRYPT_MODE);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, aps);
			return cipher;
		} catch(GeneralSecurityException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	private Cipher encryptionCipherForKeyfile(byte[] salt, byte[] ivs, char[] newPW) {
		try {
			final SecretKey secret = secretKeyFromPassword(salt, newPW);
			final AlgorithmParameterSpec aps = getAlgoParamSpec(ivs);
			
			Cipher cipher = Cipher.getInstance(CRYPT_MODE);
			cipher.init(Cipher.ENCRYPT_MODE, secret, aps);
			
			return cipher;			
		} catch(GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
	
	private Cipher decryptionCipherForKeyfile(byte[] salt, byte[] ivs) {
		try {
			final SecretKey secret = secretKeyFromPassword(salt, password);
			final AlgorithmParameterSpec aps = getAlgoParamSpec(ivs);
			
			Cipher cipher = Cipher.getInstance(CRYPT_MODE);
			cipher.init(Cipher.DECRYPT_MODE, secret, aps);
			
			return cipher;			
		} catch(GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
	
	public KeyfileCrypter(char[] passphrase) {
		this.password = passphrase;
		this.rng = new SecureRandom();

		this.key = new byte[AES_BITS / 8];
		rng.nextBytes(this.key);
		secretKeySpec = new SecretKeySpec(key, "AES");
	}
	
	public KeyfileCrypter(byte[] encryptedKeyfile, char[] passphrase) {
		this.password = passphrase;
		this.rng = new SecureRandom();

		//Decrypt keyfile
		final byte[] salt = new byte[SALT_LENGTH];
		final byte[] ivs = new byte[IVS_LENGTH];
		try(final ByteArrayInputStream bais = new ByteArrayInputStream(encryptedKeyfile); ) {
			bais.read(salt);
			bais.read(ivs);
			
			final Cipher decryptor = decryptionCipherForKeyfile(salt, ivs);
			this.key = decryptor.doFinal(bais.readAllBytes());
		} catch(IOException | BadPaddingException | IllegalBlockSizeException ex) {
			throw new RuntimeException(ex);
		}
		
		secretKeySpec = new SecretKeySpec(key, "AES");
	}
	
	public byte[] encryptKeyfile(char[] newPassphrase) throws IOException {
		final byte[] salt = getRandomBytes(SALT_LENGTH);
		final byte[] ivs = getRandomBytes(IVS_LENGTH);
		
		try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()){
			baos.write(salt);
			baos.write(ivs);
			
			final Cipher encrypter = encryptionCipherForKeyfile(salt, ivs, newPassphrase);
			baos.write(encrypter.doFinal(key));
			return baos.toByteArray();
		} catch(BadPaddingException | IllegalBlockSizeException ex) {
			throw new IOException(ex);
		}
	}
	
	public byte[] getRandomBytes(int n) {
		final byte[] out = new byte[n];
		rng.nextBytes(out);
		return out;
	}
	
	public Path encryptFileToTemp(Path in) throws IOException{
		long inputSize = Files.size(in);
		final byte[] buf = new byte[Math.min(RESET_ENC_CIPHER_EVERY, (int)Math.min(Integer.MAX_VALUE, inputSize))];
		
		final Path out = Files.createTempFile(null, null);
		try(final InputStream is = Files.newInputStream(in, StandardOpenOption.READ);
			final OutputStream os = Files.newOutputStream(out, StandardOpenOption.WRITE);){
			
			while(true) {
				int read = is.read(buf);
				if(read == -1) {
					return out;
				} else {
					byte[] ivs = getRandomBytes(IVS_LENGTH);
					Cipher c = encryptionCipherForSecret(ivs);
					os.write(ivs);
					final byte[] toWrite = c.doFinal(buf, 0, read);
					os.write(toWrite);
				}
			}
		} catch(BadPaddingException | IllegalBlockSizeException ex) {
			throw new IOException(ex);
		}
	}
	
	public void decryptFile(Path in, Path out) throws IOException {
		final long inputSize = Files.size(in);
		final byte[] ivs = new byte[IVS_LENGTH];
		
		try(final InputStream is = Files.newInputStream(in, StandardOpenOption.READ);
			final OutputStream os = Files.newOutputStream(out, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)){
			
			while(true) {
				is.read(ivs);
				Cipher c = decryptionCipherForSecret(ivs);
				//This needs to be huge for performance reasons
				//Java AEAD decryption is completely non performant for update() calls thru Java 10,
				//due to not accelerating w/ hardware, and buffering the output 
				final byte[] buf = new byte[Math.min(RESET_DEC_CIPHER_EVERY, (int)Math.min(Integer.MAX_VALUE, inputSize))];
				int read = is.read(buf);
				if(read == -1) {
					return;
				} else {
					final byte[] toWrite = c.doFinal(buf, 0, read);
					os.write(toWrite);
				}
			}
		} catch(IllegalBlockSizeException | BadPaddingException ex ) {
			throw new RuntimeException(ex);
		}
	}
		
	public byte[] encrypt(byte[] in) {
		final byte[] ivs = getRandomBytes(IVS_LENGTH);
		final Cipher cipher = encryptionCipherForSecret(ivs);
		
		try(final ByteArrayOutputStream baos = new ByteArrayOutputStream()){
			baos.write(ivs);
			baos.write(cipher.doFinal(in));
			return baos.toByteArray();
		} catch(IOException  | BadPaddingException | IllegalBlockSizeException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public byte[] decrypt(byte[] in) {
		final byte[] ivs = new byte[IVS_LENGTH];
		try (final ByteArrayInputStream bais = new ByteArrayInputStream(in)) {
			bais.read(ivs);
			final Cipher cipher = decryptionCipherForSecret(ivs);
			return cipher.doFinal(bais.readAllBytes());
		} catch(IOException | BadPaddingException | IllegalBlockSizeException ex) {
			throw new RuntimeException(ex);
		}
	}
}
