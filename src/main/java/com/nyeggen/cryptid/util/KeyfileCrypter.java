package com.nyeggen.cryptid.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyfileCrypter {
	private static final int IVS_LENGTH = 16; //May also be 12?
	private static final int KEY_ROUNDS = 65536; //This is major performance bottleneck for small files
	private static final int AES_BITS = 256;
	//We might need to retain this for performance reasons?
	private static final int SALT_LENGTH = 16;
	
	private static final int GCM_TAG_LENGTH = 16; //num bytes
	
	private static final String CRYPT_MODE_GCM = "AES/GCM/NoPadding";
	private static final String KEY_SPEC = "PBKDF2WithHmacSHA256";
	
	//This passphrase is used to encrypt the underlying key, to support changing passphrases
	private final char[] password;
	//This is the raw underlying key, encrypted on the backend via the passphrase
	private final byte[] key;

	private final String CRYPT_MODE = CRYPT_MODE_GCM;
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
		if(CRYPT_MODE.equals(CRYPT_MODE_GCM)) {
			return new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivs);
		} else throw new IllegalStateException();
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
			try(final CipherInputStream cis = new CipherInputStream(bais, decryptor);){
				this.key = cis.readAllBytes();
				//Should be 32 bytes, ie 256 bits
			}
		} catch(IOException ex) {
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
			try (final CipherOutputStream cos = new CipherOutputStream(baos, encrypter);){
				cos.write(key);
			}
			
			return baos.toByteArray();
		}
	}
	
	public byte[] getRandomBytes(int n) {
		final byte[] out = new byte[n];
		rng.nextBytes(out);
		return out;
	}
	
	public static final int STREAM_PAD_SIZE = 32;
	
	public InputStream createInputStream(Path in) throws IOException {
		final byte[] ivs = getRandomBytes(IVS_LENGTH);
		final ByteArrayInputStream ivsStream = new ByteArrayInputStream(ivs);

		final Cipher encryptor = encryptionCipherForSecret(ivs);
		
		final InputStream fis = Files.newInputStream(in, StandardOpenOption.READ);
		//This will be closed when we close the produced InputStream
		@SuppressWarnings("resource")
		final CipherInputStream cis = new CipherInputStream(fis, encryptor);
		
		return new SequenceInputStream(ivsStream, cis);
	}
	
	public byte[] encrypt(byte[] in) {
		final byte[] ivs = getRandomBytes(IVS_LENGTH);
		final Cipher cipher = encryptionCipherForSecret(ivs);
		
		try(final ByteArrayOutputStream baos = new ByteArrayOutputStream()){
			baos.write(ivs);
			try(final CipherOutputStream cos = new CipherOutputStream(baos, cipher)){
				cos.write(in);
			}
			return baos.toByteArray();
		} catch(IOException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public byte[] decrypt(byte[] in) {
		final byte[] ivs = new byte[IVS_LENGTH];
		try (final ByteArrayInputStream bais = new ByteArrayInputStream(in)) {
			bais.read(ivs);
			final Cipher cipher = decryptionCipherForSecret(ivs);
			try(final CipherInputStream is = new CipherInputStream(bais, cipher)){
				return is.readAllBytes();
			}
		} catch(IOException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public void decrypt(InputStream is, OutputStream os) throws IOException {
		final byte[] ivs = new byte[IVS_LENGTH];
		is.read(ivs);
		final Cipher cipher = decryptionCipherForSecret(ivs);
		try (final CipherInputStream cis = new CipherInputStream(is, cipher)){
			cis.transferTo(os);
		}
	}
}
