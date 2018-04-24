package com.nyeggen.cryptid.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hasher {
	public static final int OUTPUT_LENGTH = 20;
	//Should this be here?
	public static final byte[] HASH_SALT = new byte[] {102, 38, -75, -38, 28, 1, -40, 108, 72, -57};
	
	public static byte[] hash(Path in) throws IOException {
		try {
			MessageDigest mDigest = MessageDigest.getInstance("SHA1");
			mDigest.update(HASH_SALT);
			
			final byte[] buf = new byte[8192];
			//No point in buffering since we read predictable chunks anyway
			try(final InputStream is = Files.newInputStream(in, StandardOpenOption.READ)){
				int read = is.read(buf);
				while(read != -1) {
					mDigest.update(buf, 0, read);
					read = is.read(buf);
				}
			}
			return mDigest.digest();
		} catch(NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
