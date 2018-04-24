package com.nyeggen.cryptid.b2;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import com.backblaze.b2.client.contentSources.B2ContentSource;
import com.nyeggen.cryptid.util.KeyfileCrypter;

public class EncryptedB2ContentSource implements B2ContentSource {
	private final Path source;
	private final KeyfileCrypter crypt;
	
	public EncryptedB2ContentSource(Path source, KeyfileCrypter crypt) {
		this.source = source;
		this.crypt = crypt;
	}
	@Override
	public Long getSrcLastModifiedMillisOrNull() throws IOException {
		return Files.getLastModifiedTime(source).toMillis();
	}
	
	@Override
	public String getSha1OrNull() throws IOException {
		//No point in pre calculating
		return null;
	}
	
	@Override
	public InputStream createInputStream() throws IOException {
		return crypt.createInputStream(source);
	}
	
	@Override
	public long getContentLength() throws IOException {
		return Files.size(source) + KeyfileCrypter.STREAM_PAD_SIZE;
	}
}
