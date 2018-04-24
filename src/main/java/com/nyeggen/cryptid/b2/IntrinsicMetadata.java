package com.nyeggen.cryptid.b2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.backblaze.b2.client.structures.B2DeleteFileVersionRequest;
import com.backblaze.b2.client.structures.B2DownloadByNameRequest;
import com.backblaze.b2.client.structures.B2FileVersion;
import com.nyeggen.cryptid.util.Hasher;
import com.nyeggen.cryptid.util.KeyfileCrypter;

//This is the structure for metadata embedded in the underlying remote file,
//not in a replaceable metadata file.  This implies it's immutable wrt content.
public class IntrinsicMetadata implements B2Deletable {
	private static final String MD_KEY = "m";
	
	private final long size;
	//This is the salted hash of the unencrypted file, or null if not computed yet
	private byte[] hash;
	//Name of the remote content file, may be null if it hasn't been assigned
	private final String remoteName;
	//ID to support deletes, may be null if it hasn't been assigned
	private String remoteID = null;

	private IntrinsicMetadata(byte[] hash, long size, String remoteName) {
		this.hash = hash;
		this.size = size;
		this.remoteName = remoteName;
	}
	
	public IntrinsicMetadata(byte[] hash, long size) {
		this.hash = hash;
		this.size = size;
		this.remoteName = UUID.randomUUID().toString();
	}
	
	@Override
	public String getRemoteName() { return remoteName; }
	public byte[] getHash() { return hash; }
	public String getRemoteID() { return remoteID; }
	
	public long getSize() { return size; }
	
	public void setHash(byte[] hash) {
		this.hash = hash;
	}
	
	@Override
	public B2DeleteFileVersionRequest toDelete() {
		return B2DeleteFileVersionRequest.builder(remoteName, remoteID).build();
	}
	
	public static boolean isIntrinsicMDName(B2FileVersion b2fv) {
		return !b2fv.getFileName().startsWith(NamefileMetadata.NAMEFILE_PREFIX);
	}

	//Buffer is laid out hash + size (as long)
	public static IntrinsicMetadata fromB2FileVersion(B2FileVersion b2fv, KeyfileCrypter crypt) {
		if(!isIntrinsicMDName(b2fv)) throw new IllegalArgumentException();

		final String remoteName = b2fv.getFileName();

		final Map<String, String> info = b2fv.getFileInfo();
		final String encoded = info.get(MD_KEY);
		
		final byte[] encrypted = Base64.getDecoder().decode(encoded);
		final byte[] decrypted = crypt.decrypt(encrypted);
		final ByteBuffer buf = ByteBuffer.wrap(decrypted).order(ByteOrder.LITTLE_ENDIAN);
		
		final byte[] hash = new byte[Hasher.OUTPUT_LENGTH];
		buf.get(hash);
		final long size = buf.getLong();
		
		final IntrinsicMetadata out = new IntrinsicMetadata(hash, size, remoteName);
		out.remoteID = b2fv.getFileId();
		
		return out;
	}
	
	//This metadata is attached to the B2UploadRequest that actually has the content
	public Map<String, String> mdForUpload(KeyfileCrypter crypt) throws IOException {
		
		final ByteBuffer buf = ByteBuffer.allocate(Hasher.OUTPUT_LENGTH + 8).order(ByteOrder.LITTLE_ENDIAN);
		buf.put(hash);
		buf.putLong(size);
		final byte[] plain = buf.array();
		final byte[] encrypted = crypt.encrypt(plain);
		final String encoded = Base64.getEncoder().encodeToString(encrypted);
		
		final Map<String, String> out = new HashMap<>(1);
		out.put(MD_KEY, encoded);
		
		return out;
	}
	
	public B2DownloadByNameRequest downloadForBody(String bucket) {
		return B2DownloadByNameRequest.builder(bucket, remoteName)
				.build();
	}

}
