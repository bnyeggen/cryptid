package com.nyeggen.cryptid.b2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.backblaze.b2.client.contentSources.B2ByteArrayContentSource;
import com.backblaze.b2.client.contentSources.B2ContentTypes;
import com.backblaze.b2.client.structures.B2DeleteFileVersionRequest;
import com.backblaze.b2.client.structures.B2FileVersion;
import com.backblaze.b2.client.structures.B2UploadFileRequest;
import com.nyeggen.cryptid.util.KeyfileCrypter;

//This is replaceable remote metadata to support rename / move / touch
//semantics, or anything else that doesn't affect content.

public class NamefileMetadata implements B2Deletable {
	public static final String NAMEFILE_PREFIX = "md/";
	
	long timestamp;
	//Name of the local file we're mirroring
	String localName;
	//Name of the remote namefile itself
	String remoteName;
	//ID to support deletes
	String remoteID;
	//Name of the remote intrinsic file to which this refers
	String associatedIntrinsicFile;

	@Override
	public String getRemoteName() { return remoteName; }
	public String getAssociatedIntrinsicFile() { return associatedIntrinsicFile; }
	public String getLocalName() { return localName; }
	public long getTimestamp() { return timestamp; }
	
	public static boolean isNamefileMDName(B2FileVersion b2fv) {
		return b2fv.getFileName().startsWith(NAMEFILE_PREFIX);
	}
	
	private NamefileMetadata(String localName, long timestamp, String remoteName, String associatedIntrinsic) {
		this.localName = localName;
		this.timestamp = timestamp;
		this.remoteName = remoteName;
		this.associatedIntrinsicFile = associatedIntrinsic;
	}
	public NamefileMetadata(String localName, long timestamp, String associatedIntrinsic) {
		this(localName, timestamp, NAMEFILE_PREFIX + UUID.randomUUID().toString(), associatedIntrinsic);
	}
	
	public B2UploadFileRequest toUpload(KeyfileCrypter crypt, String bucketId) throws IOException{
		//Use existing timestamp field, non encrypted
		final Map<String, String> meta = new HashMap<>(2);
		meta.put("src_last_modified_millis", Long.toString(timestamp));
		
		//Encrypt the local name
		final byte[] nameBytes = localName.getBytes(StandardCharsets.UTF_8);
		final byte[] encrypted = crypt.encrypt(nameBytes);
		final String encoded = Base64.getEncoder().encodeToString(encrypted);
		meta.put("m", encoded);
		
		//Associated intrinsic file in plaintext, since it's random
		meta.put("a", associatedIntrinsicFile);
		
		final B2UploadFileRequest out = B2UploadFileRequest.builder(
				bucketId, 
				remoteName,
				B2ContentTypes.APPLICATION_OCTET, 
				B2ByteArrayContentSource.build(crypt.getRandomBytes(16)))
					.setCustomFields(meta)
					.build();
		
		return out;
	}
	
	@Override
	public B2DeleteFileVersionRequest toDelete(){
		return B2DeleteFileVersionRequest.builder(remoteName, remoteID).build();
	}
	
	public static NamefileMetadata fromB2FileVersion(B2FileVersion b2fv, KeyfileCrypter crypt) {
		final String remoteName = b2fv.getFileName();

		final Map<String, String> meta = b2fv.getFileInfo();
		final String timestampString = meta.get("src_last_modified_millis");
		final long timestamp = Long.parseLong(timestampString);
		
		final String encoded = meta.get("m");
		final byte[] encrypted = Base64.getDecoder().decode(encoded);
		final byte[] nameBytes = crypt.decrypt(encrypted);
		final String localName = new String(nameBytes, StandardCharsets.UTF_8);
		
		final String associated = meta.get("a");
				
		final NamefileMetadata out = new NamefileMetadata(localName, timestamp, remoteName, associated);
		out.remoteID = b2fv.getFileId();
		return out;
	}
	
	public boolean refersToIntrinsic(IntrinsicMetadata imd) {
		return associatedIntrinsicFile.equals(imd.getRemoteName());
	}
}
