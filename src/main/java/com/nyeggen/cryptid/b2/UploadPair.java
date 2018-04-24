package com.nyeggen.cryptid.b2;

import java.io.IOException;

import com.backblaze.b2.client.structures.B2UploadFileRequest;
import com.nyeggen.cryptid.util.KeyfileCrypter;

//Point of this is to bundle the two uploads together and compare by body size,
//so we don't end up repeatedly uploading only small namefile uploads and deleting
//them as orphans
public class UploadPair implements Comparable<UploadPair> {
	public static final UploadPair QUEUE_POISON = new UploadPair(null, false);
	
	private final LocalRecord rec;
	private final boolean uploadBody;
	private final long uploadSize;
	
	public static UploadPair contentUpload(LocalRecord rec) {
		return new UploadPair(rec, true);
	}
	
	public static UploadPair namefileUpload(LocalRecord rec) {
		return new UploadPair(rec, false);
	}
	
	private UploadPair(LocalRecord rec, boolean uploadBody) {
		this.uploadBody = uploadBody;
		this.rec = rec;
		if(!uploadBody) uploadSize = 0;
		else uploadSize = rec.getSize();
	}
	
	public String getLocalName() { 
		return rec.getLocalName(); 
	}
	public B2UploadFileRequest getBodyUpload(KeyfileCrypter crypt, String bucketId) throws IOException {
		if(!uploadBody) return null;
		return rec.uploadForBody(crypt, bucketId);
	}
	public B2UploadFileRequest getNamefileUpload(KeyfileCrypter crypt, String bucketId) throws IOException {
		return rec.uploadForName(crypt, bucketId);
	}
	
	@Override
	public int compareTo(UploadPair o) {
		if(this == o) return 0;
		//POISON object is always at end of queue
		if(this == QUEUE_POISON) return 1;
		if(o == QUEUE_POISON) return -1;
		return Long.compare(uploadSize, o.uploadSize);
	}

}
