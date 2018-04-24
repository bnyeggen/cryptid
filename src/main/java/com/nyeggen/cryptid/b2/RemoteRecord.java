package com.nyeggen.cryptid.b2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import com.backblaze.b2.client.B2StorageClient;
import com.backblaze.b2.client.contentHandlers.B2ContentSink;
import com.backblaze.b2.client.contentSources.B2Headers;
import com.backblaze.b2.client.exceptions.B2Exception;
import com.backblaze.b2.client.structures.B2DownloadByIdRequest;
import com.nyeggen.cryptid.util.KeyfileCrypter;

//Generated from the remote file
public class RemoteRecord {
	private final IntrinsicMetadata intrinsicMD;
	private final NamefileMetadata namefileMD;
	
	public RemoteRecord(IntrinsicMetadata imd, NamefileMetadata nmd) {
		this.intrinsicMD = imd;
		this.namefileMD = nmd;
	}
		
	public byte[] getHash() { return intrinsicMD.getHash(); }
	public long getSize() { return intrinsicMD.getSize(); }
	public long getTimestamp() { return namefileMD.timestamp; }
	public String getLocalName() { return namefileMD.localName; }	
	
	public String getIntrinsicMDRemoteName() { return intrinsicMD.getRemoteName(); }
	
	public IntrinsicMetadata getIntrinsicMD() { return intrinsicMD; }
	public NamefileMetadata getNamefileMD() { return namefileMD; }
	
	public void restore(B2StorageClient b2, KeyfileCrypter crypt) throws B2Exception, IOException {
		final String destination = namefileMD.localName;
		final Path destPath = Paths.get(destination);
		try(final OutputStream fos = Files.newOutputStream(destPath, StandardOpenOption.CREATE_NEW);){
			download(fos, b2, crypt);
		}
	}
	
	//Caller must close output stream
	public void download(final OutputStream out, B2StorageClient b2, KeyfileCrypter crypt) throws B2Exception {
		//TODO: Verify input stream is appropriately closed
		final B2ContentSink sink = new B2ContentSink() {
			@Override
			public void readContent(B2Headers responseHeaders, InputStream in) throws B2Exception, IOException {
				crypt.decrypt(in, out);
			}
		};
		//Don't need namefile for this
		final String intrinsicID = intrinsicMD.getRemoteID();
		final B2DownloadByIdRequest req = B2DownloadByIdRequest.builder(intrinsicID).build();
		b2.downloadById(req, sink);
	}
}
