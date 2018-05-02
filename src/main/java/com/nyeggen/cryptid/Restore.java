package com.nyeggen.cryptid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

import com.backblaze.b2.client.B2ListFilesIterable;
import com.backblaze.b2.client.B2StorageClient;
import com.backblaze.b2.client.contentHandlers.B2ContentSink;
import com.backblaze.b2.client.contentSources.B2Headers;
import com.backblaze.b2.client.exceptions.B2Exception;
import com.backblaze.b2.client.structures.B2FileVersion;
import com.backblaze.b2.client.webApiHttpClient.B2StorageHttpClientBuilder;
import com.nyeggen.cryptid.b2.IntrinsicMetadata;
import com.nyeggen.cryptid.b2.NamefileMetadata;
import com.nyeggen.cryptid.b2.RemoteRecord;
import com.nyeggen.cryptid.util.KeyfileCrypter;

public class Restore implements AutoCloseable {
	private static final String USER_AGENT = "java";
	private static final String KEYFILE_NAME = "KEYFILE";
	private final B2StorageClient client;
	private final KeyfileCrypter crypt;
	private final String bucketId;
	private final String bucketName;
	
	public Restore(String bucketName, char[] passphrase, String accountID, String applicationID) {
		this.bucketName = bucketName;
		this.client = B2StorageHttpClientBuilder.builder(
				accountID,
				applicationID,
				USER_AGENT).build();
		try {
			this.bucketId = client.getBucketOrNullByName(bucketName).getBucketId();		

			System.out.println("Decrypting keyfile");
			final ByteArrayOutputStream keyfileStream = new ByteArrayOutputStream();
			client.downloadByName(bucketName, KEYFILE_NAME, new B2ContentSink() {
				@Override
				public void readContent(B2Headers responseHeaders, InputStream in) throws B2Exception, IOException {
					in.transferTo(keyfileStream);
				}
			});
			System.out.println("Decrypted keyfile");
			final byte[] encryptedKeyfile = keyfileStream.toByteArray();
			crypt = new KeyfileCrypter(encryptedKeyfile, passphrase);
		} catch (B2Exception ex) {
			throw new RuntimeException(ex);
		}
		
		
	}
	@Override
	public void close() throws Exception {
		client.close();
	}

	private B2ContentSink decryptionSink(OutputStream os) {
		return (B2Headers responseHeaders, InputStream in) -> { crypt.decrypt(in, os); };
	}
	
	//All remote records are correlated; if they pass the filter (eg a regex match on the name,
	//a date condition, etc) the locator function is used to determine the location they are then
	//restored to.
	public void restoreByFilter(Predicate<RemoteRecord> filter, Function<RemoteRecord, Path> locator) throws IOException, B2Exception {
		final Map<String, IntrinsicMetadata> imd = new HashMap<>();
		final Collection<NamefileMetadata> nfmd = new ArrayList<>();
		try {
			System.out.println("Scanning remote files");
			int i = 0;
			final B2ListFilesIterable remoteIt = client.fileNames(bucketId);
			for(B2FileVersion b2fv : remoteIt) {
				if(++i % 1000 == 0) System.out.println(i + " remote files scanned");
				try {
					if (b2fv.getFileName().equals(KEYFILE_NAME)) {
						//Do nothing.  This is your keyfile, pulled earlier.
					} else if(IntrinsicMetadata.isIntrinsicMDName(b2fv)) {
						IntrinsicMetadata md = IntrinsicMetadata.fromB2FileVersion(b2fv, crypt);
						imd.put(md.getRemoteName(), md);
					} else if(NamefileMetadata.isNamefileMDName(b2fv)) {
						NamefileMetadata md = NamefileMetadata.fromB2FileVersion(b2fv, crypt);
						nfmd.add(md);
					} else {
						//The checks above are already complementary, so currently this
						//should never get reached; we will get an exception trying
						//to convert.
						throw new IllegalStateException();
					}
				} catch(Exception ex) {
					//Incompatible file, presumably
					System.out.println("incompatible file: " + b2fv.getFileName());	
				}; 
			}
			System.out.println(i + " files found remotely");
		} catch(B2Exception ex) {
			throw new RuntimeException(ex);
		}
		
		//Correlate remote intrinsic & namefile to gen complete remote records
		int i = 0;
		for(final NamefileMetadata namefile : nfmd) {
			//If we have multiple namefiles, they're all treated as valid
			final IntrinsicMetadata intrinsic = imd.get(namefile.getAssociatedIntrinsicFile());
			if(intrinsic != null) {
				final RemoteRecord rr = new RemoteRecord(intrinsic, namefile);
				if(filter.test(rr)) {
					i++;
					final Path restoreTo = locator.apply(rr);
					System.out.println("Resotring " + rr.getIntrinsicMDRemoteName() + " to " + restoreTo.toString());
					try(final OutputStream os = Files.newOutputStream(restoreTo, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)){
						client.downloadById(rr.getIntrinsicMD().getRemoteID(), decryptionSink(os));
					}
				}
			}
		}
		System.out.println(i + " remote records restored");
	}
	
	public void restoreRemoteFile(String remoteName, String localOut) throws IOException, B2Exception {
		System.out.println("Restoring " + remoteName);
		try (final OutputStream os = Files.newOutputStream(Paths.get(localOut), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)){
			client.downloadByName(bucketName, remoteName, decryptionSink(os));
		}
		System.out.println("Restored " + remoteName + " to " + localOut);
	}
}
