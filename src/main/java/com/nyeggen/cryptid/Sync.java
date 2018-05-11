package com.nyeggen.cryptid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import com.backblaze.b2.client.B2ListFilesIterable;
import com.backblaze.b2.client.B2StorageClient;
import com.backblaze.b2.client.contentHandlers.B2ContentSink;
import com.backblaze.b2.client.contentSources.B2ByteArrayContentSource;
import com.backblaze.b2.client.contentSources.B2ContentTypes;
import com.backblaze.b2.client.contentSources.B2Headers;
import com.backblaze.b2.client.exceptions.B2Exception;
import com.backblaze.b2.client.exceptions.B2NotFoundException;
import com.backblaze.b2.client.structures.B2DeleteFileVersionRequest;
import com.backblaze.b2.client.structures.B2FileVersion;
import com.backblaze.b2.client.structures.B2UploadFileRequest;
import com.backblaze.b2.client.webApiHttpClient.B2StorageHttpClientBuilder;
import com.nyeggen.cryptid.b2.B2Deletable;
import com.nyeggen.cryptid.b2.IntrinsicMetadata;
import com.nyeggen.cryptid.b2.LocalRecord;
import com.nyeggen.cryptid.b2.NamefileMetadata;
import com.nyeggen.cryptid.b2.RemoteRecord;
import com.nyeggen.cryptid.b2.UploadPair;
import com.nyeggen.cryptid.util.KeyfileCrypter;

public class Sync implements AutoCloseable {
	//IE, 500M bytes.  Above this, we use the B2 "large file" API
	private static final long LARGE_FILE_SIZE_LIMIT = 500000000;

	private static final String USER_AGENT = "java";
	private static final String KEYFILE_NAME = "KEYFILE";
	
	private final B2StorageClient client;
	private final KeyfileCrypter crypt;
	private final String bucketId;
	private final Path baseDir;
	
	//Maps from the remote file name of the MD to the record, initially
	//filled and reduced over time
	private final Map<String, B2Deletable> toDelete = new HashMap<>();
	//Ordered smallest uploads first
	private final PriorityBlockingQueue<UploadPair> uploads = new PriorityBlockingQueue<UploadPair>(16);
	//Map from the putative local name to the record
	private final Map<String, RemoteRecord> remoteFiles = new HashMap<>();
	//Total number of local files currently scanned
	private final AtomicInteger totalCounter = new AtomicInteger(0);
	//This is out default parallelism for how many files we attempt to upload at once
	//To saturate bandwidth, many small files require more threads and vice versa
	private int uploadParallelism = 2;
	//This thread pool is passed to B2 for their internal parallelism when uploading large files
	private final ExecutorService pool = Executors.newFixedThreadPool(4);
	//Don't upload pure renames, only new content
	private boolean skipRenames = true;

	public Sync(Path localBaseDir, String bucketName, char[] passphrase, String accountID, String applicationID) throws B2Exception {
		this.client = B2StorageHttpClientBuilder.builder(
				accountID,
				applicationID,
				USER_AGENT).build();
		this.baseDir = localBaseDir;
		this.bucketId = client.getBucketOrNullByName(bucketName).getBucketId();
		
		//Try to download keyfile if exists
		//We do this dumb indirection bc b2 doesn't have an easy exists check,
		//standard test is to try to get, which throws if doesn't exist
		//But the exception doesn't necessarily prevent double-assignment, even
		//if it's the last clause in the block, so we need a guaranteed initialization
		//path after the try-catch
		byte[] encryptedKeyfile = null;
		try {
			final ByteArrayOutputStream keyfileStream = new ByteArrayOutputStream();
			client.downloadByName(bucketName, KEYFILE_NAME, new B2ContentSink() {
				@Override
				public void readContent(B2Headers responseHeaders, InputStream in) throws B2Exception, IOException {
					in.transferTo(keyfileStream);
				}
			});
			encryptedKeyfile = keyfileStream.toByteArray();
		} catch (B2NotFoundException ex) {
			//Otherwise, generate and upload
			encryptedKeyfile = null;
		}
		if(encryptedKeyfile == null) {
			System.out.println("No keyfile found, generating and uploading");
			crypt = new KeyfileCrypter(passphrase);
			try {
				uploadKeyfileWithPassphrase(passphrase);
			} catch(IOException ex) { 
				throw new RuntimeException(ex);
			}
		} else {
			crypt = new KeyfileCrypter(encryptedKeyfile, passphrase);
			System.out.println("Keyfile decrypted");
		}
	}
	
	public void setSkipRenames(boolean v) { 
		this.skipRenames = v;
	}
	
	public void setUploadParallelism(int n) {
		this.uploadParallelism = n;
	}
	
	//Serves for both initial write, and changing password
	public void uploadKeyfileWithPassphrase(char[] newPassphrase) throws IOException, B2Exception {
		final byte[] toUpload = crypt.encryptKeyfile(newPassphrase);
		B2UploadFileRequest req = B2UploadFileRequest.builder(
				bucketId, 
				KEYFILE_NAME, 
				B2ContentTypes.APPLICATION_OCTET, 
				B2ByteArrayContentSource.build(toUpload)).build();
		client.uploadSmallFile(req);
	}
	
	@Override
	public void close() throws Exception {
		client.close();
		pool.shutdown();
	}
	
	//Scans local filesystem and correlates w/ remote records
	private FileVisitor<Path> getLocalScanner() {
		return new FileVisitor<Path>() {
	        public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
	            return FileVisitResult.CONTINUE;
	        };
	        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
	            return FileVisitResult.CONTINUE;
	        };
	        public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
	            return FileVisitResult.CONTINUE;
	        };
	        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
	            if (!Files.exists(file)) return FileVisitResult.CONTINUE;
	            if (Files.isDirectory(file)) return FileVisitResult.CONTINUE;
	        	final LocalRecord lr = new LocalRecord(file);
	        	if(totalCounter.incrementAndGet() % 1000 == 0) {
	        		System.out.println(totalCounter.get() + " files scanned");
	        	}
	        	
				final boolean existingNameMatch;
				final boolean identityMatch;
				final String remoteIntrinsicName; 
				
				//Find corresponding name remotely, if it might exist
				final RemoteRecord rr = remoteFiles.get(lr.getLocalName());
				//Potential match
				existingNameMatch = (rr != null);
				if(existingNameMatch) {
					identityMatch = identityMatch(lr, rr);
					if(identityMatch) {
						remoteIntrinsicName = rr.getIntrinsicMDRemoteName();
					} else {
						//Name and content match, but not identical - result of "touch" operation
						remoteIntrinsicName = findMatchOrNullByContent(lr, remoteFiles.values());
					}
				} else {
					//No name match, but is potentially a content match
					identityMatch = false;
					remoteIntrinsicName = findMatchOrNullByContent(lr, remoteFiles.values());
				}
				
				if(identityMatch) {
					//Everything matches, do nothing, remove from delete list
					toDelete.remove(rr.getIntrinsicMD().getRemoteName());
					toDelete.remove(rr.getNamefileMD().getRemoteName());
				} else if( (existingNameMatch && remoteIntrinsicName != null) //Name and content matches, timestamp doesn't.
						|| (remoteIntrinsicName != null)) { //Content matches, not name.
					//Don't delete the intrinsic, since we have content match
					toDelete.remove(remoteIntrinsicName);
					//Generate namefile and upload
					final UploadPair pair = UploadPair.namefileUpload(lr);
					uploads.add(pair);
				} else {
					//No match to be found.  Generate upload
					final UploadPair pair = UploadPair.contentUpload(lr);
					uploads.add(pair);
				}
				return FileVisitResult.CONTINUE;
	        }
		};
	}
	
	//Finds any matching content which we can just generate a namefile
	//for the local record to point at remote
	private static String findMatchOrNullByContent(LocalRecord lr, Collection<RemoteRecord> remoteFiles) throws IOException {
		for(final RemoteRecord rr : remoteFiles) {
			final long lrSize = lr.getSize();
			final long rrSize = rr.getSize();
			final boolean sizeMatch = (lrSize == rrSize);

			if(! sizeMatch) continue;
			
			//Check for hash match if we have size match
			final byte[] rrHash = rr.getHash();
			final byte[] lrHash = lr.populateHash();
			if(Arrays.equals(rrHash, lrHash)) {
				return rr.getIntrinsicMDRemoteName();
			} else continue;
		}
		return null;
	}
	
	private static boolean identityMatch(LocalRecord lr, RemoteRecord rr) {
		final long lrTimestamp = lr.getTimestamp();
		final long rrTimestamp = rr.getTimestamp();
		final boolean timestampMatch = (lrTimestamp == rrTimestamp);
		if(! timestampMatch) return false;
		
		final long lrSize = lr.getSize();
		final long rrSize = rr.getSize();
		final boolean sizeMatch = (lrSize == rrSize);
		if(! sizeMatch) return false;

		final String lrName = lr.getLocalName();
		final String rrName = rr.getLocalName();
		final boolean nameMatch = lrName.equals(rrName);
		if(! nameMatch) return false;
		
		return true;
	}
	
	private void deleteLeftovers() throws B2Exception {
		final Collection<B2Deletable> md = toDelete.values();
		int cnt = md.size();
		System.out.println(cnt + " remote files to delete");
		for(final B2Deletable i : md) {
			System.out.println("Deleting " + i.getRemoteName());
			final B2DeleteFileVersionRequest del = i.toDelete();
			client.deleteFileVersion(del);
		}
	}
	
	//Checks the list for duplicate metadata, replacing older with newer in case
	//of conflict
	private static void checkAndAddNamefile(Map<String, NamefileMetadata> nfmd, NamefileMetadata md) {
		final String mdLocalName = md.getLocalName();
		final NamefileMetadata existing = nfmd.get(mdLocalName);
		if(existing == null) {
			//No name match, insert and return
			nfmd.put(mdLocalName, md);
		} else {
			//Name collision; retain more recent
			if(md.getTimestamp() > existing.getTimestamp()) {
				nfmd.put(mdLocalName, md);
			}
		}
	}
	
	//Calling this twice will result in nothing good.
	public void run(boolean deleteOrphans) throws B2Exception, IOException {				
		//From remote name (guaranteed unique) to MD record
		final Map<String, IntrinsicMetadata> imd = new HashMap<>();
		//From local name (not guaranteed unique upstream) to MD record
		final Map<String, NamefileMetadata> nfmd = new HashMap<>();
		try {
			System.out.println("Scanning remote files");
			int i = 0;
			final B2ListFilesIterable remoteIt = client.fileNames(bucketId);
			for(B2FileVersion b2fv : remoteIt) {
				if(++i % 1000 == 0) System.out.println(i + " remote files scanned");
				//Split into namefiles and intrinsic files; add all of both of them
				//to the delete lists.  Things will be removed from delete lists as they
				//are correlated with local files, leaving only orphans to be deleted
				try {
					if (b2fv.getFileName().equals(KEYFILE_NAME)) {
						//Do nothing.  This is your keyfile, pulled earlier.
					} else if(IntrinsicMetadata.isIntrinsicMDName(b2fv)) {
						final IntrinsicMetadata md = IntrinsicMetadata.fromB2FileVersion(b2fv, crypt);
						imd.put(md.getRemoteName(), md);
						if(deleteOrphans) toDelete.put(md.getRemoteName(), md);
					} else if(NamefileMetadata.isNamefileMDName(b2fv)) {
						final NamefileMetadata md = NamefileMetadata.fromB2FileVersion(b2fv, crypt);
						//Check for duplicate local names
						checkAndAddNamefile(nfmd, md);
						if(deleteOrphans) toDelete.put(md.getRemoteName(), md);
					} else {
						//The checks above are already complementary, so currently this
						//should never get reached; we will get an exception trying
						//to convert.
						throw new IllegalStateException();
					}
				} catch(Exception ex) {
					//Incompatible file, presumably
					System.out.println("incompatible file: " + b2fv.getFileName());	
					//Delete immediately, if we're hard-syncing
					if(deleteOrphans) {
						client.deleteFileVersion(B2DeleteFileVersionRequest.builder(b2fv.getFileName(), b2fv.getFileId()).build());
					}
				}; 
			}
			System.out.println(i + " files found remotely");
		} catch(B2Exception ex) {
			throw new RuntimeException(ex);
		}
		
		//Correlate remote intrinsic & namefile to gen complete remote records
		int i = 0;
		//Note that this only works if we have namefiles for a particular intrinsic,
		//otherwise it'll be deleted.
		for(final NamefileMetadata namefile : nfmd.values()) {
			//If we have multiple namefiles, they're all treated as valid, if we have for
			//instance local dupes
			final IntrinsicMetadata intrinsic = imd.get(namefile.getAssociatedIntrinsicFile());
			if(intrinsic != null) {
				final RemoteRecord rr = new RemoteRecord(intrinsic, namefile);
				remoteFiles.put(rr.getLocalName() ,rr);
				i++;
			} else {
				//We have namefile without associated intrinsic, somehow. Namefile will be deleted
				//based on having added it to the delete list above and not producing a RemoteRecord
				//to remove it from the delete list
			}
		}
		System.out.println(i + " remote records correlated");
		
		//Walk local structure, could do in separate thread
		{
			Files.walkFileTree(baseDir, getLocalScanner());
			//Signal we are done
			uploads.add(UploadPair.QUEUE_POISON);
			System.out.println(totalCounter.get() + " total local files found");	
			//File scanner handles local / remote correlation, so we can actually delete here
			if(deleteOrphans) {
				System.out.println("Deleting leftover files on remote");
				//Delete leftovers
				try {
					deleteLeftovers();
					System.out.println("Delete finished");
				} catch(B2Exception ex) {
					throw new RuntimeException("Delete failed", ex);
				}
			}
		}
		
		//Upload
		System.out.println("Uploading files");
		final AtomicInteger uploadCounter = new AtomicInteger(0);
		final Thread[] uploaders = new Thread[uploadParallelism];
		for(int thread = 0; thread < uploaders.length; thread++) {
			uploaders[thread] = new Thread(()->{
				while(true) try {
					final UploadPair upload = uploads.take();
					if(upload == UploadPair.QUEUE_POISON) {
						//Add back to the queue so other threads can die
						uploads.put(upload);
						break;
					}
					System.out.println("Uploading for local file: " + upload.getLocalName());
					final B2UploadFileRequest namefile = upload.getNamefileUpload(crypt, bucketId);
					final B2UploadFileRequest body = upload.getBodyUpload(crypt, bucketId);
					if(namefile != null && body == null && skipRenames) {
						System.out.println("Skipping rename, " + uploads.size() + " remaining, " + totalCounter.get() + " files scanned");
						continue;						
					}
					if(namefile != null) {
						System.out.println("Uploading namefile: " + namefile.getFileName());
						client.uploadSmallFile(namefile);
					}
					if(body != null) {
						System.out.println("Uploading body: " + body.getFileName());
						if(body.getContentSource().getContentLength() > LARGE_FILE_SIZE_LIMIT) {
							client.uploadLargeFile(body, pool);
						} else {
							client.uploadSmallFile(body);
						}
						upload.deleteTempCryptFile();
					}
					System.out.println(uploadCounter.incrementAndGet() + " pairs uploaded, " + uploads.size() + " remaining, " + totalCounter.get() + " files scanned");
				} catch (IOException | B2Exception | InterruptedException ex) {
					throw new RuntimeException(ex);
				}
			});
		}
		for(final Thread t : uploaders) t.start();
		for(final Thread t : uploaders) {
			try {t.join();}
			catch(InterruptedException ex) { throw new RuntimeException(ex); }
		}
		//Also delete orphaned large files, but only at end, to allow upload continuation
		if(deleteOrphans) for(final B2FileVersion b2fv : client.unfinishedLargeFiles(bucketId)) {
			System.out.println("Deleting partial " + b2fv.getFileName());
			client.deleteFileVersion(b2fv);
		}

	}
}
