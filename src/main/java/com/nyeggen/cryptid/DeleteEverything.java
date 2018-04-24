package com.nyeggen.cryptid;

import java.util.ArrayList;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

import com.backblaze.b2.client.B2ListFilesIterable;
import com.backblaze.b2.client.B2StorageClient;
import com.backblaze.b2.client.exceptions.B2Exception;
import com.backblaze.b2.client.structures.B2DeleteFileVersionRequest;
import com.backblaze.b2.client.structures.B2FileVersion;
import com.backblaze.b2.client.webApiHttpClient.B2StorageHttpClientBuilder;

//Editable script to delete everything for experimentation purposes
public class DeleteEverything {
	private static final String USER_AGENT = "java";
	private static final String ACCOUNT_ID = "";
	private static final String APPLICATION_KEY = "";
	
	private static final String BUCKET_NAME = "";
	
	
	public static void main(String[] args) throws Exception{
		try(B2StorageClient client = B2StorageHttpClientBuilder.builder(ACCOUNT_ID,
				APPLICATION_KEY,
				USER_AGENT).build();){
			final String bucketId = client.getBucketOrNullByName(BUCKET_NAME).getBucketId();
			
			final B2ListFilesIterable remoteIt = client.fileNames(bucketId);
			final AtomicInteger i = new AtomicInteger(0);
			final Queue<B2DeleteFileVersionRequest> dels = new ConcurrentLinkedQueue<>();
			for(B2FileVersion b2fv : remoteIt) {
				final B2DeleteFileVersionRequest del = B2DeleteFileVersionRequest.builder(b2fv.getFileName(), b2fv.getFileId()).build();
				dels.add(del);
			}
			System.out.println(dels.size() + " deletes scheduled");
			final ArrayList<Thread> threads = new ArrayList<>(16);
			for(int tCt = 0; tCt<16; tCt++) {
				final Thread t = new Thread(()->{
					while(true) { 
						final B2DeleteFileVersionRequest del = dels.poll();
						if(del == null) return;
						try {
							client.deleteFileVersion(del);
							if(i.incrementAndGet() % 100 == 0) System.out.println(i + " files deleted");
						} catch(B2Exception ex) { throw new RuntimeException(ex); }
					}
				});
				threads.add(t);
				t.start();
			}
			for(final Thread t : threads) t.join();
		}
	}
}
