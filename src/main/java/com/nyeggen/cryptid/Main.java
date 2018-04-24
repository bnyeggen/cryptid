package com.nyeggen.cryptid;

import java.nio.file.Paths;

public class Main {
	
	public static void main(String[] args) throws Exception {
		String configLoc = null;
		String bucket = null;
		String localPath = null;
		char[] passphrase = null;
		String accountID = null;
		String applicationID = null;
		boolean deleteOrphans = false;
		int nThreads = 2;
		char[] newPassphrase = null;

		//Manually incrementing
		for(int i=0; i<args.length; ) {
			if(args[i].equals("-h")) {
				System.out.println("Options: \n");
				System.out.println("-h");
				System.out.println("Displays this help prompt\n");
				System.out.println("-path [PATH]");
				System.out.println("Local path to synchronize with remote\n");
				System.out.println("-pw [PASSWORD]");
				System.out.println("This password will be used to decrypt the keyfile\n");
				System.out.println("-accountID [ID]");
				System.out.println("B2 account ID\n");
				System.out.println("-applicationID [ID]");
				System.out.println("B2 application ID\n");
				System.out.println("-delete");
				System.out.println("This flag causes extraneous files on the remote to be deleted, ie, the remote should be an exact mirror of the local file system with no extras after the sync completes\n");
				System.out.println("-config [CONFIG]");
				System.out.println("This config file will be used to load default settings\n");
				System.out.println("-threads [n]");
				System.out.println("This many threads will upload files in parallel. Default 2.\n");
				System.out.println("-newPW [PASSWORD]");
				System.out.println("Password on keyfile will be changed to this and uploaded\n");
				i++; 
				continue;
			}
			if(args[i].equals("-path")) {
				localPath = args[i+1];
				i += 2;
				continue;
			}
			if(args[i].equals("-pw")) {
				passphrase = args[i+1].toCharArray();
				i+=2;
				continue;
			}
			if(args[i].equals("-delete")) {
				deleteOrphans = true;
				i++;
				continue;
			}
			if(args[i].equals("-config")) {
				configLoc = args[i+1];
				i+=2;
				continue;
			}
			if(args[i].equals("-accountID")) {
				accountID = args[i+1];
				i+=2;
				continue;
			}
			if(args[i].equals("-applicationID")) {
				applicationID = args[i+1];
				i+=2;
				continue;
			}
			if(args[i].equals("-threads")) {
				nThreads = Integer.parseInt(args[i+1]);
				i+=2;
				continue;
			}
			if(args[i].equals("-newPW")) {
				newPassphrase = args[i+1].toCharArray();
				i+=2;
				continue;
			}
		}
		if(configLoc == null) Config.load();
		else Config.load(configLoc);
		
		if(passphrase == null) passphrase = Config.getInstance().getDefaultPassphrase().toCharArray();
		if(localPath == null) localPath = Config.getInstance().getDefaultSyncPath();
		if(bucket == null) bucket = Config.getInstance().getDefaultBucket();
		if(applicationID == null) applicationID = Config.getInstance().getApplicationKey();
		if(accountID == null) accountID = Config.getInstance().getAccountID();
		
		try (final Sync sync = new Sync(
				Paths.get(localPath), 
				bucket, 
				passphrase,
				accountID,
				applicationID);) {
			sync.setUploadParallelism(nThreads);
			if(newPassphrase != null) {
				sync.uploadKeyfileWithPassphrase(newPassphrase);
			}
			sync.run(deleteOrphans);
		}
	}
}
