package com.nyeggen.cryptid;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
	//In src/main/resources
	private static final String DEFAULT_CONFIG_LOC = "config.properties";
	public static Config inst = null;
		
	private final String accountID;
	private final String applicationKey;
	private final String defaultSyncPath;
	private final String defaultBucket;
	private final String defaultPassphrase;
	private final int defaultParallelism;
	private final boolean defaultSkipRenames;
	
	public static void load() {
		load(DEFAULT_CONFIG_LOC);
	}

	public static void load(String loc) {
		synchronized(Config.class) {
			if(inst == null) {
				inst = new Config(loc);
			} else {
				throw new IllegalStateException("Config.load called multiple times");
			}
		}
	}
	
	public static Config getInstance() { return inst; }
	public String getAccountID() { return accountID; }
	public String getApplicationKey() { return applicationKey; }
	public String getDefaultSyncPath() { return defaultSyncPath; }
	public String getDefaultBucket() { return defaultBucket; }
	public String getDefaultPassphrase() { return defaultPassphrase; }
	public int getDefaultParallelism() { return defaultParallelism; }
	public boolean getDefaultSkipRenames() { return defaultSkipRenames; }

	private Config(String targ){
		final Properties properties = new Properties();
		final ClassLoader loader = Thread.currentThread().getContextClassLoader();
		
		try(final InputStream is = loader.getResourceAsStream(targ);){
			properties.load(is);
			accountID = properties.getProperty("ACCOUNT_ID");
			applicationKey = properties.getProperty("APPLICATION_KEY");	
			defaultSyncPath = properties.getProperty("DEFAULT_SYNC_PATH", null);
			defaultBucket = properties.getProperty("DEFAULT_BUCKET", null);
			defaultPassphrase = properties.getProperty("DEFAULT_PASSPHRASE", null);
			String parallelism = properties.getProperty("DEFAULT_PARALLELISM", "1");
			defaultParallelism = Integer.parseInt(parallelism);
			defaultSkipRenames = Boolean.valueOf(properties.getProperty("DEFAULT_SKIP_RENAMES", null));
		} catch(IOException ex) {
			throw new RuntimeException(ex);
		}
	}
}
