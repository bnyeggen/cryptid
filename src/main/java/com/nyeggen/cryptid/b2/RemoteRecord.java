package com.nyeggen.cryptid.b2;

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
}
