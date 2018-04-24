package com.nyeggen.cryptid.b2;

import com.backblaze.b2.client.structures.B2DeleteFileVersionRequest;

public interface B2Deletable {
	public B2DeleteFileVersionRequest toDelete();
	public String getRemoteName();
}
