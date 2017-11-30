package Object;

import javax.crypto.SecretKey;

public class SymKey {
	private String keyName;
	private String keyInfo;
	private SecretKey secKey;

	
	
	
	
	public SymKey(String keyName, String keyInfo, SecretKey secKey) {
		this.keyName = keyName;
		this.keyInfo = keyInfo;
		this.secKey = secKey;
	}

	public String keyName() {
		return keyName;
	}

	public String getKeyName() {
		return keyName;
	}

	public SymKey setKeyName(String keyName) {
		this.keyName = keyName;
		return this;
	}

	public String keyInfo() {
		return keyInfo;
	}

	public String getKeyInfo() {
		return keyInfo;
	}

	public SymKey setKeyInfo(String keyInfo) {
		this.keyInfo = keyInfo;
		return this;
	}

	public SecretKey getSeckey() {
		return secKey;
	}

	public SymKey setSeckey(SecretKey seckey) {
		this.secKey = seckey;
		return this;
	}

}
