package Object;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class AsyKey {
	private String keyName;
	private String keyInfo;
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public AsyKey(String keyName, String keyInfo, PublicKey publicKey, PrivateKey privateKey) {
		this.keyName = keyName;
		this.keyInfo = keyInfo;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public String getKeyName() {
		return keyName;
	}

	public AsyKey setKeyName(String keyName) {
		this.keyName = keyName;
		return this;
	}

	public String getKeyInfo() {
		return keyInfo;
	}

	public AsyKey setKeyInfo(String keyInfo) {
		this.keyInfo = keyInfo;
		return this;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public AsyKey setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
		return this;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public AsyKey setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
		return this;
	}

}
