package org.i5y.browserid.primary;

import org.bouncycastle.util.encoders.Base64;
import org.mindrot.jbcrypt.BCrypt;

public class GenerateHash {

	public static void main(String[] args) {
		String hashed = BCrypt.hashpw(args[0], BCrypt.gensalt());
		System.out.println("Hashed PW: "
				+ new String(Base64.encode(hashed.getBytes())));
		System.out.println(BCrypt.checkpw(
				args[0],
				new String(Base64.decode(new String(Base64.encode(hashed
						.getBytes()))))));
	}

}
