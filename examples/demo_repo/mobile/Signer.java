package com.payflow.mobile;

import java.security.*;

public class Signer {
    public static byte[] signPayment(PrivateKey key, byte[] payload) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key);
        s.update(payload);
        return s.sign();
    }

    public static KeyPair deviceKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        return g.generateKeyPair();
    }
}
