package src;

import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;

public class RSAKeyExamples {

    public static void main(String [] args) throws Exception {

        // Generate fresh keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pubKey = kp.getPublic();
        PrivateKey privKey = kp.getPrivate();

        // convert
        byte[] rawPubKey = pubKey.getEncoded();
        System.out.println("Public key, raw bytes: " +
                Arrays.toString(rawPubKey));
        System.out.println(rawPubKey.length + " bytes");

        // try hex as well
//        System.out.println("Public key, raw bytes in hex form: ");
//        System.out.println(DatatypeConverter.printHexBinary(rawPubKey));

        // use KeyFactory to show key materials
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubspec = (RSAPublicKeySpec)kf.getKeySpec(pubKey,
                RSAPublicKeySpec.class);

        System.out.println("modulus: " + pubspec.getModulus());
        System.out.println("public key exponent: " + pubspec.getPublicExponent());

        RSAPrivateKeySpec privspec = (RSAPrivateKeySpec)kf.getKeySpec(privKey,
                RSAPrivateKeySpec.class);

        System.out.println("modulus: " + privspec.getModulus());
        System.out.println("private key exponent: " + privspec.getPrivateExponent());

        // use RSA specific methods to do the same
        RSAPublicKey r = (RSAPublicKey)pubKey;
        BigInteger n = r.getModulus();
        System.out.println("n = " + n);
        BigInteger e = r.getPublicExponent();
        System.out.println("e = " + e);

        RSAPrivateKey s = (RSAPrivateKey)privKey;
        n = s.getModulus();
        System.out.println("n = " + n);
        BigInteger d = s.getPrivateExponent();
        System.out.println("d = " + d);

        // In fact, even this would do!
        System.out.println(pubKey);

    }

}

