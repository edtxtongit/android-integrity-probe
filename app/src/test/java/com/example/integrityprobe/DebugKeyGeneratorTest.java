package com.example.integrityprobe;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;

public class DebugKeyGeneratorTest {
    @Test public void ecPrivatePublicAndChainRoundTrip() throws Exception { assertMaterial("EC"); }
    @Test public void rsaPrivatePublicAndChainRoundTrip() throws Exception { assertMaterial("RSA"); }

    private void assertMaterial(String algorithm) throws Exception {
        DebugKeyGenerator.Material material = new DebugKeyGenerator().generate(algorithm, "测试, CN=not-an-extra-rdn", 30);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyFactory factory = KeyFactory.getInstance(algorithm, provider);
        PrivateKey restored = factory.generatePrivate(new PKCS8EncodedKeySpec(decodePem(material.privateKeyPem)));
        assertArrayEquals(material.keyPair.getPublic().getEncoded(),
                factory.generatePublic(new X509EncodedKeySpec(decodePem(material.publicKeyPem))).getEncoded());
        X509Certificate[] chain = CertificateFactory.getInstance("X.509", provider)
                .generateCertificates(new ByteArrayInputStream(material.chainPem.getBytes(StandardCharsets.US_ASCII)))
                .toArray(new X509Certificate[0]);
        assertEquals(2, chain.length);
        chain[0].checkValidity();
        chain[1].checkValidity();
        chain[0].verify(chain[1].getPublicKey(), provider);
        chain[1].verify(chain[1].getPublicKey(), provider);
        assertEquals(-1, chain[0].getBasicConstraints());
        assertEquals(0, chain[1].getBasicConstraints());
        assertTrue(chain[0].getKeyUsage()[0]);
        assertTrue(chain[1].getKeyUsage()[5]);
        assertEquals(30 * 86400000L + 300000L, chain[0].getNotAfter().getTime() - chain[0].getNotBefore().getTime());
        assertNull(chain[0].getExtensionValue("1.3.6.1.4.1.11129.2.1.17"));
        assertArrayEquals(material.keyPair.getPublic().getEncoded(), chain[0].getPublicKey().getEncoded());
        Signature signature = Signature.getInstance(material.signatureAlgorithm, provider);
        signature.initSign(restored);
        signature.update(material.challenge);
        byte[] bytes = signature.sign();
        signature.initVerify(chain[0]);
        signature.update(material.challenge);
        assertTrue(signature.verify(bytes));
        assertTrue(material.summary.contains("不是 Android Key Attestation"));
        for (String line : material.privateKeyPem.split("\n")) {
            if (!line.startsWith("-----")) assertTrue(line.length() <= 64);
        }
    }

    @Test public void everyRunUsesFreshKeysChallengeAndCertificate() throws Exception {
        DebugKeyGenerator generator = new DebugKeyGenerator();
        DebugKeyGenerator.Material first = generator.generate("EC", "Debug", 1);
        DebugKeyGenerator.Material second = generator.generate("EC", "Debug", 1);
        assertNotEquals(first.privateKeyPem, second.privateKeyPem);
        assertNotEquals(first.publicKeyPem, second.publicKeyPem);
        assertNotEquals(first.chainPem, second.chainPem);
        assertFalse(Arrays.equals(first.challenge, second.challenge));
        assertTrue(first.chain[0].getSerialNumber().signum() > 0);
    }

    @Test public void rejectsInvalidConfiguration() {
        DebugKeyGenerator generator = new DebugKeyGenerator();
        assertThrows(IllegalArgumentException.class, () -> generator.generate("DSA", "Debug", 30));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("EC", " ", 30));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("EC", "a\nb", 30));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("EC", new String(new char[65]).replace('\0', 'a'), 30));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("EC", "Debug", 0));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("EC", "Debug", 3651));
    }

    private byte[] decodePem(String pem) {
        return Base64.decode(pem.replaceAll("-----[^\\n]+-----", "").replaceAll("\\s", ""));
    }
}
