package com.example.integrityprobe;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Locale;

/** Exportable development keys. Never represents Android hardware attestation. */
public final class DebugKeyGenerator {
    // Use platform JCA crypto; BC is only needed for directly referenced ASN.1/certificate builders.
    private final SecureRandom random = new SecureRandom();

    public Material generate(String algorithm, String commonName, int validityDays) throws Exception {
        if (!algorithm.equals("EC") && !algorithm.equals("RSA")) {
            throw new IllegalArgumentException("仅支持 EC 或 RSA");
        }
        String name = commonName.trim();
        if (name.isEmpty() || name.length() > 64 || hasControlCharacter(name)) {
            throw new IllegalArgumentException("证书名称需要 1–64 个可见字符");
        }
        if (validityDays < 1 || validityDays > 3650) {
            throw new IllegalArgumentException("有效期需要在 1–3650 天之间");
        }
        KeyPair leafKey = generatePair(algorithm);
        KeyPair rootKey = generatePair(algorithm);
        String signatureAlgorithm = algorithm.equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, name).addRDN(BCStyle.O, "Integrity Probe Debug Only").build();
        X500Name rootName = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Integrity Probe Local Debug CA").build();
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 5 * 60 * 1000L);
        Date notAfter = new Date(now + validityDays * 86400000L);
        X509Certificate root = certificate(rootName, rootName, rootKey, rootKey, true,
                signatureAlgorithm, notBefore, notAfter);
        X509Certificate leaf = certificate(rootName, subject, rootKey, leafKey, false,
                signatureAlgorithm, notBefore, notAfter);
        root.verify(root.getPublicKey());
        leaf.verify(root.getPublicKey());
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(leafKey.getPrivate(), random);
        signer.update(challenge);
        byte[] signature = signer.sign();
        signer.initVerify(leaf.getPublicKey());
        signer.update(challenge);
        if (!signer.verify(signature)) throw new IllegalStateException("密钥与证书不匹配");
        return new Material(leafKey, new X509Certificate[]{leaf, root}, signatureAlgorithm,
                challenge, signature, name, validityDays);
    }

    private static boolean hasControlCharacter(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) return true;
        }
        return false;
    }

    private KeyPair generatePair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("EC")) generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        else generator.initialize(2048, random);
        KeyPair pair = generator.generateKeyPair();
        if (pair.getPrivate().getEncoded() == null || !"PKCS#8".equals(pair.getPrivate().getFormat())) {
            throw new IllegalStateException("软件实验生成器未返回可导出的 PKCS#8 私钥");
        }
        return pair;
    }

    private X509Certificate certificate(X500Name issuer, X500Name subject, KeyPair issuerKey,
            KeyPair subjectKey, boolean ca, String signatureAlgorithm, Date from, Date to) throws Exception {
        BigInteger serial;
        do { serial = new BigInteger(159, random); } while (serial.signum() == 0);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, from, to, subject, subjectKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true,
                ca ? new BasicConstraints(0) : new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca
                ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extensions.createSubjectKeyIdentifier(subjectKey.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extensions.createAuthorityKeyIdentifier(issuerKey.getPublic()));
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder(signatureAlgorithm)
                        .build(issuerKey.getPrivate())));
    }

    public static String pem(String type, byte[] bytes) {
        String body = Base64.toBase64String(bytes);
        StringBuilder out = new StringBuilder("-----BEGIN " + type + "-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            out.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        return out.append("-----END ").append(type).append("-----\n").toString();
    }

    public static final class Material {
        public final KeyPair keyPair;
        public final X509Certificate[] chain;
        public final String signatureAlgorithm;
        public final byte[] challenge;
        public final String privateKeyPem;
        public final String publicKeyPem;
        public final String chainPem;
        public final String summary;
        public final String signingProof;

        private Material(KeyPair keyPair, X509Certificate[] chain, String signatureAlgorithm,
                byte[] challenge, byte[] signature, String name, int days) throws Exception {
            this.keyPair = keyPair;
            this.chain = chain;
            this.signatureAlgorithm = signatureAlgorithm;
            this.challenge = challenge;
            privateKeyPem = pem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
            publicKeyPem = pem("PUBLIC KEY", keyPair.getPublic().getEncoded());
            chainPem = pem("CERTIFICATE", chain[0].getEncoded()) + pem("CERTIFICATE", chain[1].getEncoded());
            StringBuilder info = new StringBuilder("仅供调试 · 软件生成，可导出私钥\n");
            info.append("CN: ").append(name).append("\n算法: ").append(keyPair.getPublic().getAlgorithm())
                    .append("\n有效期: ").append(days).append(" 天\n证书链: 叶证书 → 本地自签 CA（2 张）\n")
                    .append("不是 Android Key Attestation，不受系统或 Google 信任。\n");
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];
                info.append("\nCertificate ").append(i).append("\nSubject: ").append(cert.getSubjectX500Principal())
                        .append("\nIssuer: ").append(cert.getIssuerX500Principal())
                        .append("\nSerial: ").append(cert.getSerialNumber().toString(16))
                        .append("\nNotBefore: ").append(cert.getNotBefore())
                        .append("\nNotAfter: ").append(cert.getNotAfter())
                        .append("\nSHA-256: ");
                byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
                for (int j = 0; j < fingerprint.length; j++) {
                    if (j > 0) info.append(':');
                    info.append(String.format(Locale.US, "%02X", fingerprint[j] & 0xff));
                }
                info.append('\n');
            }
            summary = info.toString();
            signingProof = "软件签名 / 叶证书公钥验签: PASS\n算法: " + signatureAlgorithm
                    + "\n本地随机 challenge (Base64): " + Base64.toBase64String(challenge)
                    + "\n签名 (Base64): " + Base64.toBase64String(signature);
        }
    }
}
