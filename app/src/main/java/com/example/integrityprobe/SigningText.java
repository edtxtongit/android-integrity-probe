package com.example.integrityprobe;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.List;

/** Byte-exact encodings shared by the signing screen and JVM tests. */
public final class SigningText {
    public static final int MAX_CONTENT_BYTES = 65536;
    public static final int MAX_CHALLENGE_BYTES = 128;
    public static final String ALGORITHM = "SHA256withECDSA";

    private SigningText() { }

    public static byte[] utf8(String text) throws CharacterCodingException {
        // Do not trim, normalize, append a newline, or silently replace malformed Unicode.
        ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(text));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        return bytes;
    }

    public static byte[] contentBytes(String text) throws CharacterCodingException {
        byte[] bytes = utf8(text);
        if (bytes.length > MAX_CONTENT_BYTES) throw new IllegalArgumentException("签名原文最多 65536 个 UTF-8 字节");
        return bytes;
    }

    public static byte[] challengeBytes(String text) throws CharacterCodingException {
        byte[] bytes = utf8(text);
        if (bytes.length == 0 || bytes.length > MAX_CHALLENGE_BYTES) {
            throw new IllegalArgumentException("证明挑战需要 1–128 个 UTF-8 字节");
        }
        return bytes;
    }

    public static String base64(byte[] bytes) { return Base64.toBase64String(bytes); }

    public static String hex(byte[] bytes) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = alphabet[(bytes[i] & 0xff) >>> 4];
            result[i * 2 + 1] = alphabet[bytes[i] & 0x0f];
        }
        return new String(result);
    }

    public static String sha256(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    public static String pem(String type, byte[] bytes) {
        String b64 = base64(bytes);
        StringBuilder out = new StringBuilder("-----BEGIN " + type + "-----\n");
        for (int i = 0; i < b64.length(); i += 64) out.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        return out.append("-----END ").append(type).append("-----\n").toString();
    }

    /** JSON array only: Base64 contains no characters that need JSON string escaping. */
    public static String chainJson(List<X509Certificate> chain) throws Exception {
        StringBuilder out = new StringBuilder("[\n");
        for (int i = 0; i < chain.size(); i++) {
            if (i > 0) out.append(",\n");
            out.append("  \"").append(base64(chain.get(i).getEncoded())).append('"');
        }
        return out.append("\n]").toString();
    }

    public static String describe(X509Certificate cert, int index) throws Exception {
        StringBuilder out = new StringBuilder("Certificate " + index + "\n");
        out.append("Subject: ").append(cert.getSubjectX500Principal())
                .append("\nIssuer: ").append(cert.getIssuerX500Principal())
                .append("\nSerial: ").append(cert.getSerialNumber().toString(16))
                .append("\nNotBefore: ").append(cert.getNotBefore())
                .append("\nNotAfter: ").append(cert.getNotAfter())
                .append("\nSignature algorithm: ").append(cert.getSigAlgName())
                .append("\nPublic key algorithm: ").append(cert.getPublicKey().getAlgorithm())
                .append("\nCertificate SHA-256: ").append(sha256(cert.getEncoded()))
                .append("\nPublic key SPKI SHA-256: ").append(sha256(cert.getPublicKey().getEncoded()))
                .append("\nCritical OIDs: ").append(cert.getCriticalExtensionOIDs())
                .append("\nNon-critical OIDs: ").append(cert.getNonCriticalExtensionOIDs());
        byte[] extension = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
        if (extension == null) {
            out.append("\n未发现标准 Android Attestation OID；厂商扩展未解码，不能据此判断证明有效性。");
        } else {
            try {
                ASN1Sequence record = ASN1Sequence.getInstance(ASN1OctetString.getInstance(extension).getOctets());
                byte[] challenge = ASN1OctetString.getInstance(record.getObjectAt(4)).getOctets();
                out.append("\n证书内 Android attestation challenge (Base64): ").append(base64(challenge));
                out.append("\n证书内 Android attestation challenge (Hex): ").append(hex(challenge));
            } catch (Exception e) {
                out.append("\n标准证明扩展解析失败: ").append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
            }
        }
        return out.append("\n以上仅为本地解析，未验证信任锚或服务端策略。\n").toString();
    }
}
