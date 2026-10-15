package com.example.integrityprobe;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.*;

public class SigningTextTest {
    @Test public void preservesWhitespaceChineseSeparatorsAndNewlines() throws Exception {
        String text = "  应用|设备|nonce\r\nsecond line\n ";
        byte[] bytes = SigningText.contentBytes(text);
        assertEquals(text, new String(bytes, StandardCharsets.UTF_8));
        assertArrayEquals(bytes, Base64.decode(SigningText.base64(bytes)));
        assertTrue(SigningText.hex(bytes).startsWith("2020"));
        assertTrue(SigningText.hex(bytes).endsWith("0a20"));
        assertEquals(64, SigningText.sha256(bytes).length());
    }

    @Test public void emptySigningMessageIsValidButEmptyAttestationChallengeIsNot() throws Exception {
        assertEquals(0, SigningText.contentBytes("").length);
        assertThrows(IllegalArgumentException.class, () -> SigningText.challengeBytes(""));
    }

    @Test public void limitsUseBytesNotCharacters() throws Exception {
        assertEquals(126, SigningText.challengeBytes(repeat("中", 42)).length);
        assertThrows(IllegalArgumentException.class, () -> SigningText.challengeBytes(repeat("中", 43)));
        assertEquals(65536, SigningText.contentBytes(repeat("a", 65536)).length);
        assertThrows(IllegalArgumentException.class, () -> SigningText.contentBytes(repeat("a", 65537)));
    }

    @Test public void malformedUnicodeIsNotSilentlyReplaced() {
        assertThrows(CharacterCodingException.class, () -> SigningText.contentBytes("\uD800"));
    }

    @Test public void certificateJsonContainsCompleteDerInReturnedOrder() throws Exception {
        DebugKeyGenerator.Material material = new DebugKeyGenerator().generate("EC", "JSON test", 1);
        String json = SigningText.chainJson(Arrays.asList(material.chain));
        String[] entries = json.replace("[", "").replace("]", "").split(",");
        assertEquals(2, entries.length);
        for (int i = 0; i < entries.length; i++) {
            assertArrayEquals(material.chain[i].getEncoded(), Base64.decode(entries[i].replace("\"", "").trim()));
        }
        String summary = SigningText.describe(material.chain[0], 0);
        assertTrue(summary.contains("未发现标准 Android Attestation OID"));
        assertTrue(summary.contains("Public key SPKI SHA-256"));
        assertEquals(material.chainPem,
                SigningText.pem("CERTIFICATE", material.chain[0].getEncoded()) +
                SigningText.pem("CERTIFICATE", material.chain[1].getEncoded()));
    }

    private String repeat(String value, int count) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < count; i++) out.append(value);
        return out.toString();
    }
}
