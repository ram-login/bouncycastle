package com.defensepoint.bouncycastle.resource;

import com.defensepoint.bouncycastle.domain.Keys;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.util.Arrays;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import static org.junit.Assert.assertTrue;

@Controller
@RestController
public class BouncyCastle {

    @GetMapping(path = "/BouncyCastle")
    public ResponseEntity<String> bouncyCastle() {

        testXMSS();

        return ResponseEntity.ok("BouncyCastle");
    }

    @GetMapping(path = "/BouncyCastle/GetKeys")
    public ResponseEntity<Keys> getKeys() {
        return ResponseEntity.ok(getXMSSKeys());
    }

    @PostMapping(path = "/BouncyCastle/GetSignature")
    public ResponseEntity<String> getSignature(@RequestBody Keys keys) {

        XMSSParameters params = new XMSSParameters(4, new SHA512Digest());
        XMSS xmss = new XMSS(params, new SecureRandom());
        xmss.importState(keys.getPrivateKey(), keys.getPublicKey());
        xmss.generateKeys();

        byte[] secret = "Hello".getBytes();
        byte[] signature = xmss.sign(secret);

        return ResponseEntity.ok(java.util.Arrays.toString(signature));
    }

    @PostMapping(path = "/BouncyCastle/GetSignatureByStringKeys")
    public ResponseEntity<String> getSignatureByStringKeys(@RequestParam String publicKey, @RequestParam String privateKey) {

        XMSSParameters params = new XMSSParameters(4, new SHA512Digest());
        XMSS xmss = new XMSS(params, new SecureRandom());
        xmss.importState(Base64.getDecoder().decode(privateKey), Base64.getDecoder().decode(publicKey));
        xmss.generateKeys();

        byte[] secret = "Hello".getBytes();
        byte[] signature = xmss.sign(secret);

        return ResponseEntity.ok(java.util.Arrays.toString(signature));
    }

    @PostMapping(path = "/BouncyCastle/GetSignatureByFile")
    public ResponseEntity<String> getSignatureByFile(@RequestParam("files") MultipartFile[] files, @RequestParam boolean test) {

        byte[] privateKeyBytes = new byte[0], publicKeyBytes = new byte[0];
        boolean isBase64 = true;

        if(test) {
            Keys key = getXMSSKeys();
            privateKeyBytes = key.getPrivateKey();
            publicKeyBytes = key.getPublicKey();
            isBase64 = false;
        } else {
            for(MultipartFile file: files) {
                if(file.getOriginalFilename().contains("private")) {
                    try {
                        privateKeyBytes = file.getBytes();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } else if(file.getOriginalFilename().contains("public")){
                    try {
                        publicKeyBytes = file.getBytes();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } else {
                    throw new RuntimeException("Invalid filename");
                }
            }
        }

        XMSSParameters params = new XMSSParameters(4, new SHA512Digest());
        XMSS xmss = new XMSS(params, new SecureRandom());
        if(isBase64) {
            xmss.importState(Base64.getDecoder().decode(privateKeyBytes), Base64.getDecoder().decode(publicKeyBytes));
        } else {
            xmss.importState(privateKeyBytes, publicKeyBytes);
        }

        xmss.generateKeys();

        byte[] secret = "Hello".getBytes();
        byte[] signature = xmss.sign(secret);

        return ResponseEntity.ok(java.util.Arrays.toString(signature));
    }

    public void testXMSS()
    {
        XMSSParameters params = new XMSSParameters(4, new SHA512Digest());

        XMSS xmss1 = new XMSS(params, new OnlyZeroSecureRandom());
        xmss1.generateKeys();
        byte[] exportedPrivateKey = xmss1.exportPrivateKey();
        byte[] exportedPublicKey = xmss1.exportPublicKey();

        XMSS xmss2 = new XMSS(params, new OnlyZeroSecureRandom());
        xmss2.importState(exportedPrivateKey, exportedPublicKey);
        xmss2.generateKeys();

        byte[] secret = "Hello".getBytes();
        byte[] signature1 = xmss1.sign(secret);
        byte[] signature2 = xmss2.sign(secret);

        assertTrue(Arrays.areEqual(signature1, signature2));

        try
        {
            assertTrue(xmss2.verifySignature(secret, signature1, exportedPublicKey));
        }
        catch (ParseException ex)
        {
            ex.printStackTrace();
        }
    }

    private Keys getXMSSKeys() {
        XMSSParameters params = new XMSSParameters(4, new SHA512Digest());

        XMSS xmss = new XMSS(params, new OnlyZeroSecureRandom());
        xmss.generateKeys();
        byte[] exportedPrivateKey = xmss.exportPrivateKey();
        byte[] exportedPublicKey = xmss.exportPublicKey();

        return new Keys(exportedPrivateKey, exportedPublicKey);
    }

    /**
     * Implementation of OnlyZeroSecureRandom returning zeroes only.
     */
    private static class OnlyZeroSecureRandom extends SecureRandom
    {

        private static final long serialVersionUID = 1L;

        public OnlyZeroSecureRandom()
        {
            super();
        }

        public void nextBytes(byte[] bytes)
        {
            java.util.Arrays.fill(bytes, (byte) 0x00);
        }
    }
}
