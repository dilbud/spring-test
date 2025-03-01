package org.dbx.springtest;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.stream.IntStream;

//@SpringBootApplication
public class EncApplication {

    private static final Logger log = LoggerFactory.getLogger(EncApplication.class);

    public static void main() throws Exception {
//        SpringApplication.run(EncApplication.class, args);
        var aseKey = generateAseKey();
        var aseIv = generateAesIv();
        var plainData = "hello world";
        var encData = aseEncrypt(plainData.getBytes(StandardCharsets.UTF_8), aseKey, aseIv);
        var decData = aseDecrypt(encData, aseKey, aseIv);
        System.out.println(new String(decData, StandardCharsets.UTF_8));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.writeBytes(aseKey.getEncoded());
        bos.writeBytes(aseIv.getIV());

        var aseKeyAseIv = bos.toByteArray();

        var clientPublicKey = loadPublicKey("client/public_key.pem");
        var clientPrivateKey = loadPrivateKey("client/private_key.pem");

        var serverPublicKey = loadPublicKey("server/public_key.pem");
        var serverPrivateKey = loadPrivateKey("server/private_key.pem");
//
        var encAseKeyAseIv = rsaEncrypt(aseKeyAseIv, serverPublicKey);
        var decAaeKeyAseIv = rsaDecrypt(encAseKeyAseIv, serverPrivateKey);

        ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
        bos2.writeBytes(encAseKeyAseIv);
        bos2.writeBytes(encData);

        var messageToSign = bos2.toByteArray();

        var signature = signRsaMsg(messageToSign, clientPrivateKey);
        verifyRsaMsg(messageToSign, signature, clientPublicKey);

        var certificate = getCertificate("client/certificate.pem");
        var serialNumber = serialNumber(certificate);

        ByteArrayOutputStream bos3 = new ByteArrayOutputStream();
        bos3.writeBytes(serialNumber.getBytes()); //ok
        bos3.writeBytes(signature);
        bos3.writeBytes(encAseKeyAseIv);
        bos3.writeBytes(encData);

        var finalMsg = bos3.toByteArray();
        String base64String = Base64.getEncoder().encodeToString(finalMsg);
        var isOk = verify(base64String, signature, clientPublicKey, serverPrivateKey);
        System.out.println(isOk);
    }

    private static boolean verify(String base64Msg, byte[] originSignature, PublicKey clientPublicKey, PrivateKey serverPrivateKey) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        var decodedMsg = Base64.getDecoder().decode(base64Msg);
        ByteArrayInputStream bais = new ByteArrayInputStream(decodedMsg);

        var certificate = getCertificate("client/certificate.pem");
        var serialNumber = serialNumber(certificate).getBytes();

        ByteArrayInputStream bais2 = new ByteArrayInputStream(serialNumber);

        while (bais2.available() > 0) {
            if (bais2.read() != bais.read()) {
                return false;
            }
        }


        var signature = bais.readNBytes(256);

        for(Integer pos: IntStream.range(0, 256).boxed().toList()) {
            if (signature[pos] != originSignature[pos]) {
                return false;
            }
        }

        var encKeyIv = bais.readNBytes(256);
        var encMsg = bais.readNBytes(bais.available());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(encKeyIv);
        baos.write(encMsg);

        var isMsgOk = verifyRsaMsg(baos.toByteArray(), signature, clientPublicKey);

        if (!isMsgOk) {
            return false;
        }

        var keyIv = rsaDecrypt(encKeyIv, serverPrivateKey);

        ByteArrayInputStream bais3 = new ByteArrayInputStream(keyIv);

        var aseKey = bais3.readNBytes(32);
        var aseIv = bais3.readNBytes(16);

        SecretKey secretKey = new SecretKeySpec(aseKey, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(aseIv);
        var msg = aseDecrypt(encMsg, secretKey, ivParameterSpec);
        System.out.println(new String(msg, StandardCharsets.UTF_8));

        return true;

    }


    private static Key generateAseKey() throws NoSuchAlgorithmException {
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Choose 128, 192, or 256 bits
        return keyGen.generateKey();
    }

    private static IvParameterSpec generateAesIv() throws NoSuchAlgorithmException {
        byte[] iv = new byte[16]; // 16 bytes for AES
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static byte[] aseEncrypt(byte[] plainData, Key aseKey, IvParameterSpec ivSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(aseKey.getEncoded(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        return cipher.doFinal(plainData);
    }

    private static byte[] aseDecrypt(byte[] encData, Key aseKey, IvParameterSpec ivSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aseKey, ivSpec);
        return cipher.doFinal(encData);
    }

    private static PublicKey loadPublicKey(String resourcePath) throws Exception {
        try (InputStreamReader inputStreamReader = new InputStreamReader(
                Objects.requireNonNull(EncApplication.class.getClassLoader().getResourceAsStream(resourcePath)), StandardCharsets.UTF_8);
             PemReader pemReader = new PemReader(inputStreamReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] pemContent = pemObject.getContent();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemContent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        }
    }

    private static PrivateKey loadPrivateKey(String resourcePath) throws Exception {
        try (InputStreamReader inputStreamReader = new InputStreamReader(
                Objects.requireNonNull(EncApplication.class.getClassLoader().getResourceAsStream(resourcePath)), StandardCharsets.UTF_8);
             PemReader pemReader = new PemReader(inputStreamReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] pemContent = pemObject.getContent();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        }
    }

    private static byte[] rsaEncrypt(byte[] plainData, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String plainText = "Hello, RSA!";
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(plainData);
    }

    private static byte[] rsaDecrypt(byte[] encData, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encData);
    }

    private static byte[] signRsaMsg(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature rsa = Signature.getInstance("SHA1withRSA");
        rsa.initSign(privateKey);
        rsa.update(data);
        return rsa.sign();
    }

    private static boolean verifyRsaMsg(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature rsa = Signature.getInstance("SHA1withRSA");
        rsa.initVerify(publicKey);
        rsa.update(data);
        return rsa.verify(signature);
    }

    private static X509Certificate getCertificate(String resourcePath) {
        try (InputStreamReader inputStreamReader = new InputStreamReader(
                Objects.requireNonNull(EncApplication.class.getClassLoader().getResourceAsStream(resourcePath)), StandardCharsets.UTF_8);
             PEMParser pemParser = new PEMParser(inputStreamReader)) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            return converter.getCertificate(certificateHolder);
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static String serialNumber(X509Certificate certificate) {
        return certificate.getSerialNumber().toString(16).toUpperCase();
    }
}


