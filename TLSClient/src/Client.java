import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;


public class Client {

    static SecretKeySpec serverEncryptKey;
    static SecretKeySpec clientEncryptKey;
    static SecretKeySpec serverMacKey;
    static SecretKeySpec clientMacKey;
    static IvParameterSpec serverIVKey;
    static IvParameterSpec clientIVKey;

    public static int add_two_integers(int a, int b) {
        return a + b;
    }

    // util to print bytes in hex
    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

    public BigInteger nextRandomBigInteger(BigInteger n) {
        Random rand = new Random();
        BigInteger result = new BigInteger(n.bitLength(), rand);
        while( result.compareTo(n) >= 0 ) {
            result = new BigInteger(n.bitLength(), rand);
        }
        return result;
    }

    public static byte[] hkdfExpand(byte[] input, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
        byte byteValue = 1;
        String tag_byte1 = tag + String.valueOf(byteValue);

        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec inputKey = new SecretKeySpec(input, "SHA256");
        hmac.init(inputKey);
        byte[] okm = hmac.doFinal(tag_byte1.getBytes());
        return Arrays.copyOfRange(okm, 0, 16);

    }

    public static void makeSecretKeys(byte[] clientNonce, BigInteger sharedSecretFromDiffieHellman) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec nonceKey = new SecretKeySpec(clientNonce, "SHA256");

        hmac.init(nonceKey);
        byte[] prk = hmac.doFinal(sharedSecretFromDiffieHellman.toByteArray());
        byte[] serverEncrypt = hkdfExpand(prk, "server encrypt");
        byte[] clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt");
        byte[] serverMac = hkdfExpand(clientEncrypt, "server Mac");
        byte[] clientMac = hkdfExpand(serverMac, "client Mac");
        byte[] serverIV = hkdfExpand(clientMac, "server IV");
        byte[] clientIV = hkdfExpand(serverIV, "client IV");

        serverEncryptKey = new SecretKeySpec(serverEncrypt, "AES");
        clientEncryptKey = new SecretKeySpec(clientEncrypt, "AES");
        serverMacKey = new SecretKeySpec(serverMac, "SHA256");
        clientMacKey = new SecretKeySpec(clientMac, "SHA256");
        serverIVKey = new IvParameterSpec(serverIV);
        clientIVKey = new IvParameterSpec(clientIV);

        //serverIV = hkdfExpand(clientMAC, "server IV")
        //clientIV = hkdfExpand(serverIV, "client IV")
    }

    public static PrivateKey readPrivateKey(File file) throws Exception {

        FileInputStream fileInputStream = new FileInputStream(file);
        DataInputStream dataInputStream = new DataInputStream(fileInputStream);
        byte[] data = new byte[(int)file.length()];
        dataInputStream.readFully(data);
        dataInputStream.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(data);
        return keyFactory.generatePrivate(keySpec);
    }

    public static void main(String[] args) throws Exception {

        Socket s=new Socket("localhost",6666);
        DataOutputStream dataOutputStream =new DataOutputStream(s.getOutputStream());

        /** Client sends nonce **/
        byte[] clientNonce = new byte[32];
        new SecureRandom().nextBytes(clientNonce);
        dataOutputStream.write(clientNonce);
        System.out.println("Client sends nonce: " + convertBytesToHex(clientNonce));
        dataOutputStream.close();
        s.close();

        /** Client receives certificate from Server **/
        s = new Socket("localhost",6666);
        DataInputStream dataInputStream = new DataInputStream(s.getInputStream());
        byte[] serverCertificateBytes = dataInputStream.readAllBytes();
        System.out.println("Client receives CASignedServerCertificate from Server: " + convertBytesToHex(serverCertificateBytes));
        dataInputStream.close();
        s.close();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream = new ByteArrayInputStream(serverCertificateBytes);
        Certificate serverCertificate = certificateFactory.generateCertificate(certificateInputStream);

        // Server DH g, N, A_priv
        String modulus = """
                        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
                        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
                        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
                        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
                        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
                        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
                        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
                        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
                        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
                        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
                        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
                        """;

        String modulusJoined = "";
        String[] split = modulus.split(" ");
        for (int i = 0; i < split.length; i++) {
            modulusJoined += split[i];
        }
        String joined = "";
        String[] split2 = modulusJoined.split("\n");
        for (int i = 0; i < split2.length; i++) {
            joined += split2[i];
        }

        BigInteger N = new BigInteger(joined, 16);  // N

        int g = 2;  // g
        int A_priv = 19;

        /** Client receives serverDHPublic key **/
//        long raised = (long) Math.pow(g, A_priv);
//        BigInteger A_pub = new BigInteger(String.valueOf(raised));
//        A_pub = A_pub.mod(N);
        s=new Socket("localhost",6666);
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] serverDHPublicKeyBytes = dataInputStream.readAllBytes();
        System.out.println("Client receives serverDHPublicKey: " + convertBytesToHex(serverDHPublicKeyBytes));
        dataInputStream.close();
        s.close();

        /** Client received serverDHPublicKeySigned **/
        // load server rsa private key
//        PrivateKey serverRSAPrivateKey = readPrivateKey(new File("serverPrivateKey.der"));
//        // server signs with rsa private key
//        Signature serverSignature = Signature.getInstance("SHA256withRSA"); // create signature object
//        serverSignature.initSign(serverRSAPrivateKey); // add RSA private key to it
//        serverSignature.update(serverDHPublicKeyBytes);  // add message to sign - which is DH public key
        s=new Socket("localhost",6666);
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] serverDHPublicKeySignedBytes = dataInputStream.readAllBytes();
        System.out.println("Client received serverDHPublicKeySigned: " + convertBytesToHex(serverDHPublicKeySignedBytes));
        dataInputStream.close();
        s.close();

        // client verifies signature
        Signature clientSignature = Signature.getInstance("SHA256withRSA"); // create signature object
        InputStream in = new ByteArrayInputStream(serverCertificateBytes); // reads serverCertificateBytes from InputStream
        Certificate serverCert = certificateFactory.generateCertificate(in);
        clientSignature.initVerify(serverCert.getPublicKey()); // add server RSA Public Key from serverCertificate
        clientSignature.update(serverDHPublicKeyBytes); // add serverDHPublicKey sent from server
        if (clientSignature.verify(serverDHPublicKeySignedBytes) == true) { // verify DH public key sent from server
            System.out.println("Client verifies serverDHPublicKey signed by Server: " + true);
        }
        else {
            System.out.println(false);
        }

        /** Client sends CASignedClientCertificate **/
        CertificateFactory certificateFactoryClient = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStreamClient = new FileInputStream("CASignedClientCertificate.pem");
        Certificate clientCertificate = certificateFactoryClient.generateCertificate(certificateInputStreamClient);
        byte[] clientCertificateBytes = clientCertificate.getEncoded();

        s=new Socket("localhost",6666);
        dataOutputStream = new DataOutputStream(s.getOutputStream());
        dataOutputStream.write(clientCertificateBytes);
        System.out.println("Client sends CASignedClientCertificate to Server");
        dataOutputStream.close();
        s.close();

        /** Client sends DH public key **/
        int B_priv = 12;
        long exponent = (long) Math.pow(g, B_priv);
        BigInteger B_pub = BigInteger.valueOf(exponent);
        B_pub = B_pub.mod(N);
        byte[] clientDHPublicKeyBytes = B_pub.toByteArray();

        s=new Socket("localhost",6666);
        dataOutputStream = new DataOutputStream(s.getOutputStream());
        dataOutputStream.write(clientDHPublicKeyBytes);
        System.out.println("Client sends DH public Key to Server");
        dataOutputStream.close();
        s.close();

        /** Client sends Signed DH public key **/
        PrivateKey clientRSAPrivateKey = readPrivateKey(new File("clientPrivateKey.der"));
        clientSignature.initSign(clientRSAPrivateKey);
        clientSignature.update(clientDHPublicKeyBytes);
        byte[] clientDHPublicKeyBytesSigned = clientSignature.sign();

        s=new Socket("localhost",6666);
        dataOutputStream = new DataOutputStream(s.getOutputStream());
        dataOutputStream.write(clientDHPublicKeyBytesSigned);
        System.out.println("Client sends Signed DH public Key to Server");
        dataOutputStream.close();
        s.close();

        /** Client and Server compute shared DH secret key **/
        InputStream ins = new ByteArrayInputStream(serverDHPublicKeyBytes);
        BigInteger Apub = new BigInteger(ins.readAllBytes());
        BigInteger sharedSecretFromDiffieHellman = Apub.pow(B_priv);
        System.out.println("Client and Server compute shared DH secret key: " + sharedSecretFromDiffieHellman);

        /** client and server derive 6 session keys from the shared secret **/
        makeSecretKeys(clientNonce, sharedSecretFromDiffieHellman);

//        String serverMessage = "Hello";
//        Mac hmac = Mac.getInstance("HmacSHA256");
//        hmac.init(serverMacKey);
//        byte[] serverMessageHmacBytes = hmac.doFinal(serverMessage.getBytes());
//
//        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
//        byteArrayOutputStream.write(serverMessage.getBytes());
//        byteArrayOutputStream.write(serverMessageHmacBytes);
//        byte[] messageToEncrypt = byteArrayOutputStream.toByteArray();

//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, serverEncryptKey, serverIVKey);
//        byte[] cipherText = cipher.doFinal(messageToEncrypt);

        s=new Socket("localhost",6666);
        dataInputStream = new DataInputStream(s.getInputStream());
        int messageLength = dataInputStream.readInt();
        dataInputStream.close();
        s.close();

        s=new Socket("localhost",6666);
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] cipherText = dataInputStream.readAllBytes();
        System.out.println("Client receives cipherText from Server: " + convertBytesToHex(cipherText));
        dataInputStream.close();
        s.close();

        int hmacMessageLength = cipherText.length - messageLength;

        /** Client decrypts message from Server **/
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, serverEncryptKey, serverIVKey);
        byte[] plainText = cipherDecrypt.doFinal(cipherText);

        // Client separates plainServerMessage from HmacServerMessage, Hmacs plainServerMessage
        // and checks that is matches HmacServerMessage
        byte[] plainServerMessage = Arrays.copyOfRange(plainText, 0, messageLength);
        byte[] hmacServerMessage = Arrays.copyOfRange(plainText, messageLength, plainText.length);

        Mac checkServerHash = Mac.getInstance("HmacSHA256");
        checkServerHash.init(serverMacKey);
        byte[] clientHmacPlainServerMessage = checkServerHash.doFinal(plainServerMessage);

        if (clientHmacPlainServerMessage.equals(hmacServerMessage)) {
            System.out.println("Client HMAC of message from Server matches Server's HMAC of message: " + true);
        } else {
            System.out.println("Client HMAC of message from Server matches Server's HMAC of message: " + false);
        }

        Cipher cipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, clientEncryptKey, clientIVKey);

        String clientMessage = "Message received";
        byte[] clientCipherText = cipherEncrypt.doFinal(clientMessage.getBytes());

        s=new Socket("localhost",6666);
        dataOutputStream = new DataOutputStream(s.getOutputStream());
        dataOutputStream.write(clientCipherText);
        System.out.println("Client sends cipher text to server confirming message received: " + convertBytesToHex(clientCipherText));
        dataOutputStream.close();
        s.close();
    }
}
