import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class Server {

    static SecretKeySpec serverEncryptKey;
    static SecretKeySpec clientEncryptKey;
    static SecretKeySpec serverMacKey;
    static SecretKeySpec clientMacKey;
    static IvParameterSpec serverIVKey;
    static IvParameterSpec clientIVKey;

    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
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

    public static void main(String[] args) throws Exception {
        ServerSocket ss=new ServerSocket(6666);
        Socket s=ss.accept();//establishes connection

        /** Server receives nonce **/
        DataInputStream dataInputStream =new DataInputStream(s.getInputStream());
        byte[] clientNonce = dataInputStream.readAllBytes();
        System.out.println("Server receives nonce from Client: " + convertBytesToHex(clientNonce));
        dataInputStream.close();
        s.close();

        /** Server sends CASignedServerCertificate **/
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream = new FileInputStream("CASignedServerCertificate.pem");
        Certificate serverCertificate = certificateFactory.generateCertificate(certificateInputStream);
        byte[] serverCertificateBytes = serverCertificate.getEncoded();

        s = ss.accept();
        DataOutputStream outputStream = new DataOutputStream(s.getOutputStream());
        outputStream.write(serverCertificateBytes);
        System.out.println("Server sends CASignedServerCertificate to Client");
        outputStream.close();
        s.close();

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

        /** Server sends DH public key **/
        long raised = (long) Math.pow(g, A_priv);
        BigInteger A_pub = new BigInteger(String.valueOf(raised));
        A_pub = A_pub.mod(N);
        byte[] serverDHPublicKeyBytes = A_pub.toByteArray();

        s = ss.accept();
        outputStream = new DataOutputStream(s.getOutputStream());
        outputStream.write(serverDHPublicKeyBytes);
        System.out.println("Server sends DH public Key to Client");
        outputStream.close();
        s.close();

        /** Server sends Signed DH public key **/
        // load server rsa private key
        PrivateKey serverRSAPrivateKey = readPrivateKey(new File("serverPrivateKey.der"));
        // server signs with rsa private key
        Signature serverSignature = Signature.getInstance("SHA256withRSA"); // create signature object
        serverSignature.initSign(serverRSAPrivateKey); // add RSA private key to it
        serverSignature.update(serverDHPublicKeyBytes);  // add message to sign - which is DH public key
        byte[] serverDHPublicKeySignedBytes = serverSignature.sign();

        s = ss.accept();
        outputStream = new DataOutputStream(s.getOutputStream());
        outputStream.write(serverDHPublicKeySignedBytes);
        System.out.println("Server sends Signed DH public Key to Client");
        outputStream.close();
        s.close();

        /** Server receives CASignedClientCertificate **/
        s = ss.accept();
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] clientCertificateBytes = dataInputStream.readAllBytes();
        System.out.println("Server receives CASignedClientCertificate from Client: " + convertBytesToHex(clientCertificateBytes));
        dataInputStream.close();
        s.close();

        /** Server receives clientDHPublic Key **/
        s = ss.accept();
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] clientDHPublicKeyBytes = dataInputStream.readAllBytes();
        System.out.println("Server receives clientDHPublicKey: " + convertBytesToHex(clientDHPublicKeyBytes));
        dataInputStream.close();
        s.close();

        /** Server receives Signed clientDHPublic Key **/
        s = ss.accept();
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] clientDHPublicKeyBytesSigned = dataInputStream.readAllBytes();
        System.out.println("Server receives clientDHPublicKeySigned: " + convertBytesToHex(clientDHPublicKeyBytesSigned));
        dataInputStream.close();
        s.close();

        // server verifies signature from client signed DH public key
        InputStream in = new ByteArrayInputStream(clientCertificateBytes);
        Certificate clientCert = certificateFactory.generateCertificate(in);
        serverSignature.initVerify(clientCert.getPublicKey());
        serverSignature.update(clientDHPublicKeyBytes);
        if (serverSignature.verify(clientDHPublicKeyBytesSigned) == true) { // verify DH public key sent from server
            System.out.println("Server verifies clientDHPublicKey signed by Client: " + true);
        }
        else {
            System.out.println(false);
        }

        /** Client and Server compute shared DH secret key **/
        InputStream ins = new ByteArrayInputStream(clientDHPublicKeyBytes);
        BigInteger Bpub = new BigInteger(ins.readAllBytes());
        BigInteger sharedSecretFromDiffieHellman = Bpub.pow(A_priv);
        System.out.println("Client and Server compute shared DH secret key: " + sharedSecretFromDiffieHellman);

        /** client and server derive 6 session keys from the shared secret **/
        makeSecretKeys(clientNonce, sharedSecretFromDiffieHellman);

        String serverMessage = "Hello";
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(serverMacKey);
        byte[] serverMessageHmacBytes = hmac.doFinal(serverMessage.getBytes());

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(serverMessage.getBytes());
        byteArrayOutputStream.write(serverMessageHmacBytes);
        byte[] messageToEncrypt = byteArrayOutputStream.toByteArray();

        int hmacMessageLength = serverMessageHmacBytes.length;
        int messageLength = serverMessage.length();

        s = ss.accept();
        outputStream = new DataOutputStream(s.getOutputStream());
        outputStream.writeInt(messageLength);
        outputStream.close();
        s.close();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverEncryptKey, serverIVKey);
        byte[] cipherText = cipher.doFinal(messageToEncrypt);

        s = ss.accept();
        outputStream = new DataOutputStream(s.getOutputStream());
        outputStream.write(cipherText);
        System.out.println("Server sends cipherText to Client: " + convertBytesToHex(cipherText));
        outputStream.close();
        s.close();

        s = ss.accept();
        dataInputStream = new DataInputStream(s.getInputStream());
        byte[] clientCipherText = dataInputStream.readAllBytes();
        System.out.println("Server received cipher text from Client: " + convertBytesToHex(clientCipherText));
        dataInputStream.close();
        s.close();

        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, clientEncryptKey, clientIVKey);
        byte[] clientPlainText = cipherDecrypt.doFinal(clientCipherText);
        System.out.println("Server decrypted message from Client: " + new String(clientPlainText, StandardCharsets.UTF_8));
    }
}
