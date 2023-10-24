package src;
/**
    Left the original, unaltered code so you can check it out without any of the security fluff, if you need.
    Do not 100% trust what I did, because I may be stupid.
    If there is anything that we could do another way, obviously feel free to point it out.
    The alterations should be commented to the best of my abilities.
 */

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecureMulticastChat extends Thread {

    // Definition of opcode for JOIN type
    public static final int JOIN = 1;

    // Definition of opcode for LEAVE type
    public static final int LEAVE = 2;

    // Definition of opcode for a regular message type (sent/received)
    public static final int MESSAGE = 3;

    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

    // Timeout for sockets
    public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

    // Multicast socket used to send and receive multicast protocol PDUs
    protected MulticastSocket msocket;

    // Username / User-Nick-Name in Chat
    protected String username;

    // Grupo IP Multicast used
    protected InetAddress group;

    // Listener for Multicast events that must be processed
    protected MulticastChatEventListener listener;

    // Control  - execution thread

    protected boolean isActive;

    //Security related variables
    protected Properties securityProps;
    protected Properties keyProps;
    private String encryptionAlg;
    private String nickHash;
    private String macAlgorithm;
    private String ivString;
    private String signatureAlg;
    private SecretKey confidentialityKey;
    private SecretKey macKey;
    private IvParameterSpec ivSpec;
    private byte[] iv;
    private Cipher cipher;
    private MessageDigest hash;
    private Set<byte[]> nonces;


    // Message Building related variables
    private String header;

    // Multicast Chat-Messaging
    public SecureMulticastChat(String username, InetAddress group, int port,
                         int ttl, MulticastChatEventListener listener) throws Exception {

        this.username = username;
        this.group = group;
        this.listener = listener;
        isActive = true;

        //Loading security setting from the config file
        securityProps = new Properties();
        try{
            FileInputStream input = new FileInputStream("security.config");
            securityProps.load(input);
            input.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Loading public keys from the config file
        keyProps = new Properties();
        try{
            FileInputStream input = new FileInputStream("publickeys.config");
            keyProps.load(input);
            input.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Getting the stuff from the config file
        this.encryptionAlg = securityProps.getProperty("CONFIDENTIALITY");
        this.nickHash = securityProps.getProperty("HASHFORNICKNAMES");
        this.macAlgorithm = securityProps.getProperty("MACALGORITHM");
        this.confidentialityKey = getSecretKey(securityProps.getProperty("CONFIDENTIALITY-KEY"));
        this.macKey = getSecretKey(securityProps.getProperty("MACKEY"));
        this.ivString = securityProps.getProperty("IV");
        this.signatureAlg = securityProps.getProperty("SIGNATURE");

        //We may need to test out this cipher stuff
        this.iv = Utils.hexToByteArray(ivString);
        this.ivSpec  = new IvParameterSpec(iv);
        this.cipher  = Cipher.getInstance(encryptionAlg);
        this.nonces = new HashSet<>();

        // create & configure multicast socket

        msocket = new MulticastSocket(port);
        msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
        msocket.setTimeToLive(ttl);
        msocket.joinGroup(group);



        // Building Header
        this.hash = MessageDigest.getInstance(nickHash);
        hash.update(username.getBytes(StandardCharsets.UTF_8));
        header = (short) 1 + CHAT_MAGIC_NUMBER + Arrays.toString(hash.digest());

        // start receive thread and send multicast join message
        start();
        sendJoin();
    }

    /**
     * Sent notification when user wants to leave the Chat-messaging room
     */

    public void terminate() throws Exception {
        isActive = false;
        sendLeave();
    }

    // to process error message
    protected void error(String message) {
        System.err.println(new java.util.Date() + ": src.MulticastChat: "
                + message);
    }

    // Send a JOIN message
    //
    protected void sendJoin() throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeShort(1);
        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(JOIN);
        dataStream.write(hash.digest(username.getBytes(StandardCharsets.UTF_8)));

        byte[] nonce = Utils.generateNonce();
        byte[] encryptedPayload = encryptMessage(confidentialityKey, nonce.toString());

        dataStream.writeInt(encryptedPayload.length);
        dataStream.write(encryptedPayload);

        PrivateKey keyPriv = getPrivateKey(username);
        Signature s = Signature.getInstance(signatureAlg);
        s.initSign(keyPriv);
        s.update(encryptedPayload);
        byte[] digitalSignature = s.sign();

        dataStream.writeInt(digitalSignature.length);
        dataStream.write(digitalSignature);

        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }

    // Process received JOIN message
    //
    protected void processJoin(DataInputStream istream, InetAddress address,
                               int port) throws Exception {
        istream.readShort();
        long receivedMagicNumber = istream.readLong();

        if (receivedMagicNumber != CHAT_MAGIC_NUMBER) return;

        String name = istream.readUTF();

        byte[] usernameHashed = new byte[512]; // check the hash function
        if (istream.read(usernameHashed, 0, 512) <= 0) return;

        int sizeOfEncryptedMessage = istream.readInt();

        byte[] encryptedMessage = new byte[sizeOfEncryptedMessage];
        if (istream.read(encryptedMessage, 0 , sizeOfEncryptedMessage) <= 0) return;

        byte[] decryptedPayload = decryptMessage(confidentialityKey, encryptedMessage.toString());

        int sigSize = istream.readInt();
        byte[] signature = new byte[sigSize];
        if(istream.read(signature,0,sigSize) <= 0) return;

        //Nonce verification
        if(nonces.contains(decryptedPayload)) return;
        nonces.add(decryptedPayload);

        PublicKey senderKey = getPublicKey(name);
        Signature s = Signature.getInstance(keyProps.getProperty(name + "alg"));
        s.initVerify(senderKey);
        s.update(encryptedMessage);
        boolean verification = s.verify(signature);

        if(!verification) return;

        try {
            listener.chatParticipantJoined(name, address, port);
        } catch (Throwable e) {}
    }

    // Send LEAVE
    protected void sendLeave() throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeShort(1);
        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(LEAVE);
        dataStream.write(hash.digest(username.getBytes(StandardCharsets.UTF_8)));

        byte[] nonce = Utils.generateNonce();
        byte[] encryptedPayload = encryptMessage(confidentialityKey, nonce.toString());

        dataStream.writeInt(encryptedPayload.length);
        dataStream.write(encryptedPayload);

        PrivateKey keyPriv = getPrivateKey(username);
        Signature s = Signature.getInstance(signatureAlg);
        s.initSign(keyPriv);
        s.update(encryptedPayload);
        byte[] digitalSignature = s.sign();

        dataStream.writeInt(digitalSignature.length);
        dataStream.write(digitalSignature);

        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }

    // Processes a multicast chat LEAVE and notifies listeners

    protected void processLeave(DataInputStream istream, InetAddress address,
                                int port) throws Exception {
        istream.readShort();
        long receivedMagicNumber = istream.readLong();

        if (receivedMagicNumber != CHAT_MAGIC_NUMBER) return;

        String sender = istream.readUTF();

        byte[] usernameHashed = new byte[512]; // check the hash function
        if (istream.read(usernameHashed, 0, 512) <= 0) return;

        int sizeOfEncryptedMessage = istream.readInt();

        byte[] encryptedMessage = new byte[sizeOfEncryptedMessage];
        if (istream.read(encryptedMessage, 0 , sizeOfEncryptedMessage) <= 0) return;

        byte[] decryptedPayload = decryptMessage(confidentialityKey, encryptedMessage.toString());

        int sigSize = istream.readInt();
        byte[] signature = new byte[sigSize];
        if(istream.read(signature,0,sigSize) <= 0) return;

        //Nonce verification
        if(nonces.contains(decryptedPayload)) return;
        nonces.add(decryptedPayload);

        PublicKey senderKey = getPublicKey(sender);
        Signature s = Signature.getInstance(keyProps.getProperty(sender + "alg"));
        s.initVerify(senderKey);
        s.update(encryptedMessage);
        boolean verification = s.verify(signature);

        if(!verification) return;
        try {
            listener.chatParticipantLeft(username, address, port);
        } catch (Throwable e) {}
    }

    // Send message to the chat-messaging room
    //
    public void sendMessage(String message) throws IOException, Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);


        // writes the header
        dataStream.writeShort(1);
        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.write(hash.digest(username.getBytes(StandardCharsets.UTF_8)));


        // the encryption of the message

        byte[] nonce = Utils.generateNonce();

        StringBuilder toBeEncryptedPayload = new StringBuilder();

        /*Encrypted payload is only ever supposed to have the nonce and the message itself.
           Plus it makes it easier to verify nonce legitimacy.
         */
        toBeEncryptedPayload
                .append(username)
                .append(MESSAGE)
                .append(nonce)          // NONCE
                .append(message);       // msg data

        byte[] encryptedPayload = encryptMessage(confidentialityKey, toBeEncryptedPayload.toString());

        dataStream.writeInt(encryptedPayload.length);
        dataStream.writeInt(username.length());
        dataStream.writeInt(nonce.length);
        dataStream.write(encryptedPayload); // writes the message

        //Digital Signature
        PrivateKey keyPriv = getPrivateKey(username);
        Signature s = Signature.getInstance(signatureAlg);
        s.initSign(keyPriv);
        s.update(encryptedPayload);
        byte[] digitalSignature = s.sign();

        dataStream.writeInt(digitalSignature.length);
        dataStream.write(digitalSignature);

        // the HMAC proof
        int size1 = header.getBytes(StandardCharsets.UTF_8).length;
        int size2 = encryptedPayload.length;
        byte [] ola = new byte[size1 + size2];

        System.arraycopy(header.getBytes(StandardCharsets.UTF_8), 0, ola, 0,size1);
        System.arraycopy(encryptedPayload, 0, ola, size1, size2);
        byte[] HMAC = hash.digest(ola);

        dataStream.writeInt(HMAC.length);
        dataStream.write(HMAC); // writes the HMAC
        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());
        msocket.send(packet);
    }


    // Process a received message  //
    //
    protected void processMessage(DataInputStream istream,
                                  InetAddress address,
                                  int port) throws Exception {

        istream.readShort();
        long receivedMagicNumber = istream.readLong();

        if (receivedMagicNumber != CHAT_MAGIC_NUMBER) return;

        byte[] usernameHashed = new byte[512]; // check the hash function
        if (istream.read(usernameHashed, 0, 512) <= 0) return;


        int sizeOfEncryptedMessage = istream.readInt();
        int sizeOfUsername = istream.readInt();
        int sizeOfNonce = istream.readInt();

        byte[] encryptedMessage = new byte[sizeOfEncryptedMessage];
        if (istream.read(encryptedMessage, 0 , sizeOfEncryptedMessage) <= 0) return;

        int sigSize = istream.readInt();
        byte[] signature = new byte[sigSize];
        if(istream.read(signature,0,sigSize) <= 0) return;

        int sizeOfHMAC = istream.readInt();
        byte[] HMAC = new byte[sizeOfHMAC];
        if (istream.read(HMAC, 0 , sizeOfHMAC) <= 0) return;

        //Decrypting the payload to check the nonce
        byte[] decryptedPayload = decryptMessage(confidentialityKey, encryptedMessage.toString());
        byte[] senderByte = Arrays.copyOfRange(decryptedPayload, 0, sizeOfUsername);
        byte[] nonce = Arrays.copyOfRange(decryptedPayload, sizeOfUsername + 1, sizeOfNonce);
        byte[] payloadMessage = Arrays.copyOfRange(decryptedPayload, sizeOfNonce, decryptedPayload.length);

        //Nonce verification
        if(nonces.contains(nonce)) return;
        nonces.add(nonce);


        //HMAC verification
        //Please do check for any errors here
        Mac mac = Mac.getInstance(macAlgorithm);
        mac.init(macKey);
        byte[] calculatedHMAC = mac.doFinal(payloadMessage);

        //Signature verification
        String sender = senderByte.toString();
        PublicKey senderKey = getPublicKey(sender);
        Signature s = Signature.getInstance(keyProps.getProperty(sender + "alg"));
        s.initVerify(senderKey);
        s.update(encryptedMessage);
        boolean verification = s.verify(signature);


        if(!MessageDigest.isEqual(calculatedHMAC, HMAC) || !verification) return;


        String username = istream.readUTF();
        String message = istream.readUTF();

        try {
            listener.chatMessageReceived(username, address, port, message);
        } catch (Throwable e) {}
    }

    // Loop:
    // reception and demux received datagrams to process,
    // according with message types and opcodes
    //
    public void run() {
        byte[] buffer = new byte[65508];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        while (isActive) {
            try {

                // Set buffer to receive UDP packet
                packet.setLength(buffer.length);
                msocket.receive(packet);

                // Read received datagram

                DataInputStream istream =
                        new DataInputStream(new ByteArrayInputStream(packet.getData(),
                                packet.getOffset(), packet.getLength()));

                short version = istream.readShort();
                long magic = istream.readLong();

                // Only accepts CHAT-MAGIC-NUMBER of the Chat
                if (magic != CHAT_MAGIC_NUMBER) {
                    continue;

                }

                // Let's analyze the received payload and msg types in rceoved datagram
                int opCode = istream.readInt();
                switch (opCode) {
                    case JOIN:
                        processJoin(istream, packet.getAddress(), packet.getPort());
                        break;
                    case LEAVE:
                        processLeave(istream, packet.getAddress(), packet.getPort());
                        break;
                    case MESSAGE:
                        processMessage(istream, packet.getAddress(), packet.getPort());
                        break;
                    default:
                        error("Error; Unknown type " + opCode + " sent from  "
                                + packet.getAddress() + ":" + packet.getPort());
                }

            } catch (InterruptedIOException e) {

                /**
                 * Handler for Interruptions ...
                 * WILL DO NOTHING ,,,
                 * Used for debugging / control if wanted ... to notify the loop interruption
                 */

            } catch (Throwable e) {
                error("Processing error: " + e.getClass().getName() + ": "
                        + e.getMessage());
            }
        }

        try {
            msocket.close();
        } catch (Throwable e) {}
    }

    /**
     * This is supposed to go get our secret key from the config file
     * @param hexKey the key that's in the file in hexadecimal
     * @return a proper secret key
     */
    private SecretKey getSecretKey(String hexKey){
        byte [] keyBytes = Utils.toByteArray(hexKey);

        //This *should* work to be more flexible with the encryption algorithms, but if anything goes wrong, check this first
        SecretKey key = new SecretKeySpec(keyBytes, encryptionAlg);

        return key;
    }

    /**
     * encrypts the message to be sent
     * @param key the secret key we're using
     * @param message the actual message to be sent
     * @return the encrypted message
     * @throws Exception
     */
    private byte[] encryptMessage(SecretKey key, String message) throws Exception{
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = Utils.toByteArray(message);
        byte[] encryptedMessage = cipher.doFinal(cipherText);
        return encryptedMessage;

    }

    /**
     * decrypts a received message
     * @param key the secret key we're using
     * @param encryptedMessage the message that was received
     * @return the message in plaintext
     * @throws Exception
     */
    private byte[] decryptMessage(SecretKey key, String encryptedMessage) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = Utils.toByteArray(encryptedMessage);
        byte[] plaintextMessage = cipher.doFinal(plainText);
        return plaintextMessage;
    }

    /**
     *
     * @param username username of the sender
     * @return the public key of the user
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private PublicKey getPublicKey(String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyHex = keyProps.getProperty(username + "publickey");
        byte[] keyBytes = Utils.hexToByteArray(keyHex);
        String alg = keyProps.getProperty(username + "alg");
        KeyFactory factory = KeyFactory.getInstance(alg);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = factory.generatePublic(keySpec);
        return publicKey;
    }

    private PrivateKey getPrivateKey(String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyHex = keyProps.getProperty(username + "privatekey"); // Load the private key in hexadecimal format
        byte[] keyBytes = Utils.hexToByteArray(keyHex);
        String alg = keyProps.getProperty(username + "alg"); // Algorithm used for the private key
        KeyFactory factory = KeyFactory.getInstance(alg);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey = factory.generatePrivate(keySpec);
        return privateKey;
    }
}

