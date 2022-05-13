import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class wsMessage {


    long payloadLength;
    int headerLength;
    byte headerSecondByteNoMask;


    public static byte getBit(byte input, int position){

        return (byte) ((input >>> position) & 1);
    }

    public static void printByte(byte input, String string){
        int result = input & 0xff;
        System.out.println(string + " " + Integer.toBinaryString(result));
    }

    public static void printShort(short input, String string){
        int result = input & 0xffff;
        System.out.println(string + " " + Integer.toBinaryString(result));
    }

    public static void printInt(int input, String string){
        int result = input & 0xffffffff;
        System.out.println(string + " " + Integer.toBinaryString(result));
    }

    public static boolean finBit(byte headerFirstByte){
        int finBit = getBit(headerFirstByte, 7);

        return finBit == 1;
    }

    public static boolean opcode(byte headerFirstByte){
        byte opcode = (byte) (headerFirstByte & 0xf);

        return opcode == 1;
    }

    public static boolean mask(byte headerSecondByte){
        int mask = getBit(headerSecondByte, 7);

        return mask == 1;
    }

    public static long payloadLen(byte headerSecondByte){
        byte payloadLength = (byte) (headerSecondByte & 0x7f);
        return payloadLength;
    }

    public String readMessage(Socket client) throws IOException {

        DataInputStream message = new DataInputStream(client.getInputStream());

        short first = message.readShort();

        byte[] header = new byte[2];
        header[0] = (byte)(first >>> 8);
        header[1] = (byte) first;

        long payloadLength = payloadLen(header[1]);

        if (payloadLength == 127){
            payloadLength = message.readLong();
        }
        else if (payloadLength == 126){
            payloadLength = message.readShort();
            int unsignedShort = (int) (payloadLength & 0xffff);
            payloadLength = unsignedShort;
        }

        byte[] mask= new byte[4];

        for (int i = 0; i < 4; i++){
            mask[i] = message.readByte();
        }

        String decodedMessage = "";
        for( int i=0; i< payloadLength; i++){
            decodedMessage += (char) (message.readByte() ^ mask[i % 4]);
        }
        return decodedMessage;
    }

    public static void writeMessage(Socket client, String decodedMessage) throws IOException {
        DataOutputStream out = new DataOutputStream(client.getOutputStream());
        String messageToClient = "";

        // First Byte
        out.writeByte(-127);

        String[] decodedMessageSplit;
        decodedMessageSplit = decodedMessage.split(" ");

        if (decodedMessageSplit.length >= 2){
            String username = decodedMessageSplit[0];
            String message = "";

            for (int i = 1; i < decodedMessageSplit.length; i++){
                if (i == decodedMessageSplit.length - 1){
                    message += decodedMessageSplit[i];
                }
                else {
                    message += decodedMessageSplit[i] + " ";
                }
            }

            messageToClient = String.format("{\n" +
                    "\n" +
                    "  \"user\" : \"%s\",\n" +
                    "\n" +
                    "  \"message\" : \"%s\"\n" +
                    "\n" +
                    "}", username, message);
        }

        int payloadLength = messageToClient.length();

        if (payloadLength <= 125){
            byte headerPayloadLength = (byte) (-256 | payloadLength);
            out.writeByte(headerPayloadLength);
        }
        else if (payloadLength > 125){
            byte headerPayloadLength = (byte) (-256 | 126);
            out.writeByte(headerPayloadLength);
            out.writeShort(payloadLength);
        }

        out.writeBytes(messageToClient);
        out.flush();

    }
}
