import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ServerResponse {
    public final static String stringConstant = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public static void httpResponse(String fileRequest, Socket client) throws IOException {

        String file_to_load;

        if (fileRequest.equals("/")) {
            file_to_load = "index.html";
        } else {
            file_to_load = fileRequest.substring(1);
        }
        File file = new File(file_to_load);

        if (file_to_load.equals("index.html") && !file.exists()){
            throw new FileNotFoundException("index.html file not found");
        }

        PrintWriter pw = new PrintWriter(client.getOutputStream());
        if (!file.exists()) {
            pw.println("HTTP/1.0" + " 404 Not Found");
            pw.println();
            pw.flush();
        } else {
            pw.println("HTTP/1.0" + " 200 OK");
            pw.println("Content-Length: " + file.length());
            pw.println();
            pw.flush();
            FileInputStream fileScanner = new FileInputStream(file);
            fileScanner.transferTo(client.getOutputStream());
        }
        pw.close();
    }

    public static void webSocketResponse(Socket client, HTTPRequest httpRequest) throws IOException, NoSuchAlgorithmException {

        PrintWriter outs = new PrintWriter(client.getOutputStream());

        String combinedKey = httpRequest.headers.get("Sec-WebSocket-Key") + stringConstant;

        outs.println("HTTP/1.1 101 Switching Protocols");
        outs.println("Upgrade: websocket");
        outs.println("Connection: Upgrade");
        outs.println("Sec-WebSocket-Accept: "+ Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((combinedKey).getBytes(StandardCharsets.UTF_8)))+"\r");
        outs.println("\r");
        outs.flush();
    }
}
