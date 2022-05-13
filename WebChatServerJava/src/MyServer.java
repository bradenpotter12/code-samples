import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;

public class MyServer {

    public static void main(String[] args) {
        try {

            ServerSocket server = new ServerSocket(8080);

            while (true) {
                try {

                    Socket client = server.accept();
                    HTTPRequest httpRequest = new HTTPRequest();

                    new Thread (() -> {
                        System.out.println("Client connected.");
                        try {
                            httpRequest.getHeaders(client);
                            System.out.println("reading headers to map");
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        if (httpRequest.headers.containsKey("Sec-WebSocket-Key")) {
                            System.out.println("Key Found");
                            httpRequest.isWebSocket = true;
                            try {
                                ServerResponse.webSocketResponse(client, httpRequest);
                                System.out.println("WebSocket Response Sent");
                                wsMessage ws = new wsMessage();

                                String joinRoomMessage = ws.readMessage(client);
                                Room room = Room.joinRoom(joinRoomMessage, client);
                                while (true) {
                                    String decodedMessage = ws.readMessage(client);
                                    Room.sendMessageToRoom(decodedMessage, room);
                                }
                            } catch (IOException | NoSuchAlgorithmException e) {
                                e.printStackTrace();
                            }
                        } else {
                            try {
                                ServerResponse.httpResponse(httpRequest.fileRequest, client);
                                System.out.println("Http Response sent");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }).start();
                } catch (SocketException e) {
                    System.err.println(e.getMessage() + " client connection failed");
                } catch (FileNotFoundException e){
                    System.err.println(e.getMessage() + "file not found");
                    System.exit(1);
                }

            }
        } catch (IOException e) {
            System.err.println(e.getMessage() + " could not create socket on port 8080");
            System.exit(1);
        }
    }
}
