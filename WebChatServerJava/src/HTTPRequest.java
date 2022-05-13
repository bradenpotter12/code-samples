import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class HTTPRequest {
    public HashMap<String, String> headers = new HashMap<>();
    public boolean isWebSocket = false;
    public String fileRequest;

    public void getHeaders(Socket client) throws IOException {
        InputStream inputToServer = client.getInputStream();
        Scanner scanner = new Scanner(inputToServer, StandardCharsets.UTF_8);


        String firstHeader = scanner.nextLine();
        String[] firstHeaderSplit;
        firstHeaderSplit = firstHeader.split(" ");

        //String request = firstHeaderSplit[0];
        fileRequest = firstHeaderSplit[1];
        //String next = firstHeaderSplit[2];

        while (true) {
            String line = scanner.nextLine();
            if (line.contains(": ")) {
                String[] split = line.split(": ");
                String key = split[0];
                String value = split[1];
                headers.put(key, value);
            } else if (line.isBlank()) {
                break;
            }
        }
//        for (String key : headers.keySet()) {
//            System.out.println(key);
//        }
    }
}
