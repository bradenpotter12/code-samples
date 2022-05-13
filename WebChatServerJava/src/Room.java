import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;

public class Room {

    public static HashMap<String, Room> rooms = new HashMap<>();
    public ArrayList<Socket> clients = new ArrayList<>();
    public ArrayList<String> messages = new ArrayList<>();

    public synchronized static Room joinRoom(String joinRoomMessage, Socket client) throws IOException {
        String[] joinRoomMessageSplit;
        joinRoomMessageSplit = joinRoomMessage.split(" ");
        String roomName = joinRoomMessageSplit[1];

        if (!rooms.containsKey(roomName)){
            Room newRoom = new Room();
            rooms.put(roomName, newRoom);
            newRoom.clients.add(client);
            return newRoom;
        }
        else {
            rooms.get(roomName).clients.add(client);

            for (var message: rooms.get(roomName).messages){
                wsMessage.writeMessage(client, message);
            }
            return rooms.get(roomName);
        }
    }

    public synchronized static void sendMessageToRoom(String newMessage, Room room) throws IOException {
        room.messages.add(newMessage);

        for (Socket client: room.clients){
            wsMessage.writeMessage(client, newMessage);
        }
    }


}
