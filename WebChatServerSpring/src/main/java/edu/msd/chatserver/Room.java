package edu.msd.chatserver;

import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;

public class Room {
    public static HashMap<String, Room> rooms = new HashMap<>();
    public static ArrayList<Room> roomList = new ArrayList<>();
    public ArrayList<WebSocketSession> clients = new ArrayList<>();
    public ArrayList<String> messages = new ArrayList<>();

    public static void joinRoom(String roomName, WebSocketSession session) throws IOException {
        if (!rooms.containsKey(roomName)) {
            Room newRoom = new Room();
            rooms.put(roomName, newRoom);
            newRoom.clients.add(session);
            roomList.add(newRoom);
        } else {
            rooms.get(roomName).clients.add(session);
            roomList.add(rooms.get(roomName));

            for (var message : rooms.get(roomName).messages) {
                TextMessage message1 = new TextMessage(message);
                session.sendMessage(message1);
            }
        }
    }
    // Find room client is in and return it else return null
    public static Room lookup(WebSocketSession session) {
        for (Room room: roomList){
            for (WebSocketSession client: room.clients){
                if (client == session){
                    return room;
                }
            }
        }
        return null;
    }

    public void postMessage(String newMessage) throws IOException {
        messages.add(newMessage);

        for (WebSocketSession client: clients){
            TextMessage message1 = new TextMessage(newMessage);
            client.sendMessage(message1);
        }
    }
}
