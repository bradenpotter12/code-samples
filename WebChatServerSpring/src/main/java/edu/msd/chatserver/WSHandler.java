package edu.msd.chatserver;

import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;

public class WSHandler extends TextWebSocketHandler {
    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage message) throws IOException {

        Room r = Room.lookup(session);
        if (r == null){
            //join the room
            Room.joinRoom(message.getPayload().split(" ")[1], session);
        } else {
            r.postMessage(message.getPayload());
        }
    }
}
