package src;// src.MulticastChatEventListener.java
// Deals with events caused by the reception of messages in the CHAT-Messaging session

import java.net.InetAddress;

public interface MulticastChatEventListener 
  extends java.util.EventListener {

  // Invoked when a multicast chat message has been received
  void chatMessageReceived(String username, InetAddress host, int port, 
                           String message);

  // Invoked when a multicast participant has joined
  void chatParticipantJoined(String username, InetAddress host, int port);

  // Invoked when a multicast participant has left
  void chatParticipantLeft(String username, InetAddress host, int port);
}
