package src;// src.MChatClient.java
// Main Multicast Chat-Message tool
// 

import java.io.IOException;
import java.net.InetAddress;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.util.*;

// Uses ... A swing based simple GUI interface ...

public class MChatClient extends JFrame implements MulticastChatEventListener
{
	// The "multicast chat" window
	protected MulticastChat chat;

	// Txtarea in GUI for chatting/messaging or receiving events in the Chat "room"

	protected JTextArea textArea;

	// Area for message input
	protected JTextField messageField;
	
	// An area ... that will not be used for nothing
	protected JTextField fileField;
	
	// An area that you can use to build a buddy list of participants joining the chat
        // the original code dont do it but ou can add this functionality
	protected DefaultListModel users;

	// Constructor for the chat multicast  
	public MChatClient() {
		super("src.MulticastChat");

		// Construct GUI components 
		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setLineWrap( true);
		textArea.setBorder(BorderFactory.createLoweredBevelBorder());

		JScrollPane textAreaScrollPane = new JScrollPane(textArea, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
						 JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		getContentPane().add(textAreaScrollPane, BorderLayout.CENTER);
		
		users = new DefaultListModel();
		JList usersList = new JList( users);
		JScrollPane usersListScrollPane = new JScrollPane(usersList, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, 
								  JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
				public Dimension getMinimumSize() {
					Dimension d = super.getMinimumSize();
					d.width = 100;
					return d;
				}
				public Dimension getPreferredSize() {
					Dimension d = super.getPreferredSize();
					d.width = 100;
					return d;
				}
			};
		getContentPane().add(usersListScrollPane, BorderLayout.WEST);

		Box box = new Box( BoxLayout.Y_AXIS);
		box.add( Box.createVerticalGlue());
		JPanel messagePanel = new JPanel(new BorderLayout());

		messagePanel.add(new JLabel("Message:"), BorderLayout.WEST);

		messageField = new JTextField();
		messageField.addActionListener( new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			sendMessage();
			}
			});
		messagePanel.add(messageField, BorderLayout.CENTER);

		JButton sendButton = new JButton("  SEND ");
		sendButton.addActionListener( new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			sendMessage();
			}
			});
		messagePanel.add(sendButton, BorderLayout.EAST);
		box.add( messagePanel);

		box.add( Box.createVerticalGlue());
		
		
		JPanel filePanel = new JPanel(new BorderLayout());

		filePanel.add(new JLabel("Not used"), BorderLayout.WEST);
		fileField = new JTextField();
		fileField.addActionListener( new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			downloadFile();
			}
			});
		filePanel.add(fileField, BorderLayout.CENTER);

		JButton downloadButton = new JButton("Not Impl.");
		downloadButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    //downloadFile();
		}
		});
		filePanel.add(downloadButton, BorderLayout.EAST);
		box.add( filePanel);
		
		box.add( Box.createVerticalGlue());
		

		getContentPane().add(box, BorderLayout.SOUTH);

		// detect window closing and terminate multicast chat session
		// detectar o fecho da janela no termino de uma sessao de chat
		// 
		addWindowListener( new WindowAdapter() {
			// when the window is started and opened (first time)
			public void windowOpened(WindowEvent e) {
				messageField.requestFocus();
			} 
			// when the window is closed 
			public void windowClosing(WindowEvent e) {
				onQuit();
				dispose();
			} 
			public void windowClosed(WindowEvent e) {
				System.exit(0);
			} 
			});
	}
	
	/**
	 * Ca be used to add a user (foining the chat) in the buddy list
	 */
	protected void uiAddUser( String userName) {
		users.addElement( userName);
	}
	
	/**
	 * Ca be used to remove a user when she/he leaves the chat
	 * @return true if he user was removed.
	 */
	protected boolean uiRemUser( String userName) {
		return users.removeElement( userName);
	}
	
	/**
	 * Inicialize list of users -- can be used
	 */
	protected void uiInitUsers( Iterator it) {
		users.clear();
		if( it != null)
			while( it.hasNext()) {
				users.addElement( it.next());
			}
	}
	
	/**
	 * Returns an enumeration as list of usernames.
	 */
	protected Enumeration uiListUsers() {
		return users.elements();
	}
	
	// Multicast address used for the chat-messagig room
	public void join(String username, InetAddress group, int port, 
					 int ttl) throws IOException {
		setTitle("CHAT MulticastIP " + username + "@" + group.getHostAddress() 
				 + ":" + port + " [TTL=" + ttl + "]");


		
		// Creates a multicast session (as the chat-messaging room)
		chat = new MulticastChat(username, group, port, ttl, this);
	} 

	protected void log(final String message) {
		java.util.Date date = new java.util.Date();

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
			textArea.append(message + "\n");
			} 
			});
	} 

	/**
	 * SEND the message the user wants to send 
	 */
	protected void sendMessage() {
		String message = messageField.getText();
		messageField.setText("");
		doSendMessage( message);
		messageField.requestFocus();
	}

	/**
	 * SEND to chat-messaging room (where the participants will receive)
	 */
	protected void doSendMessage( String message) {
		try {
			chat.sendMessage(message);
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this, "Error sending the message: "  + ex.getMessage(), "Chat Error", JOptionPane.ERROR_MESSAGE);
		} 
	}
	
	/**
	 * Print an error message if this is the case
	 */
	protected void displayMsg( final String str, final boolean error) {
		final JFrame f = this;

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if( error)
				   JOptionPane.showMessageDialog(f, str, "Chat Error", JOptionPane.ERROR_MESSAGE);
				else
				   JOptionPane.showMessageDialog(f, str, "Chat Information", JOptionPane.INFORMATION_MESSAGE);
			}
		    });
	    }

    /** This is code if we want to add the possibility for a user to
     * to ask to download a file ... BUT WILL NOT BE USED !
     **/

	protected void downloadFile() {
		final String file = fileField.getText();
		fileField.setText("");
		new Thread( new Runnable() {
			public void run() {
				doDownloadFile( file);
			}
			}).start();
		messageField.requestFocus();
	}

	protected void doDownloadFile( String file) {
		// TODO: a completar
		System.err.println( "Request to download the file " + file);
	}

	/**
         * Handler when the suer cose the chat-messging window
	 */
	protected void onQuit() {
		try {
			if (chat != null) {
				chat.terminate();
			} 
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this, "Error closing the chat-messanger: " + ex.getMessage(), "ERROR ! ", JOptionPane.ERROR_MESSAGE); } 
	} 


	// Process a received message
	public void chatMessageReceived(String username, InetAddress address, 
			int port, String message) {
		log("MSG:[" + username+"@"+address.getHostName() + "] said : " + message);
	} 


	// Process when a user joined the chat-messaging
	public void chatParticipantJoined(String username, InetAddress address, 	  int port) {
		log("+++ NEW Participant: " + username + " joined to chat-messaging from " + address.getHostName() + ":" + port);
	} 

	// Processing when a user leaves the chat  // 
	public void chatParticipantLeft(String username, InetAddress address, 
		int port) {
		log("--- USER: " + username + " leaves from " + address.getHostName() + ":" 
			+ port);
	} 

	// Command-line invocation expecting three arguments
	public static void main(String[] args) {
		if ((args.length != 3) && (args.length != 4)) {
			System.err.println("Use: MChatCliente " 
			   + "<nickusername> <grupo IPMulticast> <porto> { <ttl> }");
			System.err.println(" - TTL default = 1");
			System.exit(1);
		} 

		String username = args[0];
		InetAddress group = null;
		int port = -1;
		int ttl = 1;

		try {
			group = InetAddress.getByName(args[1]);
		} catch (Throwable e) {
			System.err.println("Invalid IPv4 Multicat Address " 
				   + e.getMessage());
			System.exit(1);
		} 

		if (!group.isMulticastAddress()) {
			System.err.println("Group: " + args[1] 
				   + " is not a valid IP multicast");
			System.exit(1);
		} 

		try {
			port = Integer.parseInt(args[2]);
		} catch (NumberFormatException e) {
			System.err.println("Porto invalido: " + args[2]);
			System.exit(1);
		} 

		if (args.length >= 4) {
			try {
				ttl = Integer.parseInt(args[3]);
			} catch (NumberFormatException e) {
				System.err.println("TTL invalido: " + args[3]);
				System.exit(1); 
			} 
		} 

		try {
			MChatClient frame = new MChatClient();
			frame.setSize(800, 300);
			frame.setVisible( true);

			frame.join(username, group, port, ttl);
		} catch (Throwable e) {
			System.err.println("Error starting frame: " + e.getClass().getName() + ": " + e.getMessage());
			System.exit(1);
		} 
	} 
}
