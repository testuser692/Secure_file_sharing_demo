from config import create_app, db
from flask_migrate import Migrate
from flask_socketio import emit, join_room, leave_room
from flask_cors import CORS
import os
from src.models.users import Message,ChatMessage
from src.views.chat import encrypt_message
app , socket = create_app()
migrate = Migrate(app, db)


#-------------------------------
encryption_key = os.urandom(32) 

# Join-chat event. Emit online message to other users and join the room
@socket.on("join-chat")
def join_private_chat(data):
    room = data["rid"]
    join_room(room=room)
    socket.emit(
        "joined-chat",
        {"msg": f"{room} is now online."},
        room=room,
        # include_self=False,
    )

# Outgoing event handler
@socket.on("outgoing")
def chatting_event(json, methods=["GET", "POST"]):
    """
    Handles saving messages and sending messages to all clients.
    """
    room_id = json["rid"]
    timestamp = json["timestamp"]
    message = json["message"]
    sender_id = json["sender_id"]
    sender_username = json["sender_username"]
    
    encrypted_message = encrypt_message(encryption_key, message)
    # Get the message entry for the chat room
    message_entry = Message.query.filter_by(room_id=room_id).first()

    # Add the new message to the conversation
    chat_message = ChatMessage(
        content=encrypted_message,
        timestamp=timestamp,
        sender_id=sender_id,
        sender_username=sender_username,
        room_id=room_id,
    )
    # Add the new chat message to the messages relationship of the message
    message_entry.messages.append(chat_message)

    # Updated the database with the new message
    try:
        chat_message.save_to_db()
        message_entry.save_to_db()
    except Exception as e:
        # Handle the database error, e.g., log the error or send an error response to the client.
        print(f"Error saving message to the database: {str(e)}")
        db.session.rollback()

    # Emit the message(s) sent to other users in the room
    socket.emit(
        "message",
        json,
        room=room_id,
        include_self=False,
    )
#-------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    socket.run(app, host='0.0.0.0', port=5000, debug=True)
    # app.run(debug=True,host='0.0.0.0',port=8080)
