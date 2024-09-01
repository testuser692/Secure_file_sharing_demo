import os
import json
import base64
from config import db,socket
from datetime import datetime
from src.controller.users_controller import *
from src.models.users import User,Chat,Message
from flask import Blueprint, render_template, request, url_for, redirect, session, flash, jsonify

views = Blueprint('views', __name__, static_folder='static', template_folder='templates')

# Global symmetric key store
SYMMETRIC_KEY_STORE = {}


@views.route("/new-chat", methods=["POST"])
def new_chat():
    """
    Creates a new chat room and adds users to the chat list.

    Returns:
        Response: Flask response object.
    """
    user_id = session.get('user_id')
    new_chat_email = request.form["email"].strip().lower()

    # If user is trying to add themselves, show error message
    if new_chat_email == session.get('email_id'):
        error = "You cannot add yourself to the chat."
        return render_template("chat.html", error=error)

    # Check if the recipient user exists
    recipient_user = User.query.filter_by(email=new_chat_email).first()
    if not recipient_user:
        error = "User not found."
        return render_template("chat.html", error=error)

    # Check if the chat already exists for the current user
    existing_chat = Chat.query.filter_by(user_id=user_id).first()

    # If no chat exists for the current user, create a new one
    if not existing_chat:
        existing_chat = Chat(user_id=user_id, chat_list=[])
        db.session.add(existing_chat)
        db.session.commit()

    # Check if the new chat is already in the chat list
    if recipient_user.id not in [user_chat["user_id"] for user_chat in existing_chat.chat_list]:
        # Generate a room_id (you may use your logic to generate it)
        room_id = str(int(recipient_user.id) + int(user_id))[-4:]

        # Add the new chat to the chat list of the current user
        updated_chat_list = existing_chat.chat_list + [{"user_id": recipient_user.id, "room_id": room_id}]
        existing_chat.chat_list = updated_chat_list

        # Save the changes to the database
        db.session.commit()

        # Create a new chat list for the recipient user if it doesn't exist
        recipient_chat = Chat.query.filter_by(user_id=recipient_user.id).first()
        if not recipient_chat:
            recipient_chat = Chat(user_id=recipient_user.id, chat_list=[])
            db.session.add(recipient_chat)
            db.session.commit()

        # Add the new chat to the chat list of the recipient user
        updated_chat_list = recipient_chat.chat_list + [{"user_id": user_id, "room_id": room_id}]
        recipient_chat.chat_list = updated_chat_list
        db.session.commit()

        # Create a new message entry for the chat room
        new_message = Message(room_id=room_id)
        db.session.add(new_message)
        db.session.commit()

    return redirect(url_for("views.chat"))


@views.route("/chat/", methods=["GET", "POST"])
def chat():
    """
    Renders the chat interface and displays chat messages.

    Returns:
        Response: Flask response object.
    """
    # Get the room id from the URL or set it to None
    room_id = request.args.get("rid", None)

    # Get the chat list for the user
    current_user_id = session.get('user_id')
    current_user_chats = Chat.query.filter_by(user_id=current_user_id).first()
    chat_list = current_user_chats.chat_list if current_user_chats else []

    # Initialize context that contains information about the chat room
    data = []

    for chat in chat_list:
        # Query the database to get the username of users in a user's chat list
        username = User.query.get(chat["user_id"]).username
        is_active = room_id == chat["room_id"]

        try:
            # Get the Message object for the chat room
            message = Message.query.filter_by(room_id=chat["room_id"]).first()

            # Get the last ChatMessage object in the Message's messages relationship
            last_message = message.messages[-1]

            # Decrypt the message content of the last ChatMessage object
            encryption_key = SYMMETRIC_KEY_STORE.get(chat["room_id"])
            if encryption_key:
                last_message_content = decrypt_message(encryption_key, last_message.content)
            else:
                last_message_content = "[Encrypted Message]"
        except (AttributeError, IndexError):
            # Set variable to this when no messages have been sent to the room
            last_message_content = "This place is empty. No messages ..."

        data.append({
            "username": username,
            "room_id": chat["room_id"],
            "is_active": is_active,
            "last_message": last_message_content,
        })

    # Get all the message history in a certain room
    messages = Message.query.filter_by(room_id=room_id).first().messages if room_id else []
    decrypted_messages = []

    for msg in messages:
        encryption_key = SYMMETRIC_KEY_STORE.get(room_id)
        if encryption_key:
            decrypted_content = decrypt_message(encryption_key, msg.content)
        else:
            decrypted_content = "[Encrypted Message]"
        decrypted_messages.append({
            "content": decrypted_content,
            "timestamp": msg.timestamp,
            "sender_username": msg.sender_username,
        })

    return render_template(
        "chat.html",
        user_data=session.get("user_id"),
        username=session.get("username"),
        email=session.get("user_email"),
        room_id=room_id,
        data=data,
        messages=decrypted_messages,
    )

# Custom time filter to be used in the jinja template
@views.app_template_filter("ftime")
def ftime(date):
    dt = datetime.fromtimestamp(int(date))
    time_format = "%I:%M %p"  # Use  %I for 12-hour clock format and %p for AM/PM
    formatted_time = dt.strftime(time_format)

    formatted_time += " | " + dt.strftime("%m/%d")
    return formatted_time


@views.route('/visualize')
def visualize():
    """
    TODO: Utilize pandas and matplotlib to analyze the number of users registered to the app.
    Create a chart of the analysis and convert it to base64 encoding for display in the template.

    Returns:
        Response: Flask response object.
    """
    pass


@views.route('/get_name')
def get_name():
    """
    :return: json object with username
    """
    data = {'name': ''}
    if 'username' in session:
        data = {'name': session['username']}

    return jsonify(data)


@views.route('/get_messages')
def get_messages():
    """
    query the database for messages o in a particular room id
    :return: all messages
    """
    pass


@views.route('/leave')
def leave():
    """
    Emits a 'disconnect' event and redirects to the home page.

    Returns:
        Response: Flask response object.
    """
    socket.emit('disconnect')
    return redirect(url_for('views.home'))