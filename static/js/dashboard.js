const socket = io();

socket.on('connect', function() {
  console.log("채팅 서버에 연결됨");
});

socket.on('message', function(data) {
  const messages = document.getElementById('messages');

  const oldNotice = document.getElementById('chat_notice');
  if (oldNotice) {
    oldNotice.remove();
  }

  const item = document.createElement('li');
  item.textContent = data.username + ": " + data.message;

  messages.appendChild(item);
  messages.scrollTop = messages.scrollHeight;
});

socket.on('chat_error', function(data) {
  const messages = document.getElementById('messages');

  let notice = document.getElementById('chat_notice');

  if (!notice) {
    notice = document.createElement('li');
    notice.id = 'chat_notice';
    messages.appendChild(notice);
  }

  notice.textContent = "[알림] " + data.message;

  messages.scrollTop = messages.scrollHeight;
});

function sendMessage() {
  const input = document.getElementById('chat_input');
  const message = input.value.trim();

  if (!message) {
    return;
  }

  socket.emit('send_message', {
    'message': message
  });

  input.value = "";
}

document.getElementById('chat_send_button').addEventListener('click', sendMessage);

document.getElementById('chat_input').addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
    }
});

window.addEventListener('DOMContentLoaded', function() {
    const messages = document.getElementById('messages');
    messages.scrollTop = messages.scrollHeight;
});