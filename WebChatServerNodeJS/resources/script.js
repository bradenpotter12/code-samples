var username;
var existingRoomName;

window.onload = function() {
    let button = document.getElementById("join-room-button");

    button.addEventListener('click', function() {
        username = document.getElementById("username-field").value;
        existingRoomName = document.getElementById("existing-room-field").value;
        
        // Load chatRoom.html
        xhr = new XMLHttpRequest();
        xhr.open("GET", "resources/chatRoom.html");
        xhr.send();
        
        xhr.onload = function() {
            document.body.innerHTML = xhr.response;
            let h1 = document.getElementById("h1");
            let h1Text = document.createTextNode(existingRoomName + " room");
            h1.appendChild(h1Text);
            document.body.appendChild(h1);
        }

        let socket = new WebSocket("ws://" + location.host);
        socket.onopen = function (event) {
            
        console.log('Connection is open ...');
        socket.send("join " + existingRoomName);
    }

    function myFunction(username, message) {
        let h4 = document.createElement("h4");
        let h4Text = document.createTextNode(username + ": " + message);
        h4.appendChild(h4Text);
        div = document.getElementById("message-window");
        div.appendChild(h4);
        document.body.appendChild(div);
        br = document.createElement("br");
        document.body.appendChild(br);
        div2 = document.getElementById("send-message");
        document.body.appendChild(div2);
    }    

    socket.onmessage = function(event) {
        console.log(event.data);
        var message = event.data;
        let splitMessage = [];
        splitMessage = message.split(" ");
        let username = splitMessage[0];
        let clientMessage = "";

        for (let i = 1; i < splitMessage.length; i++){
            if (i == splitMessage.length - 1){
                clientMessage += splitMessage[i];
            }
            else {
                clientMessage += splitMessage[i] + " ";
            }
        }

        console.log(username + " " + clientMessage);
        myFunction(username, clientMessage);
    }

    window.addEventListener('keyup', function (e) {
        if (e.keyCode === 13) {
            newMessage = document.getElementById("send-message").value;
            socket.send(username + " " + newMessage);
            document.getElementById("send-message").value = "";
            var objDiv = document.getElementById("message-window");
            objDiv.scrollIntoView(true);
        }
    }, false);
    });

    
}




