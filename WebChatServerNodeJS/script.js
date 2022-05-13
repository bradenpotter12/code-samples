window.onload = function() {
    let socket = new WebSocket("ws://" + location.host);
        socket.onopen = function (event) {
            
        console.log('Connection is open ...');
        socket.send("Hello");
        }

        socket.onmessage = function (event) {
            console.log(event.data);
        }
}