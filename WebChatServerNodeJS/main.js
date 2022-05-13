var http = require('http');
let fs = require('fs');
let url = require('url');
const { connection } = require('websocket');
const { timeLog, timeStamp } = require('console');

//create a server object:
var server = http.createServer(function (req, res) {
  if (req.url == '/') {
      fs.readFile('./resources/index.html', function(error, fileContents) {
            res.end(fileContents);
      });
  } else {
    var p = req.url;
    let file = p.substr(1);
    fs.readFile(file, function(err, fileContents) {
            res.end(fileContents);
        });
    }

}).listen(8080);

var connections = [];
var room = {'users': [], 'messages': []};
var rooms = {"testRoom1": room};
var thisRoom = "";

var WebSocketServer = require('websocket').server;

wsServer = new WebSocketServer({httpServer: server, autoAcceptConnections: false});

wsServer.on('request', function(request) {

    var connection = request.accept(null, request.origin);
    console.log('Connection accepted.');
    
    connection.on('message', function(message) {
        
        let splitMessage = [];
        let roomName = "";
        splitMessage = message.utf8Data.split(" ");
        if (splitMessage[0] == 'join'){
            roomName = splitMessage[1];
            joinRoom(connection, roomName);
        }
        else {
            console.log('Received Message: ' + message.utf8Data);
        
            for(connection of rooms[thisRoom].users){
                connection.send(message.utf8Data);
            }
            rooms[thisRoom].messages.push(message.utf8Data);
        }
    });
    connection.on('close', function(reasonCode, description) {
        console.log((new Date()) + ' Peer ' + connection.remoteAddress + ' disconnected.');
    });    
});

function joinRoom(connection, roomName){
    if (!(roomName in rooms)){
        rooms[roomName] = {'users': [], 'messages': []};
        rooms[roomName].users.push(connection);
    }
    else {
        rooms[roomName].users.push(connection);
        for (message of rooms[roomName].messages){
            connection.send(message);
        }
    }
    thisRoom = roomName;
}
