import {Server} from 'socket.io'
import http from 'http'
import express from 'express'

const app=express();
const server =http.createServer(app);

const io = new Server(server,{
     cors:{
          origin:["http://localhost:5173"]
     }
});
export function getReceiverSocketId(userId){
     return userSocketmap[userId];
}

//used to store online user
     const userSocketmap ={};


    io.on("connection",(socket)=>{
     console.log("A user connected",socket.id);
     const userId=socket.handshake.query.userId
     if(userId) userSocketmap[userId]=socket.id
//this is used to send events to all the connected clients
     io.emit("getOnlineUsers",Object.keys(userSocketmap))

     socket.on("disconnect",()=>{
          console.log("A user disconnected",socket.id);
          delete userSocketmap[userId];

          io.emit("getOnlineUsers",Object.keys(userSocketmap))
     });
});


export {io,app,server};
