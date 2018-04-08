const electron = require('electron');
const {app, BrowserWindow} = require('electron');

const frida = require('child_process').fork('./src/back-end/frida/mainScript.js' );

// TODO: load settings
// TODO: Send data
// TODO: Queue
frida.on('message', (msg) => {
    switch (msg.type) {
        case "call":
            console.log("Tool intercept calling " + msg.func + " with arguments: " + msg.args);
            // stub
            var str = "console.log('Привет, Андрей... Привет, Андрей... Привет, Андрей! Ну где ты был?! Ну обними меня скорей!')";
            frida.send({
                type: "call",
                args: [str]
            });
            break;

        case "ready":
            console.log("Tool loaded!");
            break;

        default:
            console.log(msg);
    }
});

frida.on('exit', (msg) => {
    console.log('frida is dead...');
});
