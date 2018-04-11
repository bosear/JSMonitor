const electron = require('electron');
const {app, BrowserWindow, Menu, ipcMain} = electron;
const url = require('url');
const path = require('path');

let frida, window;
const menuTemplate = [{
    label: 'File',
    submenu: [{
        label: "Quit",
        accelerator: "Ctrl + Q",
        click() {
            app.quit();
        }
    }]}, {
        label: "Dev tools",
        submenu: [{
            label: "Open Dev tools",
            accelerator: "F12",
            click(item, focusedWindow) {
                focusedWindow.toggleDevTools();
            }
        }, {
            role: "reload"
        }
        ]
}];

app.on('ready', () => {
    window = new BrowserWindow({});

    window.loadURL(url.format({
        pathname: path.join(__dirname, 'index.html'),
        protocol: 'file:',
        slashes: true
    }));

    //frida = require('child_process').fork('./src/back-end/frida/mainScript.js' );
    const frida = require('child_process').spawn('node', ['./src/back-end/frida/mainScript.js'], {
        stdio: ['inherit', 'inherit', 'inherit', 'ipc'],
    });
    frida.on('message', onMessageFromFrida);
    frida.on('exit', onExitFromFrida);

    const menuApp = Menu.buildFromTemplate(menuTemplate);
    Menu.setApplicationMenu(menuApp);
});

//

// TODO: load settings
// TODO: Send data
// TODO: Queue


function onMessageFromFrida(msg)  {
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
            window.webContents.send('ready');
            break;

        default:
            console.log(msg);
    }
}
function onExitFromFrida (msg) {
    console.log('frida is dead...');
}

