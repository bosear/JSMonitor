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
    }]
}, {
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
    window = new BrowserWindow({
        width: 1280,
        height: 725
    });

    window.loadURL(url.format({
        pathname: path.join(__dirname, 'index.html'),
        protocol: 'file:',
        slashes: true
    }));

    const menuApp = Menu.buildFromTemplate(menuTemplate);
    Menu.setApplicationMenu(menuApp);

    window.on('closed', () => {
        window = null;
    });

    onMessageFromWindow();
});

// TODO: load settings
// TODO: Send data
// TODO: Queue

function onMessageFromWindow(msg) {
    ipcMain.on('start', () => {

        //frida = require('child_process').fork('./src/back-end/frida/mainScript.js' );

        frida = require('child_process').spawn('node', ['./src/back-end/frida/mainScript.js'], {
            stdio: ['inherit', 'inherit', 'inherit', 'ipc']
        });
        frida.on('message', onMessageFromFrida);
        frida.on('close', onExitFromFrida);
    });
}

function onMessageFromFrida(msg) {
    switch (msg.type) {
        case "call":
            console.log("Tool intercept calling " + msg.func + " with arguments: " + msg.args);
            window.webContents.send('log', msg);

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

        case "error":
            console.log("Произошла ошибка");
            window.webContents.send('error');
            break;

        default:
            console.log(msg);
    }
}

function onExitFromFrida(msg) {
    console.log('frida is dead...');
    window.webContents.send('dead');
}

