const electron = require('electron');
const {app, BrowserWindow, Menu, ipcMain} = electron;
const url = require('url');
const path = require('path');
const fs = require('fs');

let frida, window, savedStr, fileNameLog;
const pathToLog = 'log.txt';
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
    }]
}];
setLog('app.js');

app.on('ready', () => {
    window = new BrowserWindow({
        width: 1280,
        height: 725,
        icon: path.join(__dirname, "./images/favicon.png")
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

// TODO: Queue

function onMessageFromWindow(msg) {
    ipcMain.on('start', () => {
        frida = require('child_process').spawn('node', ['./src/back-end/frida/mainScript.js'], {
            stdio: ['inherit', 'inherit', 'inherit', 'ipc']
        });

        frida.on('message', onMessageFromFrida);
        frida.on('close', onExitFromFrida);
    });

    ipcMain.on('inputMsg', (event, msg) => {
        log('app.js я вызываюсь inputMsg, msg.str: ' + msg.str + ' savedStr: ' + savedStr);

        if (savedStr === msg.str)
            msg.skip = true;

        frida.send({
            type: "call",
            args: [msg.str],
            skip: msg.skip
        });
    });
}

function onMessageFromFrida(msg) {
    switch (msg.type) {
        case "call":
            log("Tool intercept calling " + msg.func + " with arguments: " + msg.args);
            logToFile(msg);
            window.webContents.send('log', msg);
            savedStr = msg.args;
            break;

        case "ready":
            log("Tool loaded!");
            window.webContents.send('ready');
            break;

        case "error":
            log("Произошла ошибка");
            window.webContents.send('error');
            break;

        default:
            log(msg);
    }
}

function onExitFromFrida(msg) {
    log('frida is dead...');
    window.webContents.send('dead');
}


function logToFile(msg) {
    let logStr = '[ ' + (new Date()).toString() + ' ]' + '  function: ' + msg.func + ', argument: ' + msg.args + '\n';
    fs.appendFileSync(pathToLog, logStr);
}

function log(msg) {
    console.log(fileNameLog ? '[ ' + fileNameLog + ' ] ' + ': ' + msg : '' + msg);
}

function setLog(fileName) {
    fileNameLog = fileName;
}
