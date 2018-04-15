const frida = require("frida");
const fs = require('fs');

const settingPath = './src/storage/settings.json';
const settings = JSON.parse(fs.readFileSync(settingPath, 'utf-8'));

//var path_chrome = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";
//var path_node = "C:\\Program Files\\nodejs\\node.exe";

let path = settings.path;

let source = fs.readFileSync('./src/back-end/frida/injectedScript.js', 'utf8');
let functions = { // TODO: change to settings.prop
    eval: {
        intercept: true,
        replace: false
    }
};
let script;

async function run(pid) {
    let session = await frida.attach(pid);
    script = await session.createScript(source);
    script.events.listen('message', onMessageFromFrida);
    script.events.listen('destroyed', onClose);
    process.on('message', onMessageFromElectron);
    await script.load();
}

let pid = +settings.pid;

run(pid).catch(onError);

function onClose(msg) {
    console.log('close ' + msg);
    process.exit();
}
function onError(error) {
    console.error(error.stack);
    process.exit();
}

//TODO: queue for multiple-process intercept (for example tabs in chrome)

function onMessageFromFrida(message, data) {
    if (message.type === 'send') {

        switch (message.payload.type) {
            case "settings":
                script.post({
                    type: "settings",
                    payload: functions
                });
                break;

            case "ready":
                if (process.send != null)
                    process.send(message.payload);
                else
                    console.log('Tool is ready!');
                break;

            case "call":
                // TODO: queue
                if (process.send != null)
                    process.send(message.payload);
                else
                    console.log("Tool intercept calling " + message.payload.func + " with arguments: " + message.payload.args);
                break;

            default:
                console.log(message.payload);
        }
    } else if (message.type === 'error') {
        console.error(message.stack);
    }
}

function onMessageFromElectron(msg) {
    switch (msg.type) {
        case "call":
            script.post(msg);
            break;

        default:
            console.log(msg);
    }
}
