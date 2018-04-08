
const frida = require("frida");
const fs = require('fs');

var path_chrome = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";
var path_node = "C:\\Program Files\\nodejs\\node.exe";

var path = path_node;

var source = fs.readFileSync('./src/back-end/frida/injectedScript.js', 'utf8');
var functions = {
    eval: {
        intercept: true,
        replace: true
    }
};
var script;

async function run(pid) {
    var session = await frida.attach(pid);
    script = await session.createScript(source);
    script.events.listen('message', onMessageFromFrida);
    process.on('message', onMessageFromElectron);
    await script.load();
}

var pid = 12960;

run(pid).catch(onError);

function onClose(msg) {
    console.log(msg);
}
function onError(error) {
    console.error(error.stack);
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
                process.send(message.payload);
                break;

            case "call":
                // TODO: queue
                process.send(message.payload);
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
