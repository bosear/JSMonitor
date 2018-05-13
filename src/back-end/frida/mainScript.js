const frida = require("frida");
const fs = require('fs');

const settingPath = './src/storage/settings.json';
const settings = JSON.parse(fs.readFileSync(settingPath, 'utf-8'));

let source = fs.readFileSync('./src/back-end/frida/injectedScript.js', 'utf8');
let functions = settings.functions;
let platform = settings.platform;
let script, fileNameLog;

setLog('mainScript.js');

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
    log('close ' + msg);
    process.exit();
}
function onError(error) {
    console.error(error.stack);
    process.send({type: 'error'});
    process.exit();
}

//TODO: queue for multiple-process intercept (for example tabs in chrome)

function onMessageFromFrida(message, data) {
    if (message.type === 'send') {

        switch (message.payload.type) {
            case "settings":
                script.post({
                    type: "settings",
                    payload: functions,
                    platform: platform,
                });
                break;

            case "ready":
                if (process.send != null)
                    process.send(message.payload);
                else
                    log('Tool is ready!');
                break;

            case "call":
                // TODO: queue
                if (process.send != null)
                    process.send(message.payload);
                else
                    log("Tool intercept calling " + message.payload.func + " with arguments: " + message.payload.args);
                break;

            default:
                log(message.payload);
        }
    } else if (message.type === 'error') {
        console.error(message.stack);
    }
}

function onMessageFromElectron(msg) {
    switch (msg.type) {
        case "call":
            log("Отправляю данные на внутреннюю фриду " + msg.args[0]);
            script.post(msg);
            break;

        default:
            log(msg);
    }
}

function log(msg) {
    console.log(fileNameLog ? '[ ' + fileNameLog + ' ] ' + ': ' + msg : '' + msg);
}

function setLog(fileName) {
    fileNameLog = fileName;
}
