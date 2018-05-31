const electron = require('electron');
const {ipcRenderer} = electron;
const {getCurrentWindow, dialog} = electron.remote;
const esprima = require('esprima');
const beautify = require('js-beautify').js;
const prism = require('prismjs');
const fs = require('fs');
const path = require('path');

const startButton = document.getElementById('startSession');
const pathToSettings = "./src/storage/settings.json";

let settingsFile = fs.readFileSync(pathToSettings, 'utf-8');
const settings = JSON.parse(settingsFile);
let number = 0, messages = [];
var isClosedReplaceWindow = false, fileNameLog;

initLog('script.js');

init();

ipcRenderer.on('ready', (event) => {
    deleteLoader();
    M.toast({html: 'Сессия началась'});
});

ipcRenderer.on('dead', (event) => {
    alert('Завершение сессии.');
    getCurrentWindow().reload();
});

ipcRenderer.on('error', (event) => {
    alert('Произошла ошибка.');
    getCurrentWindow().reload();
});

ipcRenderer.on('log', (event, msg) => {
    logCall(msg);
    if (!settings.functions[msg.func].replace)
        showCall(msg);
});

function init() {
    let start = document.getElementById('confirmStart');
    var el = document.querySelector('.tabs');
    M.Tabs.init(el);

    let selectPlatform = document.getElementById('selectPlatform');
    if (settings.platform == 'node.exe') {
        selectPlatform.getElementsByTagName('option')[0].selected = 'selected';
    } else if (settings.platform == 'v8.dll') {
        selectPlatform.getElementsByTagName('option')[1].selected = 'selected';
    } else {
        selectPlatform.getElementsByTagName('option')[0].selected = 'selected';
    }

    let pid = document.getElementById('last_name');
    pid.value = settings.pid;

    if (!checkSettings())
        start.classList.add('disabled');

    pid.addEventListener('input', () => {
        if (checkSettings())
            start.classList.remove('disabled');
        else if (pid.value == "" && !start.classList.contains('disabled')) {
            start.classList.add('disabled');
        }
    });
    
    startButton.addEventListener('click', () => {
        startSession();
    });


    initGlobalSettings();
    startSession();
}

function deleteLoader() {
    var loader = document.getElementById('loader');
    loader.remove();
}

function startSession() {
    let elem = document.getElementById('settingsSession');
    let instance = M.Modal.init(elem, {
        onOpenEnd: () => {
            startButton.style.display = 'block';
        }
    });
    instance.open();

    elem = document.querySelector('select');
    M.FormSelect.init(elem);

    let confirm = document.getElementById('confirmStart');
    confirm.addEventListener('click', submitInitSettings);

    document.body.addEventListener('keydown', function confirmListenerKeyDown(event) {
        if (event.keyCode !== 13)
            return;
        let result = submitInitSettings();

        if (result) {
            instance.close();
            document.body.removeEventListener('keydown', confirmListenerKeyDown);
        }
    });

    function submitInitSettings() {
        if (checkSettings()) {
            startButton.style.display = 'none';
            
            let pid = document.getElementById('last_name');
            let platform = document.getElementById('selectPlatform');

            const newSettings = {
                pid: pid.value,
                platform: platform.value,
                functions: settings.functions
            };

            fs.writeFileSync(pathToSettings, JSON.stringify(newSettings));

            document.getElementById('loader').style.display = 'block';
            ipcRenderer.send('start');

            return true;
        }

        return false;
    }
}

function checkSettings() {
    let pid = document.getElementById('last_name');
    //let pathToApp = document.getElementById('fakePathToApp');
    if (pid.value != "" /*&& pathToApp.value != ""*/)
        return true;
    return false;
}

function logCall(msg) {
    let firstRow, firstCol, secondRow, funcName,
        secondCol, table, pre, code, saveButton;

    ++number;

    pre = document.createElement('pre');
    code = document.createElement('code');
    code.innerHTML = beautify(msg.args[0], {indent_size: 2}); //TODO: изменить на несколько аргументов
    code.setAttribute('class', 'language-js');
    prism.highlightElement(code);
    pre.appendChild(code);

    table = document.getElementById('logTable');

    if (!table) {
        var card = document.createElement('div');
        card.setAttribute('class', 'card log');

        table = document.createElement('table');
        table.setAttribute('class', 'table table-bordered');
        table.setAttribute('id', 'logTable');

        firstRow = document.createElement('tr');

        firstCol = document.createElement('th');
        firstCol.innerText = '#';

        secondCol = document.createElement('th');
        secondCol.innerText = 'Название функции';

        firstRow.appendChild(firstCol);
        firstRow.appendChild(secondCol);

        table.appendChild(firstRow);
        card.appendChild(table);

        var element = document.getElementById('journal');
        element.innerHTML = '';
        element.appendChild(card);
    }

    firstRow = document.createElement('tr');

    firstCol = document.createElement('th');
    firstCol.innerText = number;
    firstCol.setAttribute('rowspan', '2');

    secondCol = document.createElement('th');
    funcName = document.createElement('span');
    funcName.classList.add('func-name');
    funcName.innerText = settings.functions[msg.func].func;
    secondCol.appendChild(funcName);

    saveButton = document.createElement('a');
    saveButton.setAttribute('class', 'btn waves-effect waves-light save-ast');
    saveButton.innerText = "Сохранить AST-дерево";
    saveButton.dataset.idx = messages.length;
    secondCol.appendChild(saveButton);
    saveButton.addEventListener('click', saveAst);
    messages.push(msg);

    firstRow.appendChild(firstCol);
    firstRow.appendChild(secondCol);

    secondRow = document.createElement('tr');
    secondCol = document.createElement('td');
    secondCol.appendChild(pre);

    secondRow.appendChild(secondCol);

    table.appendChild(firstRow);
    table.appendChild(secondRow);

    function saveAst() {
        dialog.showSaveDialog({
            filters: [{
                name: 'JSON type',
                extensions: ['json']
            }]
        }, (filePath) => {
            fs.writeFileSync(filePath, JSON.stringify(esprima.parseScript(msg.args[0])));
        });
    }
}

function initGlobalSettings() { // TODO: change for multiple functions
    let evalObj, switchEval, checkboxEval, newFunctions, newFunctionBody, functionName;
    var settingsBody = document.querySelector('.card.settings > ul');

    for (let func in settings.functions) {
        var funcItem = document.createElement('li');
        funcItem.dataset.func = func;
        funcItem.dataset.fullFunc = settings.functions[func].func;
        var html = `<div class="switch"><label><input type="checkbox" id="switch-`+func+`" `+(settings.functions[func].intercept?`checked`:``)+`><span class="lever"></span> Детектировать `+settings.functions[func].func+` </label></div>
        <ul><li><form action="#"><p><label><input type="checkbox" id="checkbox-`+func+`" `+(settings.functions[func].intercept?``:`disabled`)+` `+(settings.functions[func].replace?`checked`:``)+`/><span>Использовать "тихий режим"</span></label></p></form></li></ul>`;
        funcItem.innerHTML += html;
        settingsBody.appendChild(funcItem);

        var switchEl = document.getElementById('switch-'+func);
        var checkboxEl = document.getElementById('checkbox-'+func);

        (function (switchEl, checkboxEl) {
            switchEl.addEventListener('click', ()=> {
                checkboxEl.disabled = !switchEl.checked;
            });
        })(switchEl, checkboxEl);
    }

    var saveSettings = document.getElementById('saveSettings');
    saveSettings.addEventListener('click', ()=> {
        newFunctions = {};

        var functionsSettings = document.querySelectorAll('.card.settings > ul > li');

        for (var i = 0; i < functionsSettings.length; i++) {
            newFunctionBody = {};
            functionName = functionsSettings[i].dataset.func;
            newFunctionBody.func = functionsSettings[i].dataset.fullFunc;
            newFunctionBody.intercept = functionsSettings[i].querySelector('#switch-'+functionName).checked;
            newFunctionBody.replace = functionsSettings[i].querySelector('#checkbox-'+functionName).checked;

            newFunctions[functionName] = newFunctionBody;
        }


        let newSettings = {
            pid: settings.pid,
            platform: settings.platform,
            functions: newFunctions
        };

        fs.writeFile(pathToSettings, JSON.stringify(newSettings), (error)=> {
            if (error)
                M.toast({html: 'Произошла ошибка'});
            else
                M.toast({html: 'Сохранено'});
        });
    });

}

function showCall(msg) {
    let title = document.getElementById('funcName');
    title.innerText = 'Вызов ' +  msg.func;
    let text = document.getElementById('funcArg');
    //text.innerHTML = '';
    text.value = beautify(msg.args[0], {indent_size: 2});
    isClosedReplaceWindow = false;

    let elem = document.getElementById('showCall');
    let instance = M.Modal.init(elem, {
        onCloseStart: function () {
            cancel();
        }
    });
    instance.open();

    document.getElementById('saveArg').addEventListener('click', confirm);
    document.getElementById('skipArg').addEventListener('click', cancel);

    function cancel() {
        if (isClosedReplaceWindow)
            return;

        isClosedReplaceWindow = true;
        ipcRenderer.send('inputMsg',{
            str: text.innerHTML,
            skip: true
        });
    }

    function confirm() {
        if (isClosedReplaceWindow)
            return;
        
        isClosedReplaceWindow = true;
        ipcRenderer.send('inputMsg',{
            str: text.value,
            skip: false
        });
    }
}

function log(msg) {
    console.log(fileNameLog ? '[ ' + fileNameLog + ' ] ' + ': ' + msg : '' + msg);
}

function initLog(fileName) {
    fileNameLog = fileName;
}

