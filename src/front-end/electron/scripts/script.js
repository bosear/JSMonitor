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
    if (!settings.functions[0].replace) // TODO: for others functions
        showCall(msg);
});

function init() {
    let start = document.getElementById('confirmStart');
    var el = document.querySelector('.tabs');
    M.Tabs.init(el);

    let selectPlatform = document.getElementById('selectPlatform');
    if (settings.platform == 'node') {
        selectPlatform.getElementsByTagName('option')[0].selected = 'selected';
    } else if (settings.platform == 'chrome') {
        selectPlatform.getElementsByTagName('option')[1].selected = 'selected';
    } else {
        selectPlatform.getElementsByTagName('option')[0].selected = 'selected';
    }

    //let pathToApp = document.getElementById('fakePathToApp');
    //pathToApp.value = path.basename(settings.path);

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


    /*document.getElementById('pathToApp').addEventListener('change', () => {
     setTimeout(() => {
     if (checkSettings())
     start.classList.remove('disabled');
     else if (pathToApp.value == "" && !start.classList.contains('disabled')) {
     start.classList.add('disabled');
     }
     }, 0);
     });*/

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

            //let pathToApp = document.getElementById('pathToApp');
            let pid = document.getElementById('last_name');
            let platform = document.getElementById('selectPlatform');

            const newSettings = {
                //path: pathToApp.files.length ? pathToApp.files[0].path : settings.path,
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
    funcName.innerText = msg.func;
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
            fs.writeFileSync(filePath, JSON.stringify(esprima.parseScript(msg.args[0]))); // TODO: to change for multiple arguments
        });
    }
}

function initGlobalSettings() {
    let evalObj, switchEval, checkboxEval, newFunctions;

    // eval
    evalObj = settings.functions[0]; //TODO change structure
    switchEval = document.getElementById('switchEval');
    switchEval.checked = evalObj.intercept;
    checkboxEval = document.getElementById('checkboxEval');
    checkboxEval.disabled = !evalObj.intercept;
    checkboxEval.checked = evalObj.replace;

    var saveSettings = document.getElementById('saveSettings');
    saveSettings.addEventListener('click', ()=> {
        newFunctions = [];

        // eval
        evalObj.intercept = switchEval.checked;
        evalObj.replace = checkboxEval.checked;
        newFunctions.push(evalObj);

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

    switchEval.addEventListener('click', ()=> {
        checkboxEval.disabled = !switchEval.checked;
    });
}

function showCall(msg) {
    let title = document.getElementById('funcName');
    title.innerText = msg.func;
    let text = document.getElementById('funcArg');
    //text.innerHTML = '';
    text.value = beautify(msg.args[0], {indent_size: 2});

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
        ipcRenderer.send('inputMsg',{
            str: text.innerHTML,
            skip: true
        });
    }

    function confirm() {
        ipcRenderer.send('inputMsg',{
            str: text.value,
            skip: false
        });
    }
}