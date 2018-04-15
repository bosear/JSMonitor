const electron = require('electron');
const {ipcRenderer} = electron;
const fs = require('fs');
const path = require('path');

const startButton = document.getElementById('startSession');
const pathToSettings = "./src/storage/settings.json";

let settingsFile = fs.readFileSync(pathToSettings, 'utf-8');
const settings = JSON.parse(settingsFile);

init();

ipcRenderer.on('ready', (event) => {
    deleteLoader();
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
    instance = M.FormSelect.init(elem);

    let confirm = document.getElementById('confirmStart');
    confirm.addEventListener('click', ()=> {
        if (checkSettings()) {
            startButton.style.display = 'none';

            //let pathToApp = document.getElementById('pathToApp');
            let pid = document.getElementById('last_name');
            let platform = document.getElementById('selectPlatform');

            const newSettings = {
                //path: pathToApp.files.length ? pathToApp.files[0].path : settings.path,
                pid: pid.value,
                platform: platform.value
            };

            fs.writeFileSync(pathToSettings, JSON.stringify(newSettings));

            document.getElementById('loader').style.display = 'block';
            ipcRenderer.send('start');
        }
    });
}

function checkSettings() {
    let pid = document.getElementById('last_name');
    //let pathToApp = document.getElementById('fakePathToApp');
    if (pid.value != "" /*&& pathToApp.value != ""*/)
        return true;
    return false;
}