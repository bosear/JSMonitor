const electron = require('electron');
const {ipcRenderer} = electron;

ipcRenderer.on('ready', (event) => {
    deleteLoader();
    startSession();
});

initTabs();

function initTabs() {
    var el = document.querySelector('.tabs');
    M.Tabs.init(el);
}

function deleteLoader() {
    var loader = document.getElementById('loader');
    loader.remove();
}

function startSession() {
    var elem = document.getElementById('startSession');
    var instance = M.Modal.init(elem);
    instance.open();
    elem = document.querySelector('select');
    instance = M.FormSelect.init(elem);
}