const electron = require('electron');
const {ipcRenderer} = electron;

ipcRenderer.on('ready', (event) => {
    var loader = document.getElementById('loader');
    loader.remove();
});