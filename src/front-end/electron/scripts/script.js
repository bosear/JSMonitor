const electron = require('electron');
const {ipcRenderer} = electron;

ipcRenderer.on('ready', (event) => {
    var loader = document.getElementById('loader');
    loader.remove();
});

var el = document.querySelector('.tabs');
var instance = M.Tabs.init(el);
console.log(instance);