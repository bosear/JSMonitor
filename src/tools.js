const frida = require("frida");
const fs = require('fs');

var path_chrome = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";

var source = `console.log('from .exe!');
var result = [];
var modules = Process.enumerateModulesSync();
modules.forEach(function(module) {
    console.log(module.name);
    var exports = Module.enumerateExportsSync(module.name);
    exports.forEach(function (func) {
         if (~func.name.search(/timeout/i))
             result.push(func.name + ' -> ' + module.name)
    });
});
var set_Timeout = 'SSL_CTX_get_timeout';
func_set_Timeout = new NativeFunction(Module.findExportByName('node.exe', set_Timeout), 'pointer', ['pointer', 'pointer']);

Interceptor.attach(func_set_Timeout, {
    onEnter: function (args) {
        console.log('setTimeout from node.js: ');
 }});

console.log(result.length);
for (var i = 0; i < result.length; i++)
    console.log(result[i]);
`;
var script;

async function run(pid) {
    var session = await frida.attach(pid);
    script = await session.createScript(source);

    await script.load();
}

var pid = 264;

run(pid).catch(onError);

function onClose(msg) {
    console.log(msg);
}
function onError(error) {
    console.error(error.stack);
}