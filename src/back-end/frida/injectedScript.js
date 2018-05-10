'use strict';

// global variables
var getFunctionFromEval = '?GetFunctionFromEval@Compiler@internal@v8@@SA?AV?$MaybeHandle@VJSFunction@internal@v8@@@23@V?$Handle@VString@internal@v8@@@23@V?$Handle@VSharedFunctionInfo@internal@v8@@@23@V?$Handle@VContext@internal@v8@@@23@W4LanguageMode@23@W4ParseRestriction@23@HHHHHV?$Handle@VObject@internal@v8@@@23@VScriptOriginOptions@3@@Z';
var getCurrentIsolate = '?GetCurrent@Isolate@v8@@SAPEAV12@XZ';
var newStringFromUtf8 = '?NewStringFromUtf8@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@V?$Vector@$$CBD@23@W4PretenureFlag@23@@Z';
var func_getFunctionFromEval, func_getCurrentIsolate, func_newStringFromUtf8, fileNameLog;

setLog('injectedScript.js');

function setWrapperFunctions(platform) {
    log('platform ' + platform);
    func_getFunctionFromEval = new NativeFunction(Module.findExportByName(platform, getFunctionFromEval), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int', 'int', 'int', 'int', 'int', 'pointer', 'pointer']);
    func_getCurrentIsolate = new NativeFunction(Module.findExportByName(platform, getCurrentIsolate), 'pointer', []);
    func_newStringFromUtf8 = new NativeFunction(Module.findExportByName(platform, newStringFromUtf8), 'pointer', ['pointer', 'pointer', 'pointer', 'int']);

    functionsMap = {
        eval: {
            target: func_getFunctionFromEval,
            onEnter: onEnterToEval
        }
    };
};

var functions, platform, functionsMap;

function attach() {
    var callbacks = {};

    functions.forEach(function(funcObj) {
        functionsMap[funcObj.func].settings = funcObj;

        if (!funcObj.intercept)
            return;

        if (functionsMap[funcObj.func].onEnter)
            callbacks.onEnter = functionsMap[funcObj.func].onEnter;

        if (functionsMap[funcObj.func].onLeave)
            callbacks.onLeave = functionsMap[funcObj.func].onLeave;

        Interceptor.attach(functionsMap[funcObj.func].target, callbacks);
    });
}

function init() {
    send({type: "settings"});
    var promise = recv("settings", function (resp) {
        functions = resp.payload;
        setWrapperFunctions(resp.platform);
    });
    promise.wait();
    attach();
    send({type: "ready"});
}

// tool from eval
function onEnterToEval(args) {
    var str = '', skip = false;
    var stringPointer = Memory.readPointer(args[1]);

    log('detect calling eval');

    console.log(hexdump(stringPointer, {
        offset: 0,
        length: 512
    }));

    log('pointer' + Memory.readPointer(stringPointer.add(31)));
    /*log(hexdump(Memory.readPointer(stringPointer.add(31)), {
     offset: 0,
     length: 512
     }));*/

    //log(Memory.readUtf16String(Memory.readPointer(Memory.readPointer(stringPointer.add(23)).add(23)).add(23)));

    var stringObj = getStringObject(stringPointer);
    send({
        type: "call",
        func: "eval",
        args: [stringObj.string]
    });

    if (!functionsMap['eval'].settings.replace) {
        log('Получен объект V8::i::String');

        var promise = recv("call", function (resp) {
            log('Получены новые данные с UI skip: ' + resp.skip + ' resp.args[0]: ' + resp.args[0]);
            if (resp.skip)
                skip = true;
            str = ''+resp.args[0];
        });
        promise.wait();

        if (skip)
            return;

        var writableString = Memory.allocUtf8String(str);
        var vector = Memory.alloc(16);
        Memory.writePointer(vector, writableString);
        Memory.writeUInt(vector.add(8), lengthInUtf8Bytes(str));

        var isolate = func_getCurrentIsolate();
        var memoryForNewObject = Memory.alloc(8);
        func_newStringFromUtf8(isolate, memoryForNewObject, vector, 0);

        args[1] = Memory.readPointer(memoryForNewObject);
    }

    function getStringObject(stringPointer) {
        var string = stringPointer.add(23);
        var size = stringPointer.add(19);
        size = Memory.readInt(size);

        var testArrBinary1 = Memory.readByteArray(stringPointer.add(1), 3);
        var view1 = new Uint8Array(testArrBinary1);
        var test1 = [];
        for (var i = 0; i < view1.length; i++)
            test1.push((+view1[i]).toString(16));

        var addedValue = size;
        if (size % 8) {
            addedValue += 8 - size % 8;
        }
        addedValue += 2;

        var testArrBinary2 = Memory.readByteArray(string.add(addedValue), 3);
        var view2 = new Uint8Array(testArrBinary2);
        var test2 = [];
        for (var i = 0; i < view2.length; i++)
            test2.push((+view2[i]).toString(16));

        var result = isArrayEqual(test1, test2);

        if (result) {
            string = Memory.readUtf8String(string, size);
        } else {
            string = Memory.readUtf16String(string, size);
        }

        return {
            string: string,
            size: size
        }
    }

    function isArrayEqual(arr1, arr2) {
        for (var i = 0; i < arr1.length; i++)
            if (arr1[i] !== arr2[i])
                return false;

        return true;
    }

    function lengthInUtf8Bytes(str) {
        // TODO: проверить в браузере на китайских символах
        // https://stackoverflow.com/questions/5515869/string-length-in-bytes-in-javascript
        // Matches only the 10.. bytes that are non-initial characters in a multi-byte sequence.
        var m = encodeURIComponent(str).match(/%[89ABab]/g);
        return str.length + (m ? m.length : 0);
    }
}

init();

function log(msg) {
    console.log(fileNameLog ? '[ ' + fileNameLog + ' ] ' + ': ' + msg : '' + msg);
}

function setLog(fileName) {
    fileNameLog = fileName;
}
