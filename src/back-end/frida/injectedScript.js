'use strict';

// global variables
var getFunctionFromEval = '?GetFunctionFromEval@Compiler@internal@v8@@SA?AV?$MaybeHandle@VJSFunction@internal@v8@@@23@V?$Handle@VString@internal@v8@@@23@V?$Handle@VSharedFunctionInfo@internal@v8@@@23@V?$Handle@VContext@internal@v8@@@23@W4LanguageMode@23@W4ParseRestriction@23@HHHHHV?$Handle@VObject@internal@v8@@@23@VScriptOriginOptions@3@@Z';
var getCurrentIsolate = '?GetCurrent@Isolate@v8@@SAPEAV12@XZ';
var newStringFromUtf8 = '?NewStringFromUtf8@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@V?$Vector@$$CBD@23@W4PretenureFlag@23@@Z';

var func_getFunctionFromEval = new NativeFunction(Module.findExportByName('node.exe', getFunctionFromEval), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int', 'int', 'int', 'int', 'int', 'pointer', 'pointer']);
var func_getCurrentIsolate = new NativeFunction(Module.findExportByName('node.exe', getCurrentIsolate), 'pointer', []);
var func_newStringFromUtf8 = new NativeFunction(Module.findExportByName('node.exe', newStringFromUtf8), 'pointer', ['pointer', 'pointer', 'pointer', 'int']);

var functions, functionsMap = {
    eval: {
        target: func_getFunctionFromEval,
        onEnter: onEnterToEval
    }
};

function attach() {
    var callbacks = {};

    for (var func in functions) {

        if (!functions[func].intercept)
            continue;

        if (functionsMap[func].onEnter)
            callbacks.onEnter = functionsMap[func].onEnter;

        if (functionsMap[func].onLeave)
            callbacks.onLeave = functionsMap[func].onLeave;

        Interceptor.attach(functionsMap[func].target, callbacks);
    }
}

function init() {
    send({type: "settings"});
    var promise = recv("settings", function (resp) {
        functions = resp.payload;
    });
    promise.wait();
    attach();
    send({type: "ready"});
}

// tool from eval
function onEnterToEval(args) {
    var str = '';
    var stringPointer = Memory.readPointer(args[1]);
    var stringObj = getStringObject(stringPointer);
    send({
        type: "call",
        func: "eval",
        args: [stringObj.string]
    });

    if (functions['eval'].replace) {
        var promise = recv("call", function (resp) {
            str = resp.args[0];
        });
        promise.wait();

        var writableString = Memory.allocUtf8String(str);
        var vector = Memory.alloc(16);
        Memory.writePointer(vector, writableString);
        Memory.writeUInt(vector.add(8), lengthInUtf8Bytes(str));

        //console.log('vector: ' + vector);
        //console.log('writable string: ' + writableString);
        //console.log('stringPointer: ' + stringPointer);

        var isolate = func_getCurrentIsolate();
        var rdx = Memory.alloc(8);
        func_newStringFromUtf8(isolate, rdx, vector, 0);

        args[1] = Memory.readPointer(rdx);
    }

    //console.log('string: ' + stringObj.string);
    //console.log('size: ' + stringObj.size);

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

//console.log('--------------------');
//console.log('Attached?');