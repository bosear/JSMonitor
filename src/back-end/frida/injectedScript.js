'use strict';

// global variables
var getFunctionFromEval = '?GetFunctionFromEval@Compiler@internal@v8@@SA?AV?$MaybeHandle@VJSFunction@internal@v8@@@23@V?$Handle@VString@internal@v8@@@23@V?$Handle@VSharedFunctionInfo@internal@v8@@@23@V?$Handle@VContext@internal@v8@@@23@W4LanguageMode@23@W4ParseRestriction@23@HHHHHV?$Handle@VObject@internal@v8@@@23@VScriptOriginOptions@3@@Z';
var getCurrentIsolate = '?GetCurrent@Isolate@v8@@SAPEAV12@XZ';
var newStringFromUtf8 = '?NewStringFromUtf8@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@V?$Vector@$$CBD@23@W4PretenureFlag@23@@Z';
var func_getFunctionFromEval, func_getCurrentIsolate, func_newStringFromUtf8, fileNameLog;

var stringTag = {
    kStringRepresentationMask: 0x07,
    kSeqStringTag: 0x0,
    kConsStringTag: 0x1,
    kExternalStringTag: 0x2,
    kSlicedStringTag: 0x3,
    kThinStringTag: 0x5,
    kStringEncodingMask: 0x8,
    kTwoByteStringTag: 0x0,
    kOneByteStringTag: 0x8,
    kIsNotStringMask: 0xff80,
    kStringTag: 0x0,
    kIsNotInternalizedMask: 0x40,
    kNotInternalizedTag: 0x40,
    kInstanceTypeOffset: 11
};

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
        },
        newFunction: {
            target: func_getFunctionFromEval,
            onEnter: onEnterToNewFunction
        }
    };
}

var functions, platform, functionsMap;

function attach() {
    var callbacks = {};

    Object.keys(functions).forEach(function(func) {
        console.log(functionsMap[func].settings);
        console.log(func + '');

        functionsMap[func].settings = funcObj;

        if (!functions[func].intercept)
            return;

        if (functionsMap[func].onEnter)
            callbacks.onEnter = functionsMap[func].onEnter;

        if (functionsMap[func].onLeave)
            callbacks.onLeave = functionsMap[func].onLeave;

        Interceptor.attach(functionsMap[func].target, callbacks);
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

function getStringFromV8(stringPointer) {
    var string, size, type = '0x' + getStringType(stringPointer);

    if (isSliced(type)) {
        console.log('lol');
        console.log(hexdump(Memory.readPointer(stringPointer.sub(1)), {
            offset: 0,
            length: 512
        }));
    }

    if (isSequential(type)) {
        string = stringPointer.add(23);
        size = Memory.readInt(stringPointer.add(19));

        if (isSequentialOneByte(type))
            return Memory.readUtf8String(string, size);
        return Memory.readUtf16String(string, size);

    } else if (isCons(type)) {
        return getStringFromV8(Memory.readPointer(stringPointer.add(23))) +
            getStringFromV8(Memory.readPointer(stringPointer.add(31)));
    }
}

function fullRepresentationTag(type) {
    return (type & (stringTag.kStringRepresentationMask | stringTag.kStringEncodingMask));
}

function isSequentialOneByte(type) {
    return fullRepresentationTag(type) == (stringTag.kSeqStringTag | stringTag.kOneByteStringTag);
}

function isSequentialTwoByte(type) {
    return fullRepresentationTag(type) == (stringTag.kSeqStringTag | stringTag.kTwoByteStringTag);
}

function isSequential(type) {
    return (type & stringTag.kStringRepresentationMask) == stringTag.kSeqStringTag;
}

function isCons(type) {
    return (type & stringTag.kStringRepresentationMask) == stringTag.kConsStringTag;
}

function isThin(type) {
    return (type & stringTag.kStringRepresentationMask) == stringTag.kThinStringTag;
}

function isSliced(type) {
    return (type & stringTag.kStringRepresentationMask) == stringTag.kSlicedStringTag;
}

function getStringType(stringPointer) {
    var typeAddr = Memory.readPointer(stringPointer.sub(1)).add(stringTag.kInstanceTypeOffset);
    return getSimpleArrayFromArrayBuffer(Memory.readByteArray(typeAddr, 1))[0];
}

function getSimpleArrayFromArrayBuffer(arrayBuffer) {
    var view1 = new Uint8Array(arrayBuffer);
    var arr = [];
    for (var i = 0; i < view1.length; i++)
        arr.push((+view1[i]).toString(16));

    return arr;
}

function onEnterToNewFunction(args) {
    onEnterToEval(args, true);
}
// tool for eval
function onEnterToEval(args, isNewFunction) {
    var str = '', skip = false;
    var stringPointer = Memory.readPointer(args[1]);

    log('detect calling eval');

    /*console.log(hexdump(stringPointer, {
        offset: 0,
        length: 512
    }));

    console.log(hexdump(Memory.readPointer(stringPointer.sub(1)), {
        offset: 0,
        length: 512
    }));*/

    /*stringPointer = Memory.readPointer(stringPointer.add(23));

    console.log(hexdump(stringPointer, {
        offset: 0,
        length: 512
    }));

    console.log(hexdump(Memory.readPointer(stringPointer.sub(1)), {
        offset: 0,
        length: 512
    }));

    stringPointer = Memory.readPointer(stringPointer.add(23));

    console.log(hexdump(stringPointer, {
        offset: 0,
        length: 512
    }));*/

    log('pointer ' + Memory.readPointer(stringPointer.add(31)));
    /*log(hexdump(Memory.readPointer(stringPointer.add(31)), {
     offset: 0,
     length: 512
     }));*/

    //log(Memory.readUtf16String(Memory.readPointer(Memory.readPointer(stringPointer.add(23)).add(23)).add(23)));

    var stringObj = getStringFromV8(stringPointer);
    console.log("string: " + stringObj);

    send({
        type: "call",
        func: isNewFunction ? "new Function" : "eval",
        args: [stringObj]
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
