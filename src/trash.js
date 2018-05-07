// this file for reference materials

/*
 Interceptor.attach(func_nStr13, {
 onEnter: function (args) {
 console.log('str13: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr12, {
 onEnter: function (args) {
 console.log('str12: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr11, {
 onEnter: function (args) {
 console.log('str11: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr10, {
 onEnter: function (args) {
 console.log('str10: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr9, {
 onEnter: function (args) {
 console.log('str9: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr8, {
 onEnter: function (args) {
 console.log('str8: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr6, {
 onEnter: function (args) {
 console.log('str6: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr7, {
 onEnter: function (args) {
 console.log('str7: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr5, {
 onEnter: function (args) {
 console.log('str5: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr1, {
 onEnter: function (args) {
 console.log('str1: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr2, {
 onEnter: function (args) {
 console.log('str2: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr3, {
 onEnter: function (args) {
 console.log('str3: ' + args[1]);
 }
 });
 Interceptor.attach(func_nStr4, {
 onEnter: function (args) {
 console.log('str4: ' + args[1]);
 }
 });
 */
/*var modules = Process.enumerateModulesSync();
 modules.forEach(function(module) {
 console.log(module.name);
 });*/

/*var exportFunctions = Module.enumerateExportsSync('node.exe');

 exportFunctions.forEach(function(exp) {
 console.log(exp.name);
 });*/

var newFromUtf8 = '?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z';
var newFromUtf82 = '?NewFromUtf8@String@v8@@SA?AV?$Local@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@12@H@Z';

var getCurrentIsolate = '?GetCurrent@Isolate@v8@@SAPEAV12@XZ';
var getCurrentIsolate2 = '?GetIsolate@Object@v8@@QEAAPEAVIsolate@2@XZ';
var getCurrentIsolate = '?GetCurrent@Isolate@v8@@SAPEAV12@XZ';


var possibleEval = '?CheckPossibleEvalCall@?$ParserBase@VParser@internal@v8@@@internal@v8@@IEAA?AW4PossiblyEval@Call@23@PEAVExpression@23@PEAVScope@23@@Z';
var isEvalParser = '?IsEval@Parser@internal@v8@@AEBA_NPEBVAstRawString@23@@Z';
var isEvalStack = '?IsEval@StackFrame@v8@@QEBA_NXZ';
var isEvalOrArguments = '?IsEvalOrArguments@Parser@internal@v8@@AEBA_NPEBVAstRawString@23@@Z';
var markAsEval = '?MarkAsEval@CompilationInfo@internal@v8@@QEAAXXZ';
var recordEvalCall = '?RecordEvalCall@Scope@internal@v8@@QEAAXXZ';
var recordEvalInnerCall = '?RecordInnerScopeEvalCall@Scope@internal@v8@@QEAAXXZ';
var newEvalScope = '?NewEvalError@Factory@internal@v8@@QEAA?AV?$Handle@VObject@internal@v8@@@23@W4Template@MessageTemplate@23@V423@11@Z';
var getFunctionFromString = '?GetFunctionFromString@Compiler@internal@v8@@SA?AV?$MaybeHandle@VJSFunction@internal@v8@@@23@V?$Handle@VContext@internal@v8@@@23@V?$Handle@VString@internal@v8@@@23@W4ParseRestriction@23@H@Z';
var utfV8Length = '?Utf8Length@String@v8@@QEBAHXZ';//'?length@Value@String@v8@@QEBAHXZ';//'?length@Utf8Value@String@v8@@QEBAHXZ';
var someLength =  '?length@Value@String@v8@@QEBAHXZ';
var toString = '?ToString@Value@v8@@QEBA?AV?$MaybeLocal@VString@v8@@@2@V?$Local@VContext@v8@@@2@@Z';//'?ToString@Value@v8@@QEBA?AV?$Local@VString@v8@@@2@XZ';
var hash = '?ComputeUtf8Hash@StringHasher@internal@v8@@SAIV?$Vector@$$CBD@23@IPEAH@Z';
var run = '?Run@Script@v8@@QEAA?AV?$Local@VValue@v8@@@2@XZ';
var builtIns = '?CallableFor@Builtins@internal@v8@@SA?AVCallable@23@PEAVIsolate@23@W4Name@123@@Z';
var codeFactory = '?BinaryOperation@CodeFactory@internal@v8@@SA?AVCallable@23@PEAVIsolate@23@W4Value@Token@23@@Z';
var newBuffer = '?New@Buffer@node@@YA?AV?$MaybeLocal@VObject@v8@@@v8@@PEAVIsolate@4@PEAD_K@Z';
var newBuffer2 = '?New@Buffer@node@@YA?AV?$MaybeLocal@VObject@v8@@@v8@@PEAVIsolate@4@_K@Z';
var signatureMap = '?Find@SignatureMap@wasm@internal@v8@@QEBAHPEAV?$Signature@W4MachineRepresentation@internal@v8@@@34@@Z';

var maybeUtf8Value = '??0Utf8Value@String@v8@@QEAA@V?$Local@VValue@v8@@@2@@Z';

var nStr1 = '?NewStringFromOneByte@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@V?$Vector@$$CBE@23@W4PretenureFlag@23@@Z';
var nStr2 = '?NewStringFromTwoByte@Factory@internal@v8@@AEAA?AV?$MaybeHandle@VString@internal@v8@@@23@PEBGHW4PretenureFlag@23@@Z';
var nStr3 = '?NewStringFromTwoByte@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@PEBV?$ZoneVector@G@23@W4PretenureFlag@23@@Z';
var nStr4 = '?NewStringFromTwoByte@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@V?$Vector@$$CBG@23@W4PretenureFlag@23@@Z';
var nStr5 = '?NewTwoByteInternalizedString@Factory@internal@v8@@QEAA?AV?$Handle@VString@internal@v8@@@23@V?$Vector@$$CBG@23@I@Z';
var nStr6 = '?AllocateSeqTwoByteString@CodeStubAssembler@internal@v8@@QEAAPEAVNode@compiler@23@HV?$Flags@W4AllocationFlag@CodeStubAssembler@internal@v8@@H@base@3@@Z';
var nStr7 = '?AllocateSeqTwoByteString@CodeStubAssembler@internal@v8@@QEAAPEAVNode@compiler@23@PEAV4523@0W4ParameterMode@123@V?$Flags@W4AllocationFlag@CodeStubAssembler@internal@v8@@H@base@3@@Z';
var nStr8 = '?AllocateTwoByteConsString@CodeStubAssembler@internal@v8@@QEAAPEAVNode@compiler@23@PEAV4523@00V?$Flags@W4AllocationFlag@CodeStubAssembler@internal@v8@@H@base@3@@Z';
var nStr9 = '?InternalizeTwoByteString@Factory@internal@v8@@QEAA?AV?$Handle@VString@internal@v8@@@23@V?$Vector@$$CBG@23@@Z';
var nStr10 = '?NewExternalStringFromTwoByte@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VString@internal@v8@@@23@PEBVExternalStringResource@String@3@@Z';
var nStr11 = '?NewRawTwoByteString@Factory@internal@v8@@QEAA?AV?$MaybeHandle@VSeqTwoByteString@internal@v8@@@23@HW4PretenureFlag@23@@Z';
var nStr12 = '?WriteUtf16Slow@Utf8DecoderBase@unibrow@@KAXPEBE_KPEAG1@Z';
var nStr13 = '?NewStringFromAsciiChecked@Factory@internal@v8@@QEAA?AV?$Handle@VString@internal@v8@@@23@PEBDW4PretenureFlag@23@@Z';
var nStr14 = '?IsOneByte@String@v8@@QEBA_NXZ';
var hsFini = '??0HandleScope@v8@@IEAA@XZ';
var hsInit = '??0HandleScope@v8@@QEAA@PEAVIsolate@1@@Z';
var getCurrentContext = '?GetCurrentContext@Isolate@v8@@QEAA?AV?$Local@VContext@v8@@@2@XZ';
var func_getCurrentContext = new NativeFunction(Module.findExportByName('node.exe', getCurrentContext), 'pointer', ['pointer']);
var func_hsInit = new NativeFunction(Module.findExportByName('node.exe', hsInit), 'void', ['pointer','pointer']);
var func_hsFini = new NativeFunction(Module.findExportByName('node.exe', hsFini), 'void', ['pointer']);
var func_nStr1 = new NativeFunction(Module.findExportByName('node.exe', nStr1), 'pointer', ['pointer', 'pointer', 'pointer'], 'win64');
var func_nStr2 = new NativeFunction(Module.findExportByName('node.exe', nStr2), 'pointer', ['pointer']);
var func_nStr3 = new NativeFunction(Module.findExportByName('node.exe', nStr3), 'pointer', ['pointer']);
var func_nStr4 = new NativeFunction(Module.findExportByName('node.exe', nStr4), 'pointer', ['pointer']);
var func_nStr5 = new NativeFunction(Module.findExportByName('node.exe', nStr5), 'pointer', ['pointer']);
var func_nStr6 = new NativeFunction(Module.findExportByName('node.exe', nStr6), 'pointer', ['pointer']);
var func_nStr7 = new NativeFunction(Module.findExportByName('node.exe', nStr7), 'pointer', ['pointer']);
var func_nStr8 = new NativeFunction(Module.findExportByName('node.exe', nStr8), 'pointer', ['pointer']);
var func_nStr9 = new NativeFunction(Module.findExportByName('node.exe', nStr9), 'pointer', ['pointer']);
var func_nStr10 = new NativeFunction(Module.findExportByName('node.exe', nStr10), 'pointer', ['pointer']);
var func_nStr11 = new NativeFunction(Module.findExportByName('node.exe', nStr11), 'pointer', ['pointer']);
var func_nStr12 = new NativeFunction(Module.findExportByName('node.exe', nStr12), 'pointer', ['pointer']);
var func_nStr13 = new NativeFunction(Module.findExportByName('node.exe', nStr13), 'pointer', ['pointer']);
var func_nStr14 = new NativeFunction(Module.findExportByName('node.exe', nStr14), 'int', ['pointer', 'pointer'], 'win64');
//var func_getCurrentIsolate2 = new NativeFunction(Module.findExportByName('node.exe', getCurrentIsolate2), 'pointer', ['pointer']);
var func_newFromUtf82 = new NativeFunction(Module.findExportByName('node.exe', newFromUtf82), 'pointer', ['pointer', 'pointer', 'int', 'int']);

var func_utf8Value = new NativeFunction(Module.findExportByName('node.exe', maybeUtf8Value), 'pointer', [ 'pointer']);
//var func_getCurrentIsolate = new NativeFunction(Module.findExportByName('node.exe', getCurrentIsolate), 'pointer', []);

var func_utfV8Length = new NativeFunction(Module.findExportByName('node.exe', utfV8Length), 'int', ['pointer']);

var func_checkPossibleEval = new NativeFunction(Module.findExportByName('node.exe', possibleEval), 'int', ['int', 'pointer']);
var func_isEvalParser = new NativeFunction(Module.findExportByName('node.exe', isEvalParser), 'int', []);
var func_isEvalStack = new NativeFunction(Module.findExportByName('node.exe', isEvalStack), 'int', []);
var func_isEvalOrArguments = new NativeFunction(Module.findExportByName('node.exe', isEvalOrArguments), 'int', []);
var func_markAsEval = new NativeFunction(Module.findExportByName('node.exe', markAsEval), 'void', []);
var func_recordEvalCall = new NativeFunction(Module.findExportByName('node.exe', recordEvalCall), 'void', []);
var func_recordInnerScopeEval = new NativeFunction(Module.findExportByName('node.exe', recordEvalInnerCall), 'void', []);
var func_newEvalScope = new NativeFunction(Module.findExportByName('node.exe', newEvalScope), 'pointer', ['pointer']);
var func_getFunctionFromString = new NativeFunction(Module.findExportByName('node.exe', getFunctionFromString), 'pointer', ['pointer','pointer','pointer','pointer']);
var func_toString = new NativeFunction(Module.findExportByName('node.exe', toString), 'pointer', ['pointer']);
var func_hash = new NativeFunction(Module.findExportByName('node.exe', hash), 'pointer', ['pointer']);
var func_run = new NativeFunction(Module.findExportByName('node.exe', run), 'pointer', ['pointer']);
var func_builtIns = new NativeFunction(Module.findExportByName('node.exe', builtIns), 'pointer', ['pointer', 'pointer']);
var func_codeFactory = new NativeFunction(Module.findExportByName('node.exe', codeFactory), 'pointer', ['pointer', 'pointer']);
var func_newFromUtf8 = new NativeFunction(Module.findExportByName('node.exe', newFromUtf8), 'pointer', ['pointer', 'pointer', 'int']);
//var func_newFromUtf82 = new NativeFunction(Module.findExportByName('node.exe', newFromUtf82), 'pointer', ['pointer', 'pointer']);
var func_newBuffer = new NativeFunction(Module.findExportByName('node.exe', newBuffer), 'pointer', ['pointer', 'pointer', 'int', 'int']);
var func_newBuffer2 = new NativeFunction(Module.findExportByName('node.exe', newBuffer2), 'pointer', ['pointer', 'pointer', 'int', 'int']);
var func_signatureMap = new NativeFunction(Module.findExportByName('node.exe', signatureMap), 'pointer', ['pointer', 'pointer']);

/*Interceptor.attach(func_newStr, {
 onEnter: function (args) {
 console.log('func_newStr: ' + args[1]);
 }
 });*/

//console.log('handle: ' + handle);

//handle = Memory.readPointer(handle);

//handle = Memory.readPointer(handle);
//args[1] = handle;

/*console.log(hexdump(handle.sub(200), {
 offset: 0,
 length: 512
 }));*/

function writeString1() {
    var isolate = func_getCurrentIsolate();//func_getCurrentIsolate();
    const scope = Memory.alloc(132);

    console.log('isolate: ' + isolate);

    func_hsInit(scope, isolate);
    var cont = func_getCurrentContext(isolate);
    var ptr = Memory.allocUtf8String("console.log('666');");

    console.log('ptr: ' + ptr);

    var source = func_newFromUtf82(isolate, Memory.allocUtf8String("console.log('666');"), 0, -1);

    console.log(hexdump(source, {
        offset: 0,
        length: 512
    }));
    source = Memory.readPointer(source.add(71));
    console.log(sourcehexdump(source, {
        offset: 0,
        length: 512
    }));

    func_hsFini(scope);
    console.log('isolate: ' + isolate);
    console.log('source:  ' + source);
}

/*Interceptor.attach(func_getFunctionFromEval, {
 onEnter: function (args) {
 var stringPointer = Memory.readPointer(args[1]);


 console.log(hexdump(stringPointer, {
 offset: 0,
 length: 512
 }));

 var str = "console.log('Привет, Андрей... Привет, Андрей... Привет, Андрей! Ну где ты был?! Ну обними меня скорей!')";
 var writableString = Memory.allocUtf8String(str);
 var vector = Memory.alloc(16);
 Memory.writePointer(vector, writableString);
 Memory.writeUInt(vector.add(8), lengthInUtf8Bytes(str));

 console.log('vector: ' + vector);
 console.log('writable string: ' + writableString);
 console.log('stringPointer: ' + stringPointer);

 var isolate = func_getCurrentIsolate();
 var rdx = Memory.alloc(8);
 func_newStringFromUtf8(isolate, rdx, vector, 0);

 console.log(hexdump(Memory.readPointer((Memory.readPointer(rdx))), {
 offset: 0,
 length: 512
 }));

 args[1] = Memory.readPointer(rdx);

 var stringObj = getStringObject(stringPointer);

 console.log('string: ' + stringObj.string);
 console.log('size: ' + stringObj.size);

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

 function lengthInUtf8Bytes(str) { // TODO: проверить в браузере на китайских символах
 // https://stackoverflow.com/questions/5515869/string-length-in-bytes-in-javascript
 // Matches only the 10.. bytes that are non-initial characters in a multi-byte sequence.
 var m = encodeURIComponent(str).match(/%[89ABab]/g);
 return str.length + (m ? m.length : 0);
 }
 }
 });*/

// need esprima.js

function traverse(node, func) {
    func(node);//1
    for (var key in node) { //2
        if (node.hasOwnProperty(key)) { //3
            var child = node[key];
            if (typeof child === 'object' && child !== null) { //4

                if (Array.isArray(child)) {
                    child.forEach(function(node) { //5
                        traverse(node, func);
                    });
                } else {
                    traverse(child, func); //6
                }
            }
        }
    }
}

function analyzeCode(code) {
    var ast = esprima.parse(code);
    var calls = [];

    traverse(ast, function(node) { //3
        if (node.type === 'CallExpression') {
            if (node.callee.type === 'Identifier') {
                calls.push({
                    func: node.callee.name
                });
            } else if (node.callee.type === 'MemberExpression'){
                calls.push({
                    func: node.callee.property.name
                });
            }
        }
    });

    return calls;
}