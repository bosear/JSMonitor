var fs = require('fs');

var path = "C:\\Users\\Артём\\Desktop\\modules.txt";

var paths = fs.readFileSync(path, 'utf-8').split('\n');

var result = [];

paths.forEach(function (path) {
    var index = path.search(/Eval/);

    if (~index) {
        result.push(path);
    }
});

console.log(result);