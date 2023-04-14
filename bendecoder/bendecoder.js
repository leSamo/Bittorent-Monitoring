// based on https://en.wikipedia.org/wiki/Bencode

// TODO: argument input

// let input = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
// let input = "i42e"
// let input = "i-42e"
// let input = "6:ahojky"
// let input = "l4:spami42ee"
// let input = "l4:spaml4:spami42eee"
// let input = "d3:bar4:spam3:fooi42ee"
// let input = "d1:c1:d1:dde4:dictd1:a1:b3:inti123e5:list1le5:list2li123e4:ahojdeli1ei2e3:caued1:5i6eeee3:inti-42e1:llee";
let input = "d10:created by18:qBittorrent v4.5.013:creation datei1676736717e4:infod6:lengthi16e4:name7:PDS.txt12:piece lengthi16384e6:pieces20:�>���ʪ�x�amt���'\�Yee";


/*
    {
        "int": -42,
        "dict": {
            "int": 123,
            "list1": [],
            "list2": [123, "ahoj", {}, [1,2,"cau"], {"5": 6}],
            "a": "b"
        },
        "c": "d",
        "l": [],
        "d": {}
    }
*/

let mode = null

const DICT = "__DICT__";
const INT = "int";
const NUM = "num";
const STR = "str";

let output = null;
let current = "";
let remaining = 0;
let depth = 0;

function isDigit(str) {
    return /^\d+$/.test(str);
}

function pass(str) {
    console.log("passing", str)

    // TODO: loop
    if (depth === 0) {
        output = str;
    }
    else if (depth === 1) {
        output.push(str);
    }
    else if (depth === 2) {
        output.at(-1).push(str);
    }
    else if (depth === 3) {
        output.at(-1).at(-1).push(str);
    }
    else if (depth === 4) {
        output.at(-1).at(-1).at(-1).push(str);
    }
    else if (depth === 5) {
        output.at(-1).at(-1).at(-1).at(-1).push(str);
    }
}

function convertArrayToDicts(str) {
    console.log("trying to convert", str)

    if (Array.isArray(str) && str.length > 0) {
        if (str[0] === DICT) {
            if (str.length % 2 === 0) {
                console.error("Invalid input string syntax: dictionary key-value count mismatch");
                return;
            }

            console.log("converting", str)

            let obj = {}

            for (let i = 1; i < str.length; i += 2) {
                obj[str[i]] = convertArrayToDicts(str[i+1]);
            }

            return obj;
        }
        else {
            for (let i = 0; i < str.length; i ++) {
                str[i] = convertArrayToDicts(str[i]);
            }
        }
    }

    return str;
}

// TODO: verbose flag
console.log("mode : depth : remaining : current : first")

while (input !== "") {
    let first = input.substr(0,1);
    input = input.substr(1);
    console.log(mode, ":", depth, ":", remaining, ":", current, ":", first)

    if (remaining > 0) {
        current += first;
        remaining--;

        if (remaining === 0) {
            pass(current);
            current = ""
            mode = null;
        }
    }
    else {
        if (first === ":") {
            if (mode === NUM) {
                remaining = Number(current);
                current = "";
                mode = STR;
                continue;
            }
        }

        if (first === "l") {
           pass([]);
           depth++;
        }

        if (first === "d") {
            pass([DICT]);
            depth++;
         }

        if (first === "e") {
            if (mode === INT) {
                current = Number(current);
                pass(current);
                current = ""
                mode = null;
                continue;
            }
            else {
                // list end
                depth--;

                if (depth < 0) {
                    console.error("Invalid input string syntax: stack underflow");
                    return;
                }
            }
        }
    
        if (first === "i") {
            mode = INT;
            current = "";
            continue;
        }

        if (mode === INT) {
            current += first;
        }

        if (mode !== INT && isDigit(first)) {
            mode = NUM;
            current += first;
        }
    }
}

console.log(mode, ":", depth, ":", remaining, ":", current)

console.dir(output, { depth: null });
console.dir(convertArrayToDicts(output), { depth: null });
