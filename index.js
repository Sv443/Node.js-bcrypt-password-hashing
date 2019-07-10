const bcrypt = require("bcrypt");
const readline = require("readline");
 
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
 
 
function newPW() {
    console.log("\n\n\n\n\n");
    rl.question("Enter Password: ", password => {
        rl.pause();
        if(validatePassword(password).success === true) new2(password);
        else {
            console.log(`\n\x1b[31m\x1b[1m${validatePassword(password).content}\x1b[0m\n`);
            newPW();
        }
    });
}
 
function new2(password, logHash) {
    hashPassword(password).then(hashed => {
        if(logHash == null) console.log(`\n\n\nInitial: ${password}\nHashed: ${hashed.hash}\nSalt: ${hashed.salt}\nCreated in ${hashed.time.toFixed(2)}ms\n\n`);
 
        rl.question('Enter Password to compare: ', (answer) => {
            rl.pause();
            checkPassword(hashed.hash, hashed.salt, answer.toString()).then(res => {
                if(res === true) {
                    console.log("\x1b[32m\x1b[1mCorrect\x1b[0m");
                    process.exit(0);
                }
                else {
                    console.log("\x1b[31m\x1b[1mWrong\x1b[0m");
                    new2(password, false);
                }
            });
        });
    });
}
 
 
 
 
 
/**
 * @typedef {Object} saltedHash
 * @property {String} hash The hashed version of the password
 * @property {String} salt The salt of the hash
 * @property {Float} time Time it took to create the hash
 */
 
/**
 * Creates a bcrypt-encrypted and salted hash of a password
 * @param {String} password The initial Password
 * @returns {Promise<saltedHash>}
 */
function hashPassword(password) {
    let loginHashPasswordHR = process.hrtime();
    return new Promise((resolve, reject) => {
        bEncrypt(password).then(encrypted => {
            let measuredTime = (process.hrtime(loginHashPasswordHR)[1] / 1e6);
            resolve({
                hash: encrypted.hash,
                salt: encrypted.salt,
                time: measuredTime
            });
        });
    });
}
 
function validatePassword(password) {
    let opts = {
        minLength: 8,
        specialChars: /[!\.\-_;,:\^°\"#~\+\*`´\?={}\(\)\[\]\/\\%\$§&µ€\|<>²³\']/gm,
        specialCharsNeeded: 1,
        numbersNeeded: 2
    };
 
    if(typeof password != "string") return {success: false, content: "Password is not a string"};
    if(password.length < opts.minLength) return {success: false, content: `Password needs to have at least ${opts.minLength} ${opts.minLength > 1 ? "characters" : "character"}, not ${password.length}`};
     
    let specialChar = 0;
    specialChar = password.match(opts.specialChars) != null ? (password.match(opts.specialChars).length) : 0;
 
    if(specialChar < opts.specialCharsNeeded) return {success: false, content: `Password needs to contain at least ${opts.specialCharsNeeded} special ${opts.specialCharsNeeded > 1 ? "characters" : "character"}, not ${specialChar}`};
 
    if(opts.numbersNeeded > 0) {
        if(password.match(/\d/gm) == null) return {success: false, content: `Password needs to contain at least ${opts.numbersNeeded} numerical ${opts.numbersNeeded > 1 ? "characters" : "character"}, not 0`};
        if(password.match(/\d/gm).length < opts.numbersNeeded) return {success: false, content: `Password needs to contain at least ${opts.numbersNeeded} numerical ${opts.numbersNeeded > 1 ? "characters" : "character"}, not ${password.match(/\d/gm).length}`};
    }
 
    return {success: true};
}
 
 
 
 
function bEncrypt(password) {
    return new Promise((resolve, reject) => {
        bcrypt.genSalt(10, (err, salt) => {
            if(!err) {
                bcrypt.hash(password, salt, (err, res) => {
                    if(!err) resolve({
                        hash: res,
                        salt: salt
                    });
                    else reject(err);
                });
            }
            else reject(err);
        });
    });
}
 
 
 
function checkPassword(DBhash, DBsalt, userInput) {
    return new Promise((resolve, reject) => {
        bcrypt.compare(userInput, DBhash, (err, res) => {
            resolve(res);
        });
    });
}
 
 
 
newPW();