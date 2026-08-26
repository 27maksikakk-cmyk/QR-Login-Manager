// qr_login_manager.js
const { program } = require('commander');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');
const chalk = require('chalk');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

// Производная ключа (PBKDF2)
function deriveKey(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, key) => {
            if (err) reject(err);
            else resolve(key);
        });
    });
}

async function encryptData(data, password) {
    const salt = crypto.randomBytes(16);
    const key = await deriveKey(password, salt);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, authTag, encrypted]);
}

async function decryptData(encrypted, password) {
    const salt = encrypted.slice(0, 16);
    const iv = encrypted.slice(16, 28);
    const authTag = encrypted.slice(28, 44);
    const ciphertext = encrypted.slice(44);
    const key = await deriveKey(password, salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function generateCodes(count, length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const codes = [];
    for (let i = 0; i < count; i++) {
        let code = '';
        for (let j = 0; j < length; j++) {
            code += chars[crypto.randomInt(0, chars.length)];
        }
        codes.push(code);
    }
    return codes;
}

async function saveToFile(data, password, filename) {
    const json = JSON.stringify(data);
    const encrypted = await encryptData(Buffer.from(json), password);
    fs.writeFileSync(filename, encrypted);
    console.log(chalk.green(`Saved encrypted backup to ${filename}`));
}

async function loadFromFile(filename, password) {
    const encrypted = fs.readFileSync(filename);
    const decrypted = await decryptData(encrypted, password);
    return JSON.parse(decrypted.toString());
}

async function listCodes(filename, password) {
    const data = await loadFromFile(filename, password);
    console.log(chalk.cyan(`Backup: ${filename}`));
    console.log(chalk.yellow(`Created: ${data.created}`));
    console.log(chalk.green('Codes:'));
    data.codes.forEach(code => console.log(`  ${code}`));
}

async function generateQR(filename, password, output) {
    const data = await loadFromFile(filename, password);
    const codesStr = data.codes.join('\n');
    await QRCode.toFile(output, codesStr, { type: 'png' });
    console.log(chalk.green(`QR code saved to ${output}`));
}

async function checkCode(filename, password, code) {
    const data = await loadFromFile(filename, password);
    if (data.codes.includes(code)) {
        console.log(chalk.green(`Code '${code}' is valid (found in backup).`));
    } else {
        console.log(chalk.red(`Code '${code}' is NOT in backup.`));
    }
}

program
    .option('--generate <count>', 'Generate backup codes', parseInt)
    .option('--output <file>', 'Output file for encrypted backup')
    .option('--password <pwd>', 'Password for encryption/decryption')
    .option('--list <file>', 'List codes from encrypted file')
    .option('--qr <file>', 'Generate QR code from backup')
    .option('--check <code>', 'Check if code exists in backup')
    .parse(process.argv);

const opts = program.opts();

(async () => {
    if (opts.generate) {
        if (!opts.output || !opts.password) {
            console.error(chalk.red('Error: --output and --password required for generation'));
            process.exit(1);
        }
        const codes = generateCodes(opts.generate);
        const data = { created: new Date().toISOString(), codes };
        await saveToFile(data, opts.password, opts.output);
    } else if (opts.list) {
        if (!opts.password) {
            console.error(chalk.red('Error: --password required'));
            process.exit(1);
        }
        await listCodes(opts.list, opts.password);
    } else if (opts.qr) {
        if (!opts.password) {
            console.error(chalk.red('Error: --password required'));
            process.exit(1);
        }
        const outFile = opts.output || 'qrcodes.png';
        await generateQR(opts.qr, opts.password, outFile);
    } else if (opts.check) {
        if (!opts.password || !opts.list) {
            console.error(chalk.red('Error: --password and --list required for check'));
            process.exit(1);
        }
        await checkCode(opts.list, opts.password, opts.check);
    } else {
        console.log('Use --help for usage.');
    }
})();
