// QRLoginManager.kt
import com.google.zxing.BarcodeFormat
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.gson.Gson
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.File
import java.security.SecureRandom
import java.time.Instant
import kotlin.system.exitProcess

private const val SALT_SIZE = 16
private const val NONCE_SIZE = 12
private const val KEY_SIZE = 32
private const val ITERATIONS = 100000
private val RANDOM = SecureRandom()

data class BackupData(val created: String, val codes: List<String>)

fun deriveKey(password: String, salt: ByteArray): ByteArray {
    val gen = PKCS5S2ParametersGenerator(SHA256Digest())
    gen.init(password.toByteArray(), salt, ITERATIONS)
    return (gen.generateDerivedParameters(KEY_SIZE * 8) as KeyParameter).key
}

fun encryptData(data: ByteArray, password: String): ByteArray {
    val salt = ByteArray(SALT_SIZE)
    val nonce = ByteArray(NONCE_SIZE)
    RANDOM.nextBytes(salt)
    RANDOM.nextBytes(nonce)
    val key = deriveKey(password, salt)
    val cipher = GCMBlockCipher(AESEngine())
    val params = AEADParameters(KeyParameter(key), 128, nonce)
    cipher.init(true, params)
    val out = ByteArray(cipher.getOutputSize(data.size))
    val len = cipher.processBytes(data, 0, data.size, out, 0)
    val finalLen = cipher.doFinal(out, len)
    return salt + nonce + out.sliceArray(0 until len + finalLen)
}

fun decryptData(encrypted: ByteArray, password: String): ByteArray {
    if (encrypted.size < SALT_SIZE + NONCE_SIZE) throw Exception("Invalid data")
    val salt = encrypted.sliceArray(0 until SALT_SIZE)
    val nonce = encrypted.sliceArray(SALT_SIZE until SALT_SIZE + NONCE_SIZE)
    val ciphertext = encrypted.sliceArray(SALT_SIZE + NONCE_SIZE until encrypted.size)
    val key = deriveKey(password, salt)
    val cipher = GCMBlockCipher(AESEngine())
    val params = AEADParameters(KeyParameter(key), 128, nonce)
    cipher.init(false, params)
    val out = ByteArray(cipher.getOutputSize(ciphertext.size))
    val len = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
    val finalLen = cipher.doFinal(out, len)
    return out.sliceArray(0 until len + finalLen)
}

fun generateCodes(count: Int, length: Int = 8): List<String> {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return List(count) {
        (1..length).map { chars[RANDOM.nextInt(chars.length)] }.joinToString("")
    }
}

fun saveToFile(data: BackupData, password: String, filename: String) {
    val json = Gson().toJson(data)
    val encrypted = encryptData(json.toByteArray(), password)
    File(filename).writeBytes(encrypted)
    println("Saved encrypted backup to $filename")
}

fun loadFromFile(filename: String, password: String): BackupData {
    val encrypted = File(filename).readBytes()
    val decrypted = decryptData(encrypted, password)
    val json = String(decrypted)
    return Gson().fromJson(json, BackupData::class.java)
}

fun listCodes(filename: String, password: String) {
    val data = loadFromFile(filename, password)
    println("Backup: $filename")
    println("Created: ${data.created}")
    println("Codes:")
    data.codes.forEach { println("  $it") }
}

fun generateQR(filename: String, password: String, output: String) {
    val data = loadFromFile(filename, password)
    val codesStr = data.codes.joinToString("\n")
    val writer = QRCodeWriter()
    val matrix = writer.encode(codesStr, BarcodeFormat.QR_CODE, 300, 300)
    MatrixToImageWriter.writeToPath(matrix, "PNG", File(output).toPath())
    println("QR code saved to $output")
}

fun checkCode(filename: String, password: String, code: String) {
    val data = loadFromFile(filename, password)
    if (data.codes.contains(code))
        println("Code '$code' is valid (found in backup).")
    else
        println("Code '$code' is NOT in backup.")
}

fun main(args: Array<String>) {
    val params = mutableMapOf<String, String>()
    var i = 0
    while (i < args.size) {
        if (args[i].startsWith("--")) {
            val key = args[i].substring(2)
            if (i + 1 < args.size && !args[i + 1].startsWith("--")) {
                params[key] = args[++i]
            } else {
                params[key] = ""
            }
        }
        i++
    }

    try {
        when {
            params.containsKey("generate") -> {
                val count = params["generate"]!!.toInt()
                val output = params["output"] ?: throw Exception("--output required")
                val password = params["password"] ?: throw Exception("--password required")
                val codes = generateCodes(count)
                val data = BackupData(Instant.now().toString(), codes)
                saveToFile(data, password, output)
            }
            params.containsKey("list") -> {
                val file = params["list"]!!
                val password = params["password"] ?: throw Exception("--password required")
                listCodes(file, password)
            }
            params.containsKey("qr") -> {
                val file = params["qr"]!!
                val password = params["password"] ?: throw Exception("--password required")
                val output = params["output"] ?: throw Exception("--output required for QR")
                generateQR(file, password, output)
            }
            params.containsKey("check") -> {
                val code = params["check"]!!
                val file = params["list"] ?: throw Exception("--list required for check")
                val password = params["password"] ?: throw Exception("--password required")
                checkCode(file, password, code)
            }
            else -> println("Use --help for usage.")
        }
    } catch (e: Exception) {
        System.err.println("Error: ${e.message}")
        exitProcess(1)
    }
}
