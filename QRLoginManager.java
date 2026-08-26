// QRLoginManager.java
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

public class QRLoginManager {
    private static final int SALT_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int KEY_SIZE = 32;
    private static final int ITERATIONS = 100000;
    private static final SecureRandom RANDOM = new SecureRandom();

    static class BackupData {
        String created;
        List<String> codes;
    }

    private static byte[] deriveKey(String password, byte[] salt) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password.getBytes(), salt, ITERATIONS);
        KeyParameter param = (KeyParameter) gen.generateDerivedParameters(KEY_SIZE * 8);
        return param.getKey();
    }

    private static byte[] encryptData(byte[] data, String password) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(nonce);
        byte[] key = deriveKey(password, salt);
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, nonce);
        cipher.init(true, params);
        byte[] out = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, out, 0);
        len += cipher.doFinal(out, len);
        byte[] combined = new byte[salt.length + nonce.length + len];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(nonce, 0, combined, salt.length, nonce.length);
        System.arraycopy(out, 0, combined, salt.length + nonce.length, len);
        return combined;
    }

    private static byte[] decryptData(byte[] encrypted, String password) throws Exception {
        if (encrypted.length < SALT_SIZE + NONCE_SIZE) throw new Exception("Invalid data");
        byte[] salt = Arrays.copyOfRange(encrypted, 0, SALT_SIZE);
        byte[] nonce = Arrays.copyOfRange(encrypted, SALT_SIZE, SALT_SIZE + NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, SALT_SIZE + NONCE_SIZE, encrypted.length);
        byte[] key = deriveKey(password, salt);
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, nonce);
        cipher.init(false, params);
        byte[] out = new byte[cipher.getOutputSize(ciphertext.length)];
        int len = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
        len += cipher.doFinal(out, len);
        return Arrays.copyOf(out, len);
    }

    private static List<String> generateCodes(int count, int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < length; j++) {
                sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
            }
            codes.add(sb.toString());
        }
        return codes;
    }

    private static void saveToFile(BackupData data, String password, String filename) throws Exception {
        Gson gson = new Gson();
        String json = gson.toJson(data);
        byte[] encrypted = encryptData(json.getBytes(), password);
        Files.write(Paths.get(filename), encrypted);
        System.out.println("Saved encrypted backup to " + filename);
    }

    private static BackupData loadFromFile(String filename, String password) throws Exception {
        byte[] encrypted = Files.readAllBytes(Paths.get(filename));
        byte[] decrypted = decryptData(encrypted, password);
        Gson gson = new Gson();
        return gson.fromJson(new String(decrypted), BackupData.class);
    }

    private static void listCodes(String filename, String password) throws Exception {
        BackupData data = loadFromFile(filename, password);
        System.out.println("Backup: " + filename);
        System.out.println("Created: " + data.created);
        System.out.println("Codes:");
        for (String code : data.codes) {
            System.out.println("  " + code);
        }
    }

    private static void generateQR(String filename, String password, String output) throws Exception {
        BackupData data = loadFromFile(filename, password);
        String codesStr = String.join("\n", data.codes);
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(codesStr, BarcodeFormat.QR_CODE, 300, 300);
        MatrixToImageWriter.writeToPath(matrix, "PNG", Paths.get(output));
        System.out.println("QR code saved to " + output);
    }

    private static void checkCode(String filename, String password, String code) throws Exception {
        BackupData data = loadFromFile(filename, password);
        if (data.codes.contains(code)) {
            System.out.println("Code '" + code + "' is valid (found in backup).");
        } else {
            System.out.println("Code '" + code + "' is NOT in backup.");
        }
    }

    public static void main(String[] args) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                String key = args[i].substring(2);
                if (i + 1 < args.length && !args[i+1].startsWith("--")) {
                    params.put(key, args[++i]);
                } else {
                    params.put(key, "");
                }
            }
        }

        try {
            if (params.containsKey("generate")) {
                int count = Integer.parseInt(params.get("generate"));
                String output = params.get("output");
                String password = params.get("password");
                if (output == null || password == null) {
                    System.err.println("Error: --output and --password required");
                    System.exit(1);
                }
                BackupData data = new BackupData();
                data.created = Instant.now().toString();
                data.codes = generateCodes(count, 8);
                saveToFile(data, password, output);
            } else if (params.containsKey("list")) {
                String file = params.get("list");
                String password = params.get("password");
                if (password == null) {
                    System.err.println("Error: --password required");
                    System.exit(1);
                }
                listCodes(file, password);
            } else if (params.containsKey("qr")) {
                String file = params.get("qr");
                String password = params.get("password");
                String output = params.get("output");
                if (password == null || output == null) {
                    System.err.println("Error: --password and --output required for QR");
                    System.exit(1);
                }
                generateQR(file, password, output);
            } else if (params.containsKey("check")) {
                String code = params.get("check");
                String file = params.get("list");
                String password = params.get("password");
                if (file == null || password == null) {
                    System.err.println("Error: --list and --password required for check");
                    System.exit(1);
                }
                checkCode(file, password, code);
            } else {
                System.out.println("Use --help for usage.");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
