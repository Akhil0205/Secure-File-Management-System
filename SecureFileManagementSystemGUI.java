package WrapperClass;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;

public class SecureFileManagementSystemGUI {

    static Scanner sc = new Scanner(System.in);
    static final String USERS_FILE = "users.txt";
    static final String SECRET_KEY_FILE = "secret.key";
    static SecretKey secretKey;

    public static void main(String[] args) throws Exception {
        loadOrGenerateSecretKey();
        System.out.println("\n====== Secure File Management System ======");

        while (true) {
            System.out.println("\n1. Register\n2. Login\n3. Exit\nEnter choice:");
            int choice = sc.nextInt(); sc.nextLine();
            switch (choice) {
                case 1: registerUser(); break;
                case 2: if (loginUser()) showFileOperations(); break;
                case 3: System.exit(0);
                default: System.out.println("Invalid choice");
            }
        }
    }

    // Authentication Module
    static void registerUser() throws Exception {
        System.out.print("Enter Username: ");
        String username = sc.nextLine();
        System.out.print("Enter Password: ");
        String password = sc.nextLine();
        String hashed = hashPassword(password);
        FileWriter fw = new FileWriter(USERS_FILE, true);
        fw.write(username + "," + hashed + "\n");
        fw.close();
        System.out.println("User registered successfully!");
    }

    static boolean loginUser() throws Exception {
        System.out.print("Enter Username: ");
        String username = sc.nextLine();
        System.out.print("Enter Password: ");
        String password = sc.nextLine();
        String hashed = hashPassword(password);
        List<String> users = Files.readAllLines(Paths.get(USERS_FILE));
        for (String user : users) {
            String[] parts = user.split(",");
            if (parts[0].equals(username) && parts[1].equals(hashed)) {
                System.out.println("Password verified.");
                return verifyOTP();
            }
        }
        System.out.println("Invalid Credentials!");
        return false;
    }

    static boolean verifyOTP() {
        int otp = 1000 + new Random().nextInt(9000);
        System.out.println("OTP: " + otp);
        System.out.print("Enter OTP: ");
        int entered = sc.nextInt(); sc.nextLine();
        if (otp == entered) {
            System.out.println("Login Successful!");
            return true;
        } else {
            System.out.println("Incorrect OTP!");
            return false;
        }
    }

    static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // Secure File Operations
    static void showFileOperations() throws Exception {
        while (true) {
            System.out.println("\n1. Upload File\n2. Download File\n3. Read File\n4. Write to File\n5. View Metadata\n6. Logout\nEnter choice:");
            int choice = sc.nextInt(); sc.nextLine();
            switch (choice) {
                case 1: uploadFile(); break;
                case 2: downloadFile(); break;
                case 3: readFile(); break;
                case 4: writeFile(); break;
                case 5: viewMetadata(); break;
                case 6: return;
                default: System.out.println("Invalid choice");
            }
        }
    }

    static void uploadFile() throws Exception {
        System.out.print("Enter file path to upload: ");
        String path = sc.nextLine();
        File file = new File(path);
        if (!file.exists()) {
            System.out.println("File not found.");
            return;
        }
        if (detectMalware(file)) {
            System.out.println("Malware detected! Upload blocked.");
            return;
        }
        byte[] content = Files.readAllBytes(file.toPath());
        byte[] encrypted = encrypt(content);
        Files.write(Paths.get("files/" + file.getName() + ".enc"), encrypted);
        System.out.println("File encrypted and uploaded.");
    }

    static void downloadFile() throws Exception {
        System.out.print("Enter file name to download: ");
        String name = sc.nextLine();
        File file = new File("files/" + name + ".enc");
        if (!file.exists()) {
            System.out.println("File not found.");
            return;
        }
        byte[] content = Files.readAllBytes(file.toPath());
        byte[] decrypted = decrypt(content);
        Files.write(Paths.get("files/" + name + ".dec"), decrypted);
        System.out.println("File decrypted and downloaded.");
    }

    static void readFile() throws Exception {
        System.out.print("Enter file name to read: ");
        String name = sc.nextLine();
        File file = new File("files/" + name + ".dec");
        if (!file.exists()) {
            System.out.println("Decrypted file not found. Download first.");
            return;
        }
        System.out.println("\n--- File Content ---");
        Files.lines(file.toPath()).forEach(System.out::println);
    }

    static void writeFile() throws Exception {
        System.out.print("Enter file name to write: ");
        String name = sc.nextLine();
        File file = new File("files/" + name + ".dec");
        if (!file.exists()) {
            System.out.println("Decrypted file not found. Download first.");
            return;
        }
        System.out.print("Enter content to append: ");
        String content = sc.nextLine();
        if (content.length() > 1024) {
            System.out.println("Input too large! Possible buffer overflow.");
            return;
        }
        FileWriter fw = new FileWriter(file, true);
        fw.write("\n" + content);
        fw.close();
        System.out.println("Content added.");
    }

    static void viewMetadata() throws Exception {
        System.out.print("Enter file name to view metadata: ");
        String name = sc.nextLine();
        File file = new File("files/" + name + ".enc");
        if (!file.exists()) {
            System.out.println("File not found.");
            return;
        }
        System.out.println("File Size: " + file.length() + " bytes");
        System.out.println("Last Modified: " + new Date(file.lastModified()));
    }

    // Threat Detection
    static boolean detectMalware(File file) throws Exception {
        List<String> signatures = Files.readAllLines(Paths.get("signatures.txt"));
        String content = new String(Files.readAllBytes(file.toPath()));
        for (String sig : signatures) {
            if (content.contains(sig)) return true;
        }
        return false;
    }

    // Encryption & Key Management
    static void loadOrGenerateSecretKey() throws Exception {
        File keyFile = new File(SECRET_KEY_FILE);
        if (keyFile.exists()) {
            byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
            secretKey = new SecretKeySpec(keyBytes, "AES");
        } else {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
            Files.write(keyFile.toPath(), secretKey.getEncoded());
        }
    }

    static byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    static byte[] decrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }
}
