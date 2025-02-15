import javax.swing.*;
import java.awt.*;
//import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
//import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
//import java.security.*;

public class Filepackerunpacker {
    public static void main(String[] args) {
        new LoginWindow().setVisible(true);
    }

    static class LoginWindow extends JFrame {
        private JTextField usernameField;
        private JPasswordField passwordField;
        private int attempts = 3;

        public LoginWindow() {
            setTitle("Login");
            setSize(300, 150);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLayout(new FlowLayout());

            JLabel userLabel = new JLabel("Username:");
            usernameField = new JTextField(15);
            JLabel passLabel = new JLabel("Password:");
            passwordField = new JPasswordField(15);
            JButton loginButton = new JButton("Login");
            
            add(userLabel);
            add(usernameField);
            add(passLabel);
            add(passwordField);
            add(loginButton);
            
            loginButton.addActionListener(e -> {
                String username = usernameField.getText();
                String password = new String(passwordField.getPassword());
                if (authenticate(username, password)) {
                    new MainWindow().setVisible(true);
                    dispose();
                } else {
                    attempts--;
                    if (attempts <= 0) {
                        JOptionPane.showMessageDialog(null, "Too many failed attempts. Exiting...");
                        System.exit(0);
                    } else {
                        JOptionPane.showMessageDialog(null, "Invalid credentials. Attempts remaining: " + attempts);
                    }
                }
            });
        }

        private boolean authenticate(String username, String password) {
            return username.equals("MarvellousAdmin") && password.equals("MarvellousAdmin");
        }
    }

    static class MainWindow extends JFrame {
        public MainWindow() {
            setTitle("File Packer/Unpacker");
            setSize(300, 150);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLayout(new FlowLayout());

            JButton packButton = new JButton("Pack");
            JButton unpackButton = new JButton("Unpack");

            packButton.addActionListener(e -> new PackWindow().setVisible(true));
            unpackButton.addActionListener(e -> new UnpackWindow().setVisible(true));

            add(packButton);
            add(unpackButton);
        }
    }

    static class PackWindow extends JFrame {
        private JTextField dirField, packedFileField;

        public PackWindow() {
            setTitle("Packing Files");
            setSize(300, 150);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setLayout(new FlowLayout());

            JLabel dirLabel = new JLabel("Directory:");
            dirField = new JTextField(20);
            JLabel packedFileLabel = new JLabel("Packed File:");
            packedFileField = new JTextField(20);
            JButton packButton = new JButton("Pack");
            
            add(dirLabel);
            add(dirField);
            add(packedFileLabel);
            add(packedFileField);
            add(packButton);

            packButton.addActionListener(e -> {
                try {
                    FilePacker.pack(dirField.getText(), packedFileField.getText());
                    JOptionPane.showMessageDialog(null, "Packing successful!");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
                }
            });
        }
    }

    static class UnpackWindow extends JFrame {
        private JTextField packedFileField;

        public UnpackWindow() {
            setTitle("Unpacking Files");
            setSize(300, 150);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setLayout(new FlowLayout());

            JLabel packedFileLabel = new JLabel("Packed File:");
            packedFileField = new JTextField(20);
            JButton unpackButton = new JButton("Unpack");

            add(packedFileLabel);
            add(packedFileField);
            add(unpackButton);
            
            unpackButton.addActionListener(e -> {
                try {
                    FileUnpacker.unpack(packedFileField.getText(), "output");
                    JOptionPane.showMessageDialog(null, "Unpacking successful!");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
                }
            });
        }
    }

    static class FilePacker {
        public static void pack(String directoryPath, String packedFilePath) throws Exception {
            File directory = new File(directoryPath);
            File packedFile = new File(packedFilePath);

            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(packedFile))) {
                out.writeObject("MAGIC_NUMBER");

                File[] files = directory.listFiles();
                for (File file : files) {
                    if (file.isFile()) {
                        out.writeObject(file.getName());
                        out.writeLong(file.length());
                        out.writeObject(generateChecksum(file));
                        byte[] encryptedData = encryptFile(file);
                        out.write(encryptedData);
                    }
                }
            }
        }

        private static byte[] encryptFile(File file) throws Exception {
            byte[] fileData = Files.readAllBytes(file.toPath());
            SecretKeySpec key = new SecretKeySpec("1234567890123456".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(fileData);
        }
        private static String generateChecksum(File file) {
            return String.valueOf(file.hashCode());
        }
    }

    static class FileUnpacker {
        public static void unpack(String packedFilePath, String outputDirectory) throws Exception {
            try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(packedFilePath))) {
                if (!"MAGIC_NUMBER".equals(in.readObject())) {
                    throw new Exception("Invalid packed file!");
                }
                File outputDir = new File(outputDirectory);
                if (!outputDir.exists()) {
                    outputDir.mkdir();
                }

                while (in.available() > 0) {
                    String fileName = (String) in.readObject();
                    long fileSize = in.readLong();
 //                   String checksum = (String) in.readObject();

                    byte[] encryptedData = new byte[(int) fileSize];
                    in.read(encryptedData);
                    byte[] decryptedData = decryptFile(encryptedData);
                    Files.write(new File(outputDirectory + File.separator + fileName).toPath(), decryptedData);
                }
            }
        }

        private static byte[] decryptFile(byte[] encryptedData) throws Exception {
            SecretKeySpec key = new SecretKeySpec("1234567890123456".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);
        }
    }
}
