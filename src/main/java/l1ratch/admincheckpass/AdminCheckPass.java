package l1ratch.admincheckpass;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.ChatColor;
import org.bukkit.scheduler.BukkitRunnable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

import java.security.SecureRandom;
import java.sql.*;

public class AdminCheckPass extends JavaPlugin implements CommandExecutor, Listener {

    private Connection connection;
    private String secretKey;
    private String banCommand;
    private String notificationPrefix = "§8[§cAdmin§aCheck§9Pass§8] ";
    private FileConfiguration config;
    private final String githubRepo = "https://api.github.com/repos/l1ratch/*/releases/latest";
    private String latestVersion;

    @Override
    public void onEnable() {
        this.saveDefaultConfig();
        this.config = getConfig();
        this.secretKey = config.getString("secretKey");
        this.banCommand = config.getString("banCommand");

        this.setupDatabase();
        this.getServer().getPluginManager().registerEvents(this, this);
        this.getCommand("setpas").setExecutor(this);
        this.getCommand("pas").setExecutor(this);
        this.getCommand("regeneratekey").setExecutor(this);

        // Асинхронно проверяем последнюю версию плагина на GitHub
        new BukkitRunnable() {
            @Override
            public void run() {
                checkLatestVersion();
            }
        }.runTaskAsynchronously(this);

        // Асинхронно оповещаем администратора при входе
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            getServer().getOnlinePlayers().forEach(this::notifyAdmin);
        });
    }

    // Метод для проверки последней версии плагина на GitHub
    private void checkLatestVersion() {
        try {
            URL url = new URL(githubRepo);
            URLConnection connection = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = reader.readLine()) != null) {
                response.append(inputLine);
            }
            reader.close();
            // Парсим JSON и получаем последнюю версию
            latestVersion = response.toString().split("\"tag_name\":\"")[1].split("\",")[0];

            // Оповещаем обновление, если доступна новая версия
            if (isNewVersionAvailable(latestVersion)) {
                getLogger().info(notificationPrefix + ChatColor.GREEN + "A new version of the plugin is available: " + ChatColor.GOLD + latestVersion);
                getLogger().info(notificationPrefix + ChatColor.RED + "Download: https://github.com/l1ratch/*/releases/latest");
            }

        } catch (IOException e) {
            getLogger().warning(notificationPrefix + ChatColor.RED + "Couldn't check the latest version of the plugin: " + e.getMessage());
        }
    }

    private void setupDatabase() {
        String host = config.getString("database.host");
        int port = config.getInt("database.port");
        String database = config.getString("database.name");
        String username = config.getString("database.username");
        String password = config.getString("database.password");

        String url = "jdbc:mysql://" + host + ":" + port + "/" + database;

        try {
            this.connection = DriverManager.getConnection(url, username, password);
            Statement statement = connection.createStatement();
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS admin_passwords (nickname VARCHAR(255) PRIMARY KEY, password VARCHAR(255))");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (cmd.getName().equalsIgnoreCase("setpas")) {
            if (args.length != 2 && !(args.length == 3 && sender instanceof Player)) {
                sender.sendMessage(config.getString("messages.usageSetPas"));
                return true;
            }

            String nickname = (sender instanceof Player) ? ((Player) sender).getName() : args[0];
            String password = args[(sender instanceof Player) ? 0 : 1];

            if (args.length == 3 && !args[1].equals(secretKey)) {
                sender.sendMessage(config.getString("messages.secretKeyMismatch"));
                return true;
            }

            try {
                PreparedStatement statement = connection.prepareStatement("REPLACE INTO admin_passwords (nickname, password) VALUES (?, ?)");
                statement.setString(1, nickname);
                statement.setString(2, password);
                statement.executeUpdate();
                sender.sendMessage(config.getString("messages.passwordSet").replace("%nickname%", nickname));
            } catch (SQLException e) {
                e.printStackTrace();
                sender.sendMessage(config.getString("messages.errorSettingPassword"));
            }

            return true;
        } else if (cmd.getName().equalsIgnoreCase("pas")) {
            if (!(sender instanceof Player) && args.length != 2) {
                sender.sendMessage(config.getString("messages.usagePas"));
                return true;
            }

            String nickname = (sender instanceof Player) ? ((Player) sender).getName() : args[0];
            String password = args[(sender instanceof Player) ? 0 : 1];

            try {
                PreparedStatement statement = connection.prepareStatement("SELECT password FROM admin_passwords WHERE nickname = ?");
                statement.setString(1, nickname);
                ResultSet resultSet = statement.executeQuery();

                if (resultSet.next()) {
                    String correctPassword = resultSet.getString("password");
                    if (password.equals(correctPassword)) {
                        sender.sendMessage(config.getString("messages.passwordAccepted"));
                    } else {
                        sender.sendMessage(config.getString("messages.incorrectPassword"));
                        int attemptsLeft = config.getInt("maxAttempts") - 1;
                        sender.sendMessage(config.getString("messages.attemptsLeft").replace("%attempts%", String.valueOf(attemptsLeft)));
                        if (attemptsLeft <= 0) {
                            getServer().dispatchCommand(getServer().getConsoleSender(), banCommand + " " + sender.getName() + " " + config.getString("messages.maxLoginAttempts"));
                        }
                    }
                } else {
                    sender.sendMessage(config.getString("messages.setPasswordFirst"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
                sender.sendMessage(config.getString("messages.errorCheckingPassword"));
            }

            return true;
        } else if (cmd.getName().equalsIgnoreCase("regeneratekey")) {
            if (!(sender instanceof ConsoleCommandSender)) {
                sender.sendMessage("This command can only be executed from console.");
                return true;
            }

            SecureRandom random = new SecureRandom();
            byte[] keyBytes = new byte[8];
            random.nextBytes(keyBytes);
            String newSecretKey = new String(keyBytes);

            config.set("secretKey", newSecretKey);
            saveConfig();

            sender.sendMessage(config.getString("messages.regenerateKey").replace("%newSecretKey%", newSecretKey));
            return true;
        }

        return false;
    }

    // Метод для оповещения администратора
    private void notifyAdmin(Player player) {
        if (player.isOp()) {
            player.sendMessage(notificationPrefix + ChatColor.RED + "A new version of the plugin is available!" + ChatColor.GOLD + " Download: https://github.com/l1ratch/*/releases/latest");
        }
    }

    // Метод для сравнения версий и определения, доступна ли новая версия
    private boolean isNewVersionAvailable(String latestVersion) {
        String currentVersion = getDescription().getVersion();
        // Простое сравнение строк версий
        return currentVersion.compareTo(latestVersion) < 0;
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (player.isOp()) {
            try {
                PreparedStatement statement = connection.prepareStatement("SELECT password FROM admin_passwords WHERE nickname = ?");
                statement.setString(1, player.getName());
                ResultSet resultSet = statement.executeQuery();

                if (!resultSet.next()) {
                    player.sendMessage(config.getString("messages.welcomeNoPassword"));
                } else {
                    player.sendMessage(config.getString("messages.welcomeEnterPassword"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
                player.sendMessage(config.getString("messages.errorCheckingPassword"));
            }
        }
    }
}
