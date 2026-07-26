package parser;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import model.LogEntry;

/**
 * Reads and analyzes authentication log files.
 *
 * <p>
 * This class is responsible for parsing authentication logs from a text file,
 * calculating login statistics, detecting suspicious users and IP addresses,
 * assessing the overall security risk, and storing the analysis results for
 * report generation.
 * </p>
 *
 * @author Prasoon Kashyap
 * @version 1.0
 */
public class LogFileReader {

    private int totalLogs;
    private int successfulLogins;
    private int failedLogins;
    private int uniqueUsers;
    private int uniqueIPs;
    private int suspiciousUsers;
    private int suspiciousIPs;
    private String riskLevel;
    private String firstLogTime;
    private String lastLogTime;
    private String mostTargetedUser;
    private int maxFailedAttempts;
    private String mostSuspiciousIP;
    private int maxIPFailedAttempts;
    private String scanStatus;
    private String generatedBy;

    /**
     * Reads the authentication log file, parses each log entry, performs
     * security analysis, detects suspicious login activity, calculates
     * statistics, and stores the results for report generation.
     */
    public void readLogs() {

        ArrayList<LogEntry> logs = new ArrayList<>();

        try {

            BufferedReader reader = new BufferedReader(new FileReader("sample_logs/logs.txt"));

            String line = reader.readLine();

            while (line != null) {

                System.out.println(line);

                String[] parts = line.split(" ");
                String timestamp = parts[0] + " " + parts[1];
                String event = parts[2];
                String username = parts[3];
                String ipAddress = parts[4];

                LogEntry log = new LogEntry(timestamp, event, username, ipAddress);
                logs.add(log);

                line = reader.readLine();

            }

            totalLogs = logs.size();

            if (!logs.isEmpty()) {

                firstLogTime = logs.get(0).getTimestamp();
                lastLogTime = logs.get(logs.size() - 1).getTimestamp();

            }

            successfulLogins = 0;
            failedLogins = 0;

            HashSet<String> uniqueUsersSet = new HashSet<>();
            HashSet<String> uniqueIPsSet = new HashSet<>();
            HashMap<String, Integer> failedLoginCount = new HashMap<>();
            HashMap<String, Integer> failedIPCount = new HashMap<>();

            for (LogEntry log : logs) {

                if (log.getEvent().equals("LOGIN_SUCCESS")) {

                    successfulLogins++;
                    uniqueUsersSet.add(log.getUsername());
                    uniqueIPsSet.add(log.getIpAddress());

                }

                if (log.getEvent().equals("LOGIN_FAILED")) {

                    failedLogins++;

                    String username = log.getUsername();
                    failedLoginCount.put(
                            username,
                            failedLoginCount.getOrDefault(username, 0) + 1);

                    String ipAddress = log.getIpAddress();
                    failedIPCount.put(
                            ipAddress,
                            failedIPCount.getOrDefault(ipAddress, 0) + 1);

                    uniqueUsersSet.add(log.getUsername());
                    uniqueIPsSet.add(log.getIpAddress());

                }

                uniqueUsers = uniqueUsersSet.size();
                uniqueIPs = uniqueIPsSet.size();

            }

            System.out.println("========== CyberShield Statistics ==========");
            System.out.println("Total Logs         : " + totalLogs);
            System.out.println("Successful Logins  : " + successfulLogins);
            System.out.println("Failed Logins      : " + failedLogins);
            System.out.println("Unique Users       : " + uniqueUsersSet.size());
            System.out.println("Unique IPs         : " + uniqueIPsSet.size());
            System.out.println("============================================");

            System.out.println("========== Failed Login Count ==========");

            for (String username : failedLoginCount.keySet()) {

                System.out.println(username + " -> " + failedLoginCount.get(username));

            }

            System.out.println("========== Threat Detection ==========");

            for (String username : failedLoginCount.keySet()) {

                if (failedLoginCount.get(username) > maxFailedAttempts) {

                    maxFailedAttempts = failedLoginCount.get(username);
                    mostTargetedUser = username;

                }

                if (failedLoginCount.get(username) >= 3) {

                    System.out.println("⚠ ALERT!");
                    System.out.println("User: " + username);
                    System.out.println("Failed Attempts: " + failedLoginCount.get(username));
                    System.out.println("Possible Brute Force Attack Detected!");

                    suspiciousUsers++;

                }

            }

            System.out.println("========== Failed Login Count Per IP ==========");

            for (String ipAddress : failedIPCount.keySet()) {

                System.out.println(ipAddress + " -> " + failedIPCount.get(ipAddress));

            }

            System.out.println("========== Suspicious IP Detection ==========");

            for (String ipAddress : failedIPCount.keySet()) {

                if (failedIPCount.get(ipAddress) > maxIPFailedAttempts) {

                    maxIPFailedAttempts = failedIPCount.get(ipAddress);
                    mostSuspiciousIP = ipAddress;

                }

                if (failedIPCount.get(ipAddress) >= 3) {

                    System.out.println("⚠ ALERT!");
                    System.out.println("IP Address: " + ipAddress);
                    System.out.println("Failed Attempts: " + failedIPCount.get(ipAddress));
                    System.out.println("Possible Brute Force Attack from this IP!\n");

                    suspiciousIPs++;

                }

            }

            if (suspiciousUsers == 0 && suspiciousIPs == 0) {

                riskLevel = "LOW";

            } else if (suspiciousUsers <= 2 && suspiciousIPs <= 2) {

                riskLevel = "MEDIUM";

            } else {

                riskLevel = "HIGH";

            }

            scanStatus = "COMPLETED";
            generatedBy = "CyberShield Security Log Analyzer v1.0";

            reader.close();

        } catch (IOException e) {

            e.printStackTrace();

        }

    }

    /**
     * Returns the total number of log entries processed.
     *
     * @return Total log entries.
     */
    public int getTotalLogs() {
        return totalLogs;
    }

    /**
     * Returns the total number of successful login attempts.
     *
     * @return Number of successful logins.
     */
    public int getSuccessfulLogins() {
        return successfulLogins;
    }

    /**
     * Returns the total number of failed login attempts.
     *
     * @return Number of failed logins.
     */
    public int getFailedLogins() {
        return failedLogins;
    }

    /**
     * Returns the number of unique users found in the log file.
     *
     * @return Number of unique users.
     */
    public int getUniqueUsers() {
        return uniqueUsers;
    }

    /**
     * Returns the number of unique IP addresses found in the log file.
     *
     * @return Number of unique IP addresses.
     */
    public int getUniqueIPs() {
        return uniqueIPs;
    }

    /**
     * Returns the number of suspicious users detected.
     *
     * @return Number of suspicious users.
     */
    public int getSuspiciousUsers() {
        return suspiciousUsers;
    }

    /**
     * Returns the number of suspicious IP addresses detected.
     *
     * @return Number of suspicious IP addresses.
     */
    public int getSuspiciousIPs() {
        return suspiciousIPs;
    }

    /**
     * Returns the calculated overall security risk level.
     *
     * @return Security risk level.
     */
    public String getRiskLevel() {
        return riskLevel;
    }

    /**
     * Returns the timestamp of the first log entry.
     *
     * @return First log timestamp.
     */
    public String getFirstLogTime() {
        return firstLogTime;
    }

    /**
     * Returns the timestamp of the last log entry.
     *
     * @return Last log timestamp.
     */
    public String getLastLogTime() {
        return lastLogTime;
    }

    /**
     * Returns the username with the highest number of failed login attempts.
     *
     * @return Most targeted username.
     */
    public String getMostTargetedUser() {
        return mostTargetedUser;
    }

    /**
     * Returns the maximum number of failed login attempts recorded for a single user.
     *
     * @return Maximum failed login attempts.
     */
    public int getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    /**
     * Returns the IP address with the highest number of failed login attempts.
     *
     * @return Most suspicious IP address.
     */
    public String getMostSuspiciousIP() {
        return mostSuspiciousIP;
    }

    /**
     * Returns the maximum number of failed login attempts recorded from a single IP address.
     *
     * @return Maximum IP failed attempts.
     */
    public int getMaxIPFailedAttempts() {
        return maxIPFailedAttempts;
    }

    /**
     * Returns the current status of the security scan.
     *
     * @return Scan status.
     */
    public String getScanStatus() {
        return scanStatus;
    }

    /**
     * Returns the name and version of the application that generated the report.
     *
     * @return Generator information.
     */
    public String getGeneratedBy() {
        return generatedBy;
    }
}
