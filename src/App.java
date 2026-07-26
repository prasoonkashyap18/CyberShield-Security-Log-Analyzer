import parser.LogFileReader;
import report.ReportGenerator;

/**
 * Entry point of the CyberShield Security Log Analyzer application.
 *
 * <p>
 * This class coordinates the execution of the application by reading
 * authentication logs, performing security analysis, and generating
 * a comprehensive security report.
 * </p>
 *
 * @author Prasoon Kashyap
 * @version 1.0
 */
public class App {

    /**
     * Starts the CyberShield Security Log Analyzer.
     *
     * <p>
     * The application performs the following steps:
     * <ul>
     *     <li>Creates a log file reader.</li>
     *     <li>Reads and analyzes authentication logs.</li>
     *     <li>Generates and displays the security report.</li>
     * </ul>
     * </p>
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {

        LogFileReader reader = new LogFileReader();
        ReportGenerator report = new ReportGenerator();

        reader.readLogs();

        report.generateReport(
                reader.getTotalLogs(),
                reader.getSuccessfulLogins(),
                reader.getFailedLogins(),
                reader.getUniqueUsers(),
                reader.getUniqueIPs(),
                reader.getSuspiciousUsers(),
                reader.getSuccessfulLogins(),
                reader.getRiskLevel(),
                reader.getFirstLogTime(),
                reader.getLastLogTime(),
                reader.getMostTargetedUser(),
                reader.getMaxFailedAttempts(),
                reader.getMostSuspiciousIP(),
                reader.getMaxIPFailedAttempts(),
                reader.getScanStatus(),
                reader.getGeneratedBy());

    }
}
