package model;

/**
 * Represents a single authentication log entry.
 *
 * <p>This class stores the information extracted from one line of the
 * authentication log file, including the timestamp, event type,
 * username, and IP address.</p>
 *
 * @author Prasoon Kashyap
 * @version 1.0
 */
public class LogEntry {

    private final String timestamp;
    private final String event;
    private final String username;
    private final String ipAddress;

    /**
     * Creates a new LogEntry object.
     *
     * @param timestamp Date and time when the event occurred.
     * @param event Type of authentication event.
     * @param username Username associated with the event.
     * @param ipAddress IP address from which the event originated.
     */
    public LogEntry(String timestamp, String event, String username, String ipAddress) {

        this.timestamp = timestamp;
        this.event = event;
        this.username = username;
        this.ipAddress = ipAddress;
    }

    /**
     * Returns the timestamp of the log entry.
     *
     * @return Timestamp of the event.
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Returns the event type.
     *
     * @return Authentication event.
     */
    public String getEvent() {
        return event;
    }

    /**
     * Returns the username involved in the event.
     *
     * @return Username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the IP address associated with the event.
     *
     * @return IP address.
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * Returns a string representation of the log entry.
     *
     * @return Formatted log entry.
     */
    @Override
    public String toString() {
        return "LogEntry{" +
                "timestamp='" + timestamp + '\'' +
                ", event='" + event + '\'' +
                ", username='" + username + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                '}';
    }
}
