package com.abbypan.appservercert;

/**
 * Mock implementation of Android Log for unit tests
 * This provides the same interface as android.util.Log but works in JUnit tests
 */
public class MockLog {
    
    /**
     * Mock debug logging
     * @param tag The tag to use
     * @param msg The message to log
     * @return Always returns 0 (like Android Log)
     */
    public static int d(String tag, String msg) {
        System.out.println("[DEBUG] " + tag + ": " + msg);
        return 0;
    }
    
    /**
     * Mock info logging
     * @param tag The tag to use
     * @param msg The message to log
     * @return Always returns 0 (like Android Log)
     */
    public static int i(String tag, String msg) {
        System.out.println("[INFO] " + tag + ": " + msg);
        return 0;
    }
    
    /**
     * Mock warning logging
     * @param tag The tag to use
     * @param msg The message to log
     * @return Always returns 0 (like Android Log)
     */
    public static int w(String tag, String msg) {
        System.out.println("[WARN] " + tag + ": " + msg);
        return 0;
    }
    
    /**
     * Mock error logging
     * @param tag The tag to use
     * @param msg The message to log
     * @return Always returns 0 (like Android Log)
     */
    public static int e(String tag, String msg) {
        System.err.println("[ERROR] " + tag + ": " + msg);
        return 0;
    }
    
    /**
     * Mock error logging with throwable
     * @param tag The tag to use
     * @param msg The message to log
     * @param tr The throwable to log
     * @return Always returns 0 (like Android Log)
     */
    public static int e(String tag, String msg, Throwable tr) {
        System.err.println("[ERROR] " + tag + ": " + msg);
        if (tr != null) {
            tr.printStackTrace();
        }
        return 0;
    }
    
    /**
     * Mock verbose logging
     * @param tag The tag to use
     * @param msg The message to log
     * @return Always returns 0 (like Android Log)
     */
    public static int v(String tag, String msg) {
        System.out.println("[VERBOSE] " + tag + ": " + msg);
        return 0;
    }
}

