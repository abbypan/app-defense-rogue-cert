package com.abbypan.appservercert;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONObject;

/**
 * Utility class for reading JSON files
 */
public class JsonFileReader {
    
    /**
     * Reads a JSON file and returns a JSONObject
     * 
     * @param cache_file_name the path to the JSON file
     * @return JSONObject containing the parsed JSON data
     * @throws Exception if file reading or JSON parsing fails
     */
    public static String read_file(String cache_file_name) throws Exception {
        File cache_file = new File(cache_file_name);
        String our_cache_f = cache_file.getAbsolutePath();
        String our_content = new String(Files.readAllBytes(Paths.get(our_cache_f)));

        return our_content;
    }
    public static JSONObject read_json_object(String cache_file_name) throws Exception {
        String our_content = read_file(cache_file_name);
        JSONObject cache = new JSONObject(our_content);
        return cache;
    }


}
