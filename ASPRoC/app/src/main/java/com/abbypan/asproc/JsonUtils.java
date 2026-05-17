package com.abbypan.asproc;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Utility class for reading JSON files and strings
 */
public class JsonUtils {
	/**
	 * Reads a file and returns its content as String
	 *
	 * @param cache_file_name the path to the file
	 * @return file content as String
	 * @throws Exception if file reading fails
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

	/**
	 * Extract a String field from a JSON text; returns null if missing.
	 */
	public static String optString(String jsonText, String key) throws JSONException {
		if (jsonText == null || jsonText.isEmpty()) {
			return null;
		}
		JSONObject obj = new JSONObject(jsonText);
		String val = obj.optString(key, null);
		return (val != null && !val.isEmpty()) ? val : null;
	}
}


