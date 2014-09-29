package com.vinod.webloganalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.EnumMap;
import java.util.Scanner;
import java.util.regex.MatchResult;

import net.sf.uadetector.UserAgentStringParser;
import net.sf.uadetector.service.UADetectorServiceFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.vinod.webloganalyzer.Format.Field;

public class LogParser {
	private static final Log log = LogFactory.getLog(LogParser.class);
	 private static Format myCustomLogFormat = new Format(
			    "([a-z0-9.]+) " +                 // remote_host, dotted quad or resolved
			    "([a-z0-9_-]+) " +                // rfc921 usually -
			    "([a-z0-9_-]+) " +                // username if identified, else -
			    "\\[(\\d{1,2}/\\w{3}/\\d{4}):" +  // date part
			    "(\\d{1,2}:\\d{1,2}:\\d{1,2}) " + // time part
			    "(-\\d{4})\\] " +                 // timezone part
			    "\"([A-Z]{3,5}) " +               // request method
			    "(/[^ ]+) " +                     // request uri
			    "([A-Z]+/\\d\\.\\d)\" " +         // request protocol
			    "(\\d+) " +                       // response status code
			    "(-|\\d+) " +                     // bytes received
			    "\"([^\"]+)\" " +                 // referer, dotted quad or resolved 
			                                      // or '-'
			   /* "(\\d+) " +  */                     // custom: response time in microsecs
			    "\"([^\"]+)\"",                   // user-agent string
			    new Field[] {
			      Field.remote_host,
			      Field.rfc931,
			      Field.username,
			      Field.date,
			      Field.time,
			      Field.timezone,
			      Field.request_method,
			      Field.request_uri,
			      Field.request_protocol,
			      Field.response_status_code,
			      Field.bytes_recd,
			      Field.referer,
			     // Field.response_time_micros, // our custom field here
			      Field.user_agent,
			  });
	public EnumMap<Format.Field, String> parseLogLine(String logline, Format format) {
		EnumMap<Format.Field, String> tokens = new EnumMap<Format.Field, String>(
				Format.Field.class);
		Scanner scanner = new Scanner(logline);
		scanner.findInLine(format.getPattern());
		MatchResult result = scanner.match();
		for (int i = 0; i < format.getFieldNames().length; i++) {
			tokens.put(format.getFieldNames()[i], result.group(i + 1));
		}
		scanner.close();
		return tokens;
	}

	public void parseLogsFromDirectory(String directory) throws IOException {
		File[] accesslogs = (new File(directory)).listFiles();
		UserAgentStringParser uaparser = UADetectorServiceFactory.getResourceModuleParser();
		for (File accesslog : accesslogs) {
			String line;
			BufferedReader reader = new BufferedReader(
					new FileReader(accesslog));
			while ((line = reader.readLine()) != null) {
				System.out.println(line);
				EnumMap<Field, String> elements = parseLogLine(line,
						myCustomLogFormat);
					printResult(line, "CUSTOM_LOG_FORMAT", elements);
					
					System.out.println(uaparser.parse(elements.get(Field.user_agent)).getName());
			}
			reader.close();
		}
	}

	private void printResult(String line, String format,
			EnumMap<Field, String> result) {
		for (Field key : result.keySet()) {
			System.out.println("  " + key.name() + " => " + result.get(key));
		}
	}
	public static void main(String[] args) {
		LogParser parser = new LogParser();
		String line = "192.168.123.12 - - [19/Oct/2008:19:45:38 -0700] \"GET /search?q1=foo&st=bar HTTP/1.1\" 200 323 \"-\" 34567 \"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.14) Gecko/20080416 Fedora/2.0.0.14-1.fc7 Firefox/2.0.0.14\"";
		
		String line2 ="157.166.226.25 - - [25/Jul/2011:18:41:41 -0400] \"GET /favicon.ico HTTP/1.1\" 404 280 \"-\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.124 Safari/534.30\"";
		try {
			/*EnumMap<Field, String> elements = parser.parseLogLine(line2,myCustomLogFormat);
			parser.printResult(line2, "CUSTOM_LOG_FORMAT", elements);*/
			
			parser.parseLogsFromDirectory("/home/vinod/work/ex-logs");
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
