package com.vinod.webloganalyzer;

import java.util.regex.Pattern;

public class Format {

	  public enum Field {
	    remote_host,
	    remote_port,
	    local_host,
	    rfc931,
	    username,
	    date,
	    time,
	    timezone,
	    request_method,
	    request_uri,
	    request_protocol,
	    request_query_string,
	    response_status_code,
	    connection_status,
	    bytes_recd,
	    bytes_sent,
	    response_time_micros,
	    referer,
	    user_agent,
	    cookie,
	    pid,
	    tid,
	  };

	  public static final Format COMMON_LOG_FORMAT = new Format(
	    "([a-z0-9.]+) " +                 // remote_host, dotted quad or resolved
	    "([a-z0-9_-]+) " +                // rfc921 usually -
	    "([a-z0-9_-]+) " +                // username if identified, else -
	    "\\[(\\d{1,2}/\\w{3}/\\d{4}):" +  // date part
	    "(\\d{1,2}:\\d{1,2}:\\d{1,2}) " + // time part
	    "([+-]\\d{4})\\] " +              // timezone part
	    "\"([A-Z]{3,5}) " +               // request method
	    "(/[^ ]+) " +                     // request uri
	    "([A-Z]+/\\d\\.\\d)\" " +         // request protocol
	    "(\\d+) " +                       // response status code
	    "(-|\\d+)",                       // bytes received
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
	      Field.bytes_recd
	  });
	  public static final Format COMBINED_LOG_FORMAT = new Format(
	      "([a-z0-9.]+) " +                 // remote_host, dotted quad or
	                                        // resolved
	      "([a-z0-9_-]+) " +                // rfc921 usually -
	      "([a-z0-9_-]+) " +                // username if identified, else -
	      "\\[(\\d{1,2}/\\w{3}/\\d{4}):" +  // date part
	      "(\\d{1,2}:\\d{1,2}:\\d{1,2}) " + // time part
	      "([+-]\\d{4})\\] " +              // timezone part
	      "\"([A-Z]{3,5}) " +               // request method
	      "(/[^ ]+) " +                     // request uri
	      "([A-Z]+/\\d\\.\\d)\" " +         // request protocol
	      "(\\d+) " +                       // response status code
	      "(-|\\d+) " +                     // bytes received
	      "\"([^\"]+)\" " +                 // referer, dotted quad or resolved
	                                        // or '-'
	      "\"([^\"]+)\" " +                 // user-agent string
	      "\"([^\"]+)\"",                   // cookie nvps
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
	        Field.user_agent,
	        Field.cookie
	  });
	  
	  private Pattern pattern;
	  private Field[] fieldNames;
	  
	  public Format(String pattern, Field[] fieldNames) {
	    this.pattern = Pattern.compile(pattern);
	    this.fieldNames = fieldNames;
	  }
	  
	  public Pattern getPattern() {
	    return pattern;
	  }
	  
	  public void setPattern(Pattern pattern) {
	    this.pattern = pattern;
	  }
	  
	  public Field[] getFieldNames() {
	    return fieldNames;
	  }

	  public void setFieldNames(Field[] fieldNames) {
	    this.fieldNames = fieldNames;
	  }
	}