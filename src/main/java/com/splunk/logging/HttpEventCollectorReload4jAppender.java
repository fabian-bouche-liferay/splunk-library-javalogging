package com.splunk.logging;

import com.google.gson.Gson;
import com.splunk.logging.HttpEventCollectorSender.TimeoutSettings;
import com.splunk.logging.hec.MetadataTags;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.spi.LoggingEvent;

public class HttpEventCollectorReload4jAppender extends AppenderSkeleton {

    private HttpEventCollectorSender sender = null;
    
    private boolean includeLoggerName = true;
    private boolean includeThreadName = true;
    private boolean includeMDC = true;
    private boolean includeException = true;
    
	private String token;
	private String url;
	private String channel;
	private String host;
	private String index;
	private String source;
	private String sourceType;
	private String messageFormat;
	private String type;
	private long batchInterval;
	private long batchCount;
	private long batchSize;
	private String sendMode;
	private String middleware;
	private String eventBodySerializer;
	private String eventHeaderSerializer;
	private int retriesOnError;
	private String disableCertificateValidation;

	private long connectTimeout = HttpEventCollectorSender.TimeoutSettings.DEFAULT_CONNECT_TIMEOUT;
	private long callTimeout = HttpEventCollectorSender.TimeoutSettings.DEFAULT_CALL_TIMEOUT;
	private long readTimeout = HttpEventCollectorSender.TimeoutSettings.DEFAULT_READ_TIMEOUT;
	private long writeTimeout = HttpEventCollectorSender.TimeoutSettings.DEFAULT_WRITE_TIMEOUT;
	private long terminationTimeout = HttpEventCollectorSender.TimeoutSettings.DEFAULT_TERMINATION_TIMEOUT;
    
	@Override
	public void close() {
        // Cleanup resources if needed
	}

	@Override
	public boolean requiresLayout() {
		return true;
	}

	@Override
	public void activateOptions() {
		
        Map<String, String> metadata = new HashMap<>();
        metadata.put(MetadataTags.HOST, host != null ? host : "");
        metadata.put(MetadataTags.INDEX, index != null ? index : "");
        metadata.put(MetadataTags.SOURCE, source != null ? source : "");
        metadata.put(MetadataTags.SOURCETYPE, sourceType != null ? sourceType : "");
        metadata.put(MetadataTags.MESSAGEFORMAT, messageFormat != null ? messageFormat : "");
		
        TimeoutSettings timeoutSettings = new HttpEventCollectorSender.TimeoutSettings(connectTimeout, callTimeout, readTimeout, writeTimeout, terminationTimeout);
        
		this.sender = new HttpEventCollectorSender(url, token, channel, type, batchInterval, batchCount, batchSize, sendMode, metadata, timeoutSettings);
		
        // plug a user middleware
        if (middleware != null && !middleware.isEmpty()) {
            try {
                this.sender.addMiddleware((HttpEventCollectorMiddleware.HttpSenderMiddleware)(Class.forName(middleware).newInstance()));
            } catch (Exception ignored) {}
        }

        if (eventBodySerializer != null && !eventBodySerializer.isEmpty()) {
            try {
                this.sender.setEventBodySerializer((EventBodySerializer) Class.forName(eventBodySerializer).newInstance());
            } catch (final Exception ignored) {}
        }

        if (eventHeaderSerializer != null && !eventHeaderSerializer.isEmpty()) {
            try {
                this.sender.setEventHeaderSerializer((EventHeaderSerializer) Class.forName(eventHeaderSerializer).newInstance());
            } catch (final Exception ignored) {}
        }

        // plug resend middleware
        if (retriesOnError > 0) {
            this.sender.addMiddleware(new HttpEventCollectorResendMiddleware(retriesOnError));
        }

        if (disableCertificateValidation != null && disableCertificateValidation.equalsIgnoreCase("true")) {
            this.sender.disableCertificateValidation();
        }
		
		super.activateOptions();
	}
	
    /**
     * Perform Appender specific appending actions.
     * @param event The Log event.
     */
    @Override
	protected void append(LoggingEvent event) {

        String exceptionDetail = generateErrorDetail(event);

        // if an exception was thrown
        this.sender.send(
                event.getTimeStamp(),
                event.getLevel().toString(),
                layout.format(event),
                includeLoggerName ? event.getLoggerName() : null,
                includeThreadName ? event.getThreadName() : null,
                includeMDC ? (Map<String, String>) event.getProperties() : null,
                includeException ? exceptionDetail : null,
                null
        );
		
	}
	
    /**
     * Method used to generate proper exception message if any exception encountered.
     *
     * @param event
     * @return the processed string of all exception detail
     */
    private String generateErrorDetail(final LoggingEvent event) {

        String exceptionDetail = "";

        /*
        Exception details are only populated when any ERROR OR FATAL event occurred
         */
        try {
            // Exception thrown in application is wrapped with relevant information instead of just a message.
            Map<String, String> exceptionDetailMap = new LinkedHashMap<>();

            if (Level.ERROR.equals(event.getLevel()) || Level.FATAL.equals(event.getLevel())) {
                Throwable throwable = event.getThrowableInformation().getThrowable();
                if (throwable == null) {
                    return exceptionDetail;
                }

                exceptionDetailMap.put("detailMessage", throwable.getMessage());
                exceptionDetailMap.put("exceptionClass", throwable.getClass().toString());

                StackTraceElement[] elements = throwable.getStackTrace();
                // Retrieving first element from elements array is because the throws exception detail would be available as a first element.
                if (elements != null && elements.length > 0 && elements[0] != null) {
                    exceptionDetailMap.put("fileName", elements[0].getFileName());
                    exceptionDetailMap.put("methodName", elements[0].getMethodName());
                    exceptionDetailMap.put("lineNumber", String.valueOf(elements[0].getLineNumber()));
                }
                exceptionDetail = new Gson().toJson(exceptionDetailMap);
            }
        } catch (Exception e) {
            // No action here
        }
        return exceptionDetail;
    }

	public boolean isIncludeLoggerName() {
		return includeLoggerName;
	}

	public void setIncludeLoggerName(boolean includeLoggerName) {
		this.includeLoggerName = includeLoggerName;
	}

	public boolean isIncludeThreadName() {
		return includeThreadName;
	}

	public void setIncludeThreadName(boolean includeThreadName) {
		this.includeThreadName = includeThreadName;
	}

	public boolean isIncludeMDC() {
		return includeMDC;
	}

	public void setIncludeMDC(boolean includeMDC) {
		this.includeMDC = includeMDC;
	}

	public boolean isIncludeException() {
		return includeException;
	}

	public void setIncludeException(boolean includeException) {
		this.includeException = includeException;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getChannel() {
		return channel;
	}

	public void setChannel(String channel) {
		this.channel = channel;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getIndex() {
		return index;
	}

	public void setIndex(String index) {
		this.index = index;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public String getSourceType() {
		return sourceType;
	}

	public void setSourceType(String sourceType) {
		this.sourceType = sourceType;
	}

	public long getBatchInterval() {
		return batchInterval;
	}

	public void setBatchInterval(long batchInterval) {
		this.batchInterval = batchInterval;
	}

	public long getBatchCount() {
		return batchCount;
	}

	public void setBatchCount(long batchCount) {
		this.batchCount = batchCount;
	}

	public long getBatchSize() {
		return batchSize;
	}

	public void setBatchSize(long batchSize) {
		this.batchSize = batchSize;
	}

	public String getSendMode() {
		return sendMode;
	}

	public void setSendMode(String sendMode) {
		this.sendMode = sendMode;
	}

	public String getMiddleware() {
		return middleware;
	}

	public void setMiddleware(String middleware) {
		this.middleware = middleware;
	}

	public String getEventBodySerializer() {
		return eventBodySerializer;
	}

	public void setEventBodySerializer(String eventBodySerializer) {
		this.eventBodySerializer = eventBodySerializer;
	}

	public String getEventHeaderSerializer() {
		return eventHeaderSerializer;
	}

	public void setEventHeaderSerializer(String eventHeaderSerializer) {
		this.eventHeaderSerializer = eventHeaderSerializer;
	}

	public int getRetriesOnError() {
		return retriesOnError;
	}

	public void setRetriesOnError(int retriesOnError) {
		this.retriesOnError = retriesOnError;
	}

	public String getDisableCertificateValidation() {
		return disableCertificateValidation;
	}

	public void setDisableCertificateValidation(String disableCertificateValidation) {
		this.disableCertificateValidation = disableCertificateValidation;
	}

	public long getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(long connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public long getCallTimeout() {
		return callTimeout;
	}

	public void setCallTimeout(long callTimeout) {
		this.callTimeout = callTimeout;
	}

	public long getReadTimeout() {
		return readTimeout;
	}

	public void setReadTimeout(long readTimeout) {
		this.readTimeout = readTimeout;
	}

	public long getWriteTimeout() {
		return writeTimeout;
	}

	public void setWriteTimeout(long writeTimeout) {
		this.writeTimeout = writeTimeout;
	}

	public long getTerminationTimeout() {
		return terminationTimeout;
	}

	public void setTerminationTimeout(long terminationTimeout) {
		this.terminationTimeout = terminationTimeout;
	}
    
}
