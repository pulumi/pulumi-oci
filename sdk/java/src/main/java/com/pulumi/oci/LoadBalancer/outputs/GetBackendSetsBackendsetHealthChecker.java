// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBackendSetsBackendsetHealthChecker {
    /**
     * @return The interval between health checks, in milliseconds. The default is 10000 (10 seconds).  Example: `10000`
     * 
     */
    private Integer intervalMs;
    /**
     * @return Specifies if health checks should always be done using plain text instead of depending on whether or not the associated backend set is using SSL.
     * 
     */
    private Boolean isForcePlainText;
    /**
     * @return The backend server port against which to run the health check. If the port is not specified, the load balancer uses the port information from the `Backend` object.  Example: `8080`
     * 
     */
    private Integer port;
    /**
     * @return The protocol the health check must use; either HTTP or TCP.  Example: `HTTP`
     * 
     */
    private String protocol;
    /**
     * @return A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
     * 
     */
    private String responseBodyRegex;
    /**
     * @return The number of retries to attempt before a backend server is considered &#34;unhealthy&#34;. This number also applies when recovering a server to the &#34;healthy&#34; state. Defaults to 3.  Example: `3`
     * 
     */
    private Integer retries;
    /**
     * @return The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, you can use common HTTP status codes such as &#34;200&#34;.  Example: `200`
     * 
     */
    private Integer returnCode;
    /**
     * @return The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. Defaults to 3000 (3 seconds).  Example: `3000`
     * 
     */
    private Integer timeoutInMillis;
    /**
     * @return The path against which to run the health check.  Example: `/healthcheck`
     * 
     */
    private String urlPath;

    private GetBackendSetsBackendsetHealthChecker() {}
    /**
     * @return The interval between health checks, in milliseconds. The default is 10000 (10 seconds).  Example: `10000`
     * 
     */
    public Integer intervalMs() {
        return this.intervalMs;
    }
    /**
     * @return Specifies if health checks should always be done using plain text instead of depending on whether or not the associated backend set is using SSL.
     * 
     */
    public Boolean isForcePlainText() {
        return this.isForcePlainText;
    }
    /**
     * @return The backend server port against which to run the health check. If the port is not specified, the load balancer uses the port information from the `Backend` object.  Example: `8080`
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The protocol the health check must use; either HTTP or TCP.  Example: `HTTP`
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
     * 
     */
    public String responseBodyRegex() {
        return this.responseBodyRegex;
    }
    /**
     * @return The number of retries to attempt before a backend server is considered &#34;unhealthy&#34;. This number also applies when recovering a server to the &#34;healthy&#34; state. Defaults to 3.  Example: `3`
     * 
     */
    public Integer retries() {
        return this.retries;
    }
    /**
     * @return The status code a healthy backend server should return. If you configure the health check policy to use the HTTP protocol, you can use common HTTP status codes such as &#34;200&#34;.  Example: `200`
     * 
     */
    public Integer returnCode() {
        return this.returnCode;
    }
    /**
     * @return The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period. Defaults to 3000 (3 seconds).  Example: `3000`
     * 
     */
    public Integer timeoutInMillis() {
        return this.timeoutInMillis;
    }
    /**
     * @return The path against which to run the health check.  Example: `/healthcheck`
     * 
     */
    public String urlPath() {
        return this.urlPath;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackendSetsBackendsetHealthChecker defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer intervalMs;
        private Boolean isForcePlainText;
        private Integer port;
        private String protocol;
        private String responseBodyRegex;
        private Integer retries;
        private Integer returnCode;
        private Integer timeoutInMillis;
        private String urlPath;
        public Builder() {}
        public Builder(GetBackendSetsBackendsetHealthChecker defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.intervalMs = defaults.intervalMs;
    	      this.isForcePlainText = defaults.isForcePlainText;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.responseBodyRegex = defaults.responseBodyRegex;
    	      this.retries = defaults.retries;
    	      this.returnCode = defaults.returnCode;
    	      this.timeoutInMillis = defaults.timeoutInMillis;
    	      this.urlPath = defaults.urlPath;
        }

        @CustomType.Setter
        public Builder intervalMs(Integer intervalMs) {
            if (intervalMs == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "intervalMs");
            }
            this.intervalMs = intervalMs;
            return this;
        }
        @CustomType.Setter
        public Builder isForcePlainText(Boolean isForcePlainText) {
            if (isForcePlainText == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "isForcePlainText");
            }
            this.isForcePlainText = isForcePlainText;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder responseBodyRegex(String responseBodyRegex) {
            if (responseBodyRegex == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "responseBodyRegex");
            }
            this.responseBodyRegex = responseBodyRegex;
            return this;
        }
        @CustomType.Setter
        public Builder retries(Integer retries) {
            if (retries == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "retries");
            }
            this.retries = retries;
            return this;
        }
        @CustomType.Setter
        public Builder returnCode(Integer returnCode) {
            if (returnCode == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "returnCode");
            }
            this.returnCode = returnCode;
            return this;
        }
        @CustomType.Setter
        public Builder timeoutInMillis(Integer timeoutInMillis) {
            if (timeoutInMillis == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "timeoutInMillis");
            }
            this.timeoutInMillis = timeoutInMillis;
            return this;
        }
        @CustomType.Setter
        public Builder urlPath(String urlPath) {
            if (urlPath == null) {
              throw new MissingRequiredPropertyException("GetBackendSetsBackendsetHealthChecker", "urlPath");
            }
            this.urlPath = urlPath;
            return this;
        }
        public GetBackendSetsBackendsetHealthChecker build() {
            final var _resultValue = new GetBackendSetsBackendsetHealthChecker();
            _resultValue.intervalMs = intervalMs;
            _resultValue.isForcePlainText = isForcePlainText;
            _resultValue.port = port;
            _resultValue.protocol = protocol;
            _resultValue.responseBodyRegex = responseBodyRegex;
            _resultValue.retries = retries;
            _resultValue.returnCode = returnCode;
            _resultValue.timeoutInMillis = timeoutInMillis;
            _resultValue.urlPath = urlPath;
            return _resultValue;
        }
    }
}
