// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetHttpRedirectTarget {
    /**
     * @return The host portion of the redirect.
     * 
     */
    private String host;
    /**
     * @return The path component of the target URL (e.g., &#34;/path/to/resource&#34; in &#34;https://target.example.com/path/to/resource?redirected&#34;), which can be empty, static, or request-copying, or request-prefixing. Use of \ is not permitted except to escape a following \, {, or }. An empty value is treated the same as static &#34;/&#34;. A static value must begin with a leading &#34;/&#34;, optionally followed by other path characters. A request-copying value must exactly match &#34;{path}&#34;, and will be replaced with the path component of the request URL (including its initial &#34;/&#34;). A request-prefixing value must start with &#34;/&#34; and end with a non-escaped &#34;{path}&#34;, which will be replaced with the path component of the request URL (including its initial &#34;/&#34;). Only one such replacement token is allowed.
     * 
     */
    private String path;
    /**
     * @return Port number of the target destination of the redirect, default to match protocol
     * 
     */
    private Integer port;
    /**
     * @return The protocol used for the target, http or https.
     * 
     */
    private String protocol;
    /**
     * @return The query component of the target URL (e.g., &#34;?redirected&#34; in &#34;https://target.example.com/path/to/resource?redirected&#34;), which can be empty, static, or request-copying. Use of \ is not permitted except to escape a following \, {, or }. An empty value results in a redirection target URL with no query component. A static value must begin with a leading &#34;?&#34;, optionally followed by other query characters. A request-copying value must exactly match &#34;{query}&#34;, and will be replaced with the query component of the request URL (including a leading &#34;?&#34; if and only if the request URL includes a query component).
     * 
     */
    private String query;

    private GetHttpRedirectTarget() {}
    /**
     * @return The host portion of the redirect.
     * 
     */
    public String host() {
        return this.host;
    }
    /**
     * @return The path component of the target URL (e.g., &#34;/path/to/resource&#34; in &#34;https://target.example.com/path/to/resource?redirected&#34;), which can be empty, static, or request-copying, or request-prefixing. Use of \ is not permitted except to escape a following \, {, or }. An empty value is treated the same as static &#34;/&#34;. A static value must begin with a leading &#34;/&#34;, optionally followed by other path characters. A request-copying value must exactly match &#34;{path}&#34;, and will be replaced with the path component of the request URL (including its initial &#34;/&#34;). A request-prefixing value must start with &#34;/&#34; and end with a non-escaped &#34;{path}&#34;, which will be replaced with the path component of the request URL (including its initial &#34;/&#34;). Only one such replacement token is allowed.
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return Port number of the target destination of the redirect, default to match protocol
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The protocol used for the target, http or https.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return The query component of the target URL (e.g., &#34;?redirected&#34; in &#34;https://target.example.com/path/to/resource?redirected&#34;), which can be empty, static, or request-copying. Use of \ is not permitted except to escape a following \, {, or }. An empty value results in a redirection target URL with no query component. A static value must begin with a leading &#34;?&#34;, optionally followed by other query characters. A request-copying value must exactly match &#34;{query}&#34;, and will be replaced with the query component of the request URL (including a leading &#34;?&#34; if and only if the request URL includes a query component).
     * 
     */
    public String query() {
        return this.query;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetHttpRedirectTarget defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String host;
        private String path;
        private Integer port;
        private String protocol;
        private String query;
        public Builder() {}
        public Builder(GetHttpRedirectTarget defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.host = defaults.host;
    	      this.path = defaults.path;
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.query = defaults.query;
        }

        @CustomType.Setter
        public Builder host(String host) {
            if (host == null) {
              throw new MissingRequiredPropertyException("GetHttpRedirectTarget", "host");
            }
            this.host = host;
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetHttpRedirectTarget", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetHttpRedirectTarget", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetHttpRedirectTarget", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder query(String query) {
            if (query == null) {
              throw new MissingRequiredPropertyException("GetHttpRedirectTarget", "query");
            }
            this.query = query;
            return this;
        }
        public GetHttpRedirectTarget build() {
            final var _resultValue = new GetHttpRedirectTarget();
            _resultValue.host = host;
            _resultValue.path = path;
            _resultValue.port = port;
            _resultValue.protocol = protocol;
            _resultValue.query = query;
            return _resultValue;
        }
    }
}
