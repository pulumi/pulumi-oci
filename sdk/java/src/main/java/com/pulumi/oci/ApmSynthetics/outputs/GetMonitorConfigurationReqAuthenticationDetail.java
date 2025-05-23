// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmSynthetics.outputs.GetMonitorConfigurationReqAuthenticationDetailAuthHeader;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMonitorConfigurationReqAuthenticationDetail {
    /**
     * @return List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
     * 
     */
    private List<GetMonitorConfigurationReqAuthenticationDetailAuthHeader> authHeaders;
    /**
     * @return Request method.
     * 
     */
    private String authRequestMethod;
    /**
     * @return Request post body.
     * 
     */
    private String authRequestPostBody;
    /**
     * @return Authentication token.
     * 
     */
    private String authToken;
    /**
     * @return URL to get authentication token.
     * 
     */
    private String authUrl;
    /**
     * @return User name for authentication.
     * 
     */
    private String authUserName;
    /**
     * @return User password for authentication.
     * 
     */
    private String authUserPassword;
    /**
     * @return Request HTTP OAuth scheme.
     * 
     */
    private String oauthScheme;

    private GetMonitorConfigurationReqAuthenticationDetail() {}
    /**
     * @return List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
     * 
     */
    public List<GetMonitorConfigurationReqAuthenticationDetailAuthHeader> authHeaders() {
        return this.authHeaders;
    }
    /**
     * @return Request method.
     * 
     */
    public String authRequestMethod() {
        return this.authRequestMethod;
    }
    /**
     * @return Request post body.
     * 
     */
    public String authRequestPostBody() {
        return this.authRequestPostBody;
    }
    /**
     * @return Authentication token.
     * 
     */
    public String authToken() {
        return this.authToken;
    }
    /**
     * @return URL to get authentication token.
     * 
     */
    public String authUrl() {
        return this.authUrl;
    }
    /**
     * @return User name for authentication.
     * 
     */
    public String authUserName() {
        return this.authUserName;
    }
    /**
     * @return User password for authentication.
     * 
     */
    public String authUserPassword() {
        return this.authUserPassword;
    }
    /**
     * @return Request HTTP OAuth scheme.
     * 
     */
    public String oauthScheme() {
        return this.oauthScheme;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitorConfigurationReqAuthenticationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMonitorConfigurationReqAuthenticationDetailAuthHeader> authHeaders;
        private String authRequestMethod;
        private String authRequestPostBody;
        private String authToken;
        private String authUrl;
        private String authUserName;
        private String authUserPassword;
        private String oauthScheme;
        public Builder() {}
        public Builder(GetMonitorConfigurationReqAuthenticationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authHeaders = defaults.authHeaders;
    	      this.authRequestMethod = defaults.authRequestMethod;
    	      this.authRequestPostBody = defaults.authRequestPostBody;
    	      this.authToken = defaults.authToken;
    	      this.authUrl = defaults.authUrl;
    	      this.authUserName = defaults.authUserName;
    	      this.authUserPassword = defaults.authUserPassword;
    	      this.oauthScheme = defaults.oauthScheme;
        }

        @CustomType.Setter
        public Builder authHeaders(List<GetMonitorConfigurationReqAuthenticationDetailAuthHeader> authHeaders) {
            if (authHeaders == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authHeaders");
            }
            this.authHeaders = authHeaders;
            return this;
        }
        public Builder authHeaders(GetMonitorConfigurationReqAuthenticationDetailAuthHeader... authHeaders) {
            return authHeaders(List.of(authHeaders));
        }
        @CustomType.Setter
        public Builder authRequestMethod(String authRequestMethod) {
            if (authRequestMethod == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authRequestMethod");
            }
            this.authRequestMethod = authRequestMethod;
            return this;
        }
        @CustomType.Setter
        public Builder authRequestPostBody(String authRequestPostBody) {
            if (authRequestPostBody == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authRequestPostBody");
            }
            this.authRequestPostBody = authRequestPostBody;
            return this;
        }
        @CustomType.Setter
        public Builder authToken(String authToken) {
            if (authToken == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authToken");
            }
            this.authToken = authToken;
            return this;
        }
        @CustomType.Setter
        public Builder authUrl(String authUrl) {
            if (authUrl == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authUrl");
            }
            this.authUrl = authUrl;
            return this;
        }
        @CustomType.Setter
        public Builder authUserName(String authUserName) {
            if (authUserName == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authUserName");
            }
            this.authUserName = authUserName;
            return this;
        }
        @CustomType.Setter
        public Builder authUserPassword(String authUserPassword) {
            if (authUserPassword == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "authUserPassword");
            }
            this.authUserPassword = authUserPassword;
            return this;
        }
        @CustomType.Setter
        public Builder oauthScheme(String oauthScheme) {
            if (oauthScheme == null) {
              throw new MissingRequiredPropertyException("GetMonitorConfigurationReqAuthenticationDetail", "oauthScheme");
            }
            this.oauthScheme = oauthScheme;
            return this;
        }
        public GetMonitorConfigurationReqAuthenticationDetail build() {
            final var _resultValue = new GetMonitorConfigurationReqAuthenticationDetail();
            _resultValue.authHeaders = authHeaders;
            _resultValue.authRequestMethod = authRequestMethod;
            _resultValue.authRequestPostBody = authRequestPostBody;
            _resultValue.authToken = authToken;
            _resultValue.authUrl = authUrl;
            _resultValue.authUserName = authUserName;
            _resultValue.authUserPassword = authUserPassword;
            _resultValue.oauthScheme = oauthScheme;
            return _resultValue;
        }
    }
}
