// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetGatewayResponseCacheDetailServer;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetGatewayResponseCacheDetail {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Vault Service secret resource.
     * 
     */
    private String authenticationSecretId;
    /**
     * @return The version number of the authentication secret to use.
     * 
     */
    private String authenticationSecretVersionNumber;
    /**
     * @return Defines the timeout for establishing a connection with the Response Cache.
     * 
     */
    private Integer connectTimeoutInMs;
    /**
     * @return Defines if the connection should be over SSL.
     * 
     */
    private Boolean isSslEnabled;
    /**
     * @return Defines whether or not to uphold SSL verification.
     * 
     */
    private Boolean isSslVerifyDisabled;
    /**
     * @return Defines the timeout for reading data from the Response Cache.
     * 
     */
    private Integer readTimeoutInMs;
    /**
     * @return Defines the timeout for transmitting data to the Response Cache.
     * 
     */
    private Integer sendTimeoutInMs;
    /**
     * @return The set of cache store members to connect to. At present only a single server is supported.
     * 
     */
    private List<GetGatewayResponseCacheDetailServer> servers;
    /**
     * @return Type of the Response Cache.
     * 
     */
    private String type;

    private GetGatewayResponseCacheDetail() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Vault Service secret resource.
     * 
     */
    public String authenticationSecretId() {
        return this.authenticationSecretId;
    }
    /**
     * @return The version number of the authentication secret to use.
     * 
     */
    public String authenticationSecretVersionNumber() {
        return this.authenticationSecretVersionNumber;
    }
    /**
     * @return Defines the timeout for establishing a connection with the Response Cache.
     * 
     */
    public Integer connectTimeoutInMs() {
        return this.connectTimeoutInMs;
    }
    /**
     * @return Defines if the connection should be over SSL.
     * 
     */
    public Boolean isSslEnabled() {
        return this.isSslEnabled;
    }
    /**
     * @return Defines whether or not to uphold SSL verification.
     * 
     */
    public Boolean isSslVerifyDisabled() {
        return this.isSslVerifyDisabled;
    }
    /**
     * @return Defines the timeout for reading data from the Response Cache.
     * 
     */
    public Integer readTimeoutInMs() {
        return this.readTimeoutInMs;
    }
    /**
     * @return Defines the timeout for transmitting data to the Response Cache.
     * 
     */
    public Integer sendTimeoutInMs() {
        return this.sendTimeoutInMs;
    }
    /**
     * @return The set of cache store members to connect to. At present only a single server is supported.
     * 
     */
    public List<GetGatewayResponseCacheDetailServer> servers() {
        return this.servers;
    }
    /**
     * @return Type of the Response Cache.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGatewayResponseCacheDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String authenticationSecretId;
        private String authenticationSecretVersionNumber;
        private Integer connectTimeoutInMs;
        private Boolean isSslEnabled;
        private Boolean isSslVerifyDisabled;
        private Integer readTimeoutInMs;
        private Integer sendTimeoutInMs;
        private List<GetGatewayResponseCacheDetailServer> servers;
        private String type;
        public Builder() {}
        public Builder(GetGatewayResponseCacheDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authenticationSecretId = defaults.authenticationSecretId;
    	      this.authenticationSecretVersionNumber = defaults.authenticationSecretVersionNumber;
    	      this.connectTimeoutInMs = defaults.connectTimeoutInMs;
    	      this.isSslEnabled = defaults.isSslEnabled;
    	      this.isSslVerifyDisabled = defaults.isSslVerifyDisabled;
    	      this.readTimeoutInMs = defaults.readTimeoutInMs;
    	      this.sendTimeoutInMs = defaults.sendTimeoutInMs;
    	      this.servers = defaults.servers;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder authenticationSecretId(String authenticationSecretId) {
            this.authenticationSecretId = Objects.requireNonNull(authenticationSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder authenticationSecretVersionNumber(String authenticationSecretVersionNumber) {
            this.authenticationSecretVersionNumber = Objects.requireNonNull(authenticationSecretVersionNumber);
            return this;
        }
        @CustomType.Setter
        public Builder connectTimeoutInMs(Integer connectTimeoutInMs) {
            this.connectTimeoutInMs = Objects.requireNonNull(connectTimeoutInMs);
            return this;
        }
        @CustomType.Setter
        public Builder isSslEnabled(Boolean isSslEnabled) {
            this.isSslEnabled = Objects.requireNonNull(isSslEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder isSslVerifyDisabled(Boolean isSslVerifyDisabled) {
            this.isSslVerifyDisabled = Objects.requireNonNull(isSslVerifyDisabled);
            return this;
        }
        @CustomType.Setter
        public Builder readTimeoutInMs(Integer readTimeoutInMs) {
            this.readTimeoutInMs = Objects.requireNonNull(readTimeoutInMs);
            return this;
        }
        @CustomType.Setter
        public Builder sendTimeoutInMs(Integer sendTimeoutInMs) {
            this.sendTimeoutInMs = Objects.requireNonNull(sendTimeoutInMs);
            return this;
        }
        @CustomType.Setter
        public Builder servers(List<GetGatewayResponseCacheDetailServer> servers) {
            this.servers = Objects.requireNonNull(servers);
            return this;
        }
        public Builder servers(GetGatewayResponseCacheDetailServer... servers) {
            return servers(List.of(servers));
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetGatewayResponseCacheDetail build() {
            final var o = new GetGatewayResponseCacheDetail();
            o.authenticationSecretId = authenticationSecretId;
            o.authenticationSecretVersionNumber = authenticationSecretVersionNumber;
            o.connectTimeoutInMs = connectTimeoutInMs;
            o.isSslEnabled = isSslEnabled;
            o.isSslVerifyDisabled = isSslVerifyDisabled;
            o.readTimeoutInMs = readTimeoutInMs;
            o.sendTimeoutInMs = sendTimeoutInMs;
            o.servers = servers;
            o.type = type;
            return o;
        }
    }
}