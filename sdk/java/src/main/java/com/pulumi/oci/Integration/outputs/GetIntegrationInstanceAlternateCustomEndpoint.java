// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Integration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIntegrationInstanceAlternateCustomEndpoint {
    /**
     * @return When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
     * 
     */
    private String alias;
    /**
     * @return Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
     * 
     */
    private String certificateSecretId;
    /**
     * @return The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
     * 
     */
    private Integer certificateSecretVersion;
    /**
     * @return A custom hostname to be used for the integration instance URL, in FQDN format.
     * 
     */
    private String hostname;

    private GetIntegrationInstanceAlternateCustomEndpoint() {}
    /**
     * @return When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
     * 
     */
    public String alias() {
        return this.alias;
    }
    /**
     * @return Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
     * 
     */
    public String certificateSecretId() {
        return this.certificateSecretId;
    }
    /**
     * @return The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
     * 
     */
    public Integer certificateSecretVersion() {
        return this.certificateSecretVersion;
    }
    /**
     * @return A custom hostname to be used for the integration instance URL, in FQDN format.
     * 
     */
    public String hostname() {
        return this.hostname;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIntegrationInstanceAlternateCustomEndpoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String alias;
        private String certificateSecretId;
        private Integer certificateSecretVersion;
        private String hostname;
        public Builder() {}
        public Builder(GetIntegrationInstanceAlternateCustomEndpoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alias = defaults.alias;
    	      this.certificateSecretId = defaults.certificateSecretId;
    	      this.certificateSecretVersion = defaults.certificateSecretVersion;
    	      this.hostname = defaults.hostname;
        }

        @CustomType.Setter
        public Builder alias(String alias) {
            if (alias == null) {
              throw new MissingRequiredPropertyException("GetIntegrationInstanceAlternateCustomEndpoint", "alias");
            }
            this.alias = alias;
            return this;
        }
        @CustomType.Setter
        public Builder certificateSecretId(String certificateSecretId) {
            if (certificateSecretId == null) {
              throw new MissingRequiredPropertyException("GetIntegrationInstanceAlternateCustomEndpoint", "certificateSecretId");
            }
            this.certificateSecretId = certificateSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder certificateSecretVersion(Integer certificateSecretVersion) {
            if (certificateSecretVersion == null) {
              throw new MissingRequiredPropertyException("GetIntegrationInstanceAlternateCustomEndpoint", "certificateSecretVersion");
            }
            this.certificateSecretVersion = certificateSecretVersion;
            return this;
        }
        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("GetIntegrationInstanceAlternateCustomEndpoint", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        public GetIntegrationInstanceAlternateCustomEndpoint build() {
            final var _resultValue = new GetIntegrationInstanceAlternateCustomEndpoint();
            _resultValue.alias = alias;
            _resultValue.certificateSecretId = certificateSecretId;
            _resultValue.certificateSecretVersion = certificateSecretVersion;
            _resultValue.hostname = hostname;
            return _resultValue;
        }
    }
}
