// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class ConnectionTlsVerifyConfig {
    /**
     * @return (Updatable) The OCID of Oracle Cloud Infrastructure certificate service CA bundle.
     * 
     */
    private String caCertificateBundleId;
    /**
     * @return (Updatable) The type of TLS verification.
     * 
     */
    private String tlsVerifyMode;

    private ConnectionTlsVerifyConfig() {}
    /**
     * @return (Updatable) The OCID of Oracle Cloud Infrastructure certificate service CA bundle.
     * 
     */
    public String caCertificateBundleId() {
        return this.caCertificateBundleId;
    }
    /**
     * @return (Updatable) The type of TLS verification.
     * 
     */
    public String tlsVerifyMode() {
        return this.tlsVerifyMode;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConnectionTlsVerifyConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String caCertificateBundleId;
        private String tlsVerifyMode;
        public Builder() {}
        public Builder(ConnectionTlsVerifyConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.caCertificateBundleId = defaults.caCertificateBundleId;
    	      this.tlsVerifyMode = defaults.tlsVerifyMode;
        }

        @CustomType.Setter
        public Builder caCertificateBundleId(String caCertificateBundleId) {
            this.caCertificateBundleId = Objects.requireNonNull(caCertificateBundleId);
            return this;
        }
        @CustomType.Setter
        public Builder tlsVerifyMode(String tlsVerifyMode) {
            this.tlsVerifyMode = Objects.requireNonNull(tlsVerifyMode);
            return this;
        }
        public ConnectionTlsVerifyConfig build() {
            final var o = new ConnectionTlsVerifyConfig();
            o.caCertificateBundleId = caCertificateBundleId;
            o.tlsVerifyMode = tlsVerifyMode;
            return o;
        }
    }
}