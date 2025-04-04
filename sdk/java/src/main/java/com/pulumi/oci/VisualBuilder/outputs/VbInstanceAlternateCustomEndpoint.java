// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VbInstanceAlternateCustomEndpoint {
    /**
     * @return (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
     * 
     */
    private @Nullable String certificateSecretId;
    /**
     * @return The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
     * 
     */
    private @Nullable Integer certificateSecretVersion;
    /**
     * @return (Updatable) A custom hostname to be used for the vb instance URL, in FQDN format.
     * 
     */
    private String hostname;

    private VbInstanceAlternateCustomEndpoint() {}
    /**
     * @return (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
     * 
     */
    public Optional<String> certificateSecretId() {
        return Optional.ofNullable(this.certificateSecretId);
    }
    /**
     * @return The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
     * 
     */
    public Optional<Integer> certificateSecretVersion() {
        return Optional.ofNullable(this.certificateSecretVersion);
    }
    /**
     * @return (Updatable) A custom hostname to be used for the vb instance URL, in FQDN format.
     * 
     */
    public String hostname() {
        return this.hostname;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VbInstanceAlternateCustomEndpoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String certificateSecretId;
        private @Nullable Integer certificateSecretVersion;
        private String hostname;
        public Builder() {}
        public Builder(VbInstanceAlternateCustomEndpoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateSecretId = defaults.certificateSecretId;
    	      this.certificateSecretVersion = defaults.certificateSecretVersion;
    	      this.hostname = defaults.hostname;
        }

        @CustomType.Setter
        public Builder certificateSecretId(@Nullable String certificateSecretId) {

            this.certificateSecretId = certificateSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder certificateSecretVersion(@Nullable Integer certificateSecretVersion) {

            this.certificateSecretVersion = certificateSecretVersion;
            return this;
        }
        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("VbInstanceAlternateCustomEndpoint", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        public VbInstanceAlternateCustomEndpoint build() {
            final var _resultValue = new VbInstanceAlternateCustomEndpoint();
            _resultValue.certificateSecretId = certificateSecretId;
            _resultValue.certificateSecretVersion = certificateSecretVersion;
            _resultValue.hostname = hostname;
            return _resultValue;
        }
    }
}
