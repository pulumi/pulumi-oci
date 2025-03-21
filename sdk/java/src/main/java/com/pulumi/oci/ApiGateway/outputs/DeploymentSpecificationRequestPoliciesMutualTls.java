// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRequestPoliciesMutualTls {
    /**
     * @return (Updatable) Allowed list of CN or SAN which will be used for verification of certificate.
     * 
     */
    private @Nullable List<String> allowedSans;
    /**
     * @return (Updatable) Determines whether to enable client verification when API Consumer makes connection to the gateway.
     * 
     */
    private @Nullable Boolean isVerifiedCertificateRequired;

    private DeploymentSpecificationRequestPoliciesMutualTls() {}
    /**
     * @return (Updatable) Allowed list of CN or SAN which will be used for verification of certificate.
     * 
     */
    public List<String> allowedSans() {
        return this.allowedSans == null ? List.of() : this.allowedSans;
    }
    /**
     * @return (Updatable) Determines whether to enable client verification when API Consumer makes connection to the gateway.
     * 
     */
    public Optional<Boolean> isVerifiedCertificateRequired() {
        return Optional.ofNullable(this.isVerifiedCertificateRequired);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRequestPoliciesMutualTls defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> allowedSans;
        private @Nullable Boolean isVerifiedCertificateRequired;
        public Builder() {}
        public Builder(DeploymentSpecificationRequestPoliciesMutualTls defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedSans = defaults.allowedSans;
    	      this.isVerifiedCertificateRequired = defaults.isVerifiedCertificateRequired;
        }

        @CustomType.Setter
        public Builder allowedSans(@Nullable List<String> allowedSans) {

            this.allowedSans = allowedSans;
            return this;
        }
        public Builder allowedSans(String... allowedSans) {
            return allowedSans(List.of(allowedSans));
        }
        @CustomType.Setter
        public Builder isVerifiedCertificateRequired(@Nullable Boolean isVerifiedCertificateRequired) {

            this.isVerifiedCertificateRequired = isVerifiedCertificateRequired;
            return this;
        }
        public DeploymentSpecificationRequestPoliciesMutualTls build() {
            final var _resultValue = new DeploymentSpecificationRequestPoliciesMutualTls();
            _resultValue.allowedSans = allowedSans;
            _resultValue.isVerifiedCertificateRequired = isVerifiedCertificateRequired;
            return _resultValue;
        }
    }
}
