// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab {
    /**
     * @return The OCID of the secret. The secret content corresponding to the OCID is expected to be in Base64 encoded content type.
     * 
     */
    private String secretOcid;
    /**
     * @return The version of the secret. When the version is not specified, then the latest secret version is used during runtime.
     * 
     */
    private Integer secretVersion;

    private GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab() {}
    /**
     * @return The OCID of the secret. The secret content corresponding to the OCID is expected to be in Base64 encoded content type.
     * 
     */
    public String secretOcid() {
        return this.secretOcid;
    }
    /**
     * @return The version of the secret. When the version is not specified, then the latest secret version is used during runtime.
     * 
     */
    public Integer secretVersion() {
        return this.secretVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String secretOcid;
        private Integer secretVersion;
        public Builder() {}
        public Builder(GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.secretOcid = defaults.secretOcid;
    	      this.secretVersion = defaults.secretVersion;
        }

        @CustomType.Setter
        public Builder secretOcid(String secretOcid) {
            if (secretOcid == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab", "secretOcid");
            }
            this.secretOcid = secretOcid;
            return this;
        }
        @CustomType.Setter
        public Builder secretVersion(Integer secretVersion) {
            if (secretVersion == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab", "secretVersion");
            }
            this.secretVersion = secretVersion;
            return this;
        }
        public GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab build() {
            final var _resultValue = new GetDomainsIdentityPropagationTrustsIdentityPropagationTrustKeytab();
            _resultValue.secretOcid = secretOcid;
            _resultValue.secretVersion = secretVersion;
            return _resultValue;
        }
    }
}
