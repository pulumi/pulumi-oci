// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsent {
    /**
     * @return User Token URI
     * 
     */
    private String ref;
    /**
     * @return The value of a X509 certificate.
     * 
     */
    private String value;

    private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsent() {}
    /**
     * @return User Token URI
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return The value of a X509 certificate.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsent defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsent defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ref(String ref) {
            this.ref = Objects.requireNonNull(ref);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsent build() {
            final var o = new GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensiontermsOfUseUserTermsOfUseConsent();
            o.ref = ref;
            o.value = value;
            return o;
        }
    }
}