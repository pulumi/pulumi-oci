// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential {
    /**
     * @return Ocid of the User&#39;s Support Account.
     * 
     */
    private String ocid;
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

    private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential() {}
    /**
     * @return Ocid of the User&#39;s Support Account.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
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

    public static Builder builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ocid;
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ocid(String ocid) {
            this.ocid = Objects.requireNonNull(ocid);
            return this;
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
        public GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential build() {
            final var o = new GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential();
            o.ocid = ocid;
            o.ref = ref;
            o.value = value;
            return o;
        }
    }
}