// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyTrustedUserAgentIdcsCreatedBy {
    /**
     * @return Friendly name of the User to be used for purposes of display.
     * 
     */
    private String display;
    /**
     * @return The OCID of the user
     * 
     */
    private String ocid;
    /**
     * @return Full URI to the user for whom the trust-token was issued.
     * 
     */
    private String ref;
    /**
     * @return Trusted Factor
     * 
     */
    private String type;
    /**
     * @return The SCIM ID of the user for whom the trust-token was issued.
     * 
     */
    private String value;

    private GetDomainsMyTrustedUserAgentIdcsCreatedBy() {}
    /**
     * @return Friendly name of the User to be used for purposes of display.
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return The OCID of the user
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return Full URI to the user for whom the trust-token was issued.
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return Trusted Factor
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The SCIM ID of the user for whom the trust-token was issued.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyTrustedUserAgentIdcsCreatedBy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String ocid;
        private String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(GetDomainsMyTrustedUserAgentIdcsCreatedBy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(String display) {
            this.display = Objects.requireNonNull(display);
            return this;
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
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsMyTrustedUserAgentIdcsCreatedBy build() {
            final var o = new GetDomainsMyTrustedUserAgentIdcsCreatedBy();
            o.display = display;
            o.ocid = ocid;
            o.ref = ref;
            o.type = type;
            o.value = value;
            return o;
        }
    }
}