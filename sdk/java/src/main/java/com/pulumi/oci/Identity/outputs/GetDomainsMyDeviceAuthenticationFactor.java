// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyDeviceAuthenticationFactor {
    /**
     * @return Authentication Factor public key issued by client
     * 
     */
    private String publicKey;
    /**
     * @return Device Status
     * 
     */
    private String status;
    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    private String type;

    private GetDomainsMyDeviceAuthenticationFactor() {}
    /**
     * @return Authentication Factor public key issued by client
     * 
     */
    public String publicKey() {
        return this.publicKey;
    }
    /**
     * @return Device Status
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyDeviceAuthenticationFactor defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String publicKey;
        private String status;
        private String type;
        public Builder() {}
        public Builder(GetDomainsMyDeviceAuthenticationFactor defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.publicKey = defaults.publicKey;
    	      this.status = defaults.status;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder publicKey(String publicKey) {
            this.publicKey = Objects.requireNonNull(publicKey);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetDomainsMyDeviceAuthenticationFactor build() {
            final var o = new GetDomainsMyDeviceAuthenticationFactor();
            o.publicKey = publicKey;
            o.status = status;
            o.type = type;
            return o;
        }
    }
}