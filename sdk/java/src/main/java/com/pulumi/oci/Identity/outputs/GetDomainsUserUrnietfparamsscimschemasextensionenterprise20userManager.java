// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUserUrnietfparamsscimschemasextensionenterprise20userManager {
    /**
     * @return The displayName of the User&#39;s manager. OPTIONAL and READ-ONLY.
     * 
     */
    private String displayName;
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

    private GetDomainsUserUrnietfparamsscimschemasextensionenterprise20userManager() {}
    /**
     * @return The displayName of the User&#39;s manager. OPTIONAL and READ-ONLY.
     * 
     */
    public String displayName() {
        return this.displayName;
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

    public static Builder builder(GetDomainsUserUrnietfparamsscimschemasextensionenterprise20userManager defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsUserUrnietfparamsscimschemasextensionenterprise20userManager defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
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
        public GetDomainsUserUrnietfparamsscimschemasextensionenterprise20userManager build() {
            final var o = new GetDomainsUserUrnietfparamsscimschemasextensionenterprise20userManager();
            o.displayName = displayName;
            o.ref = ref;
            o.value = value;
            return o;
        }
    }
}