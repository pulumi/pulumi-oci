// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsIdentityProvidersIdentityProviderCorrelationPolicy {
    /**
     * @return A human readable name, primarily used for display purposes. READ-ONLY.
     * 
     */
    private String display;
    /**
     * @return Group URI
     * 
     */
    private String ref;
    /**
     * @return Identity Provider Type
     * 
     */
    private String type;
    /**
     * @return Value of the tag.
     * 
     */
    private String value;

    private GetDomainsIdentityProvidersIdentityProviderCorrelationPolicy() {}
    /**
     * @return A human readable name, primarily used for display purposes. READ-ONLY.
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return Group URI
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return Identity Provider Type
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Value of the tag.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsIdentityProvidersIdentityProviderCorrelationPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(GetDomainsIdentityProvidersIdentityProviderCorrelationPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
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
        public GetDomainsIdentityProvidersIdentityProviderCorrelationPolicy build() {
            final var o = new GetDomainsIdentityProvidersIdentityProviderCorrelationPolicy();
            o.display = display;
            o.ref = ref;
            o.type = type;
            o.value = value;
            return o;
        }
    }
}