// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsIdentityProviderJitUserProvGroupMapping {
    /**
     * @return (Updatable) IDP Group Name
     * 
     */
    private String idpGroup;
    /**
     * @return (Updatable) Group URI
     * 
     */
    private @Nullable String ref;
    /**
     * @return (Updatable) Value of the tag.
     * 
     */
    private String value;

    private DomainsIdentityProviderJitUserProvGroupMapping() {}
    /**
     * @return (Updatable) IDP Group Name
     * 
     */
    public String idpGroup() {
        return this.idpGroup;
    }
    /**
     * @return (Updatable) Group URI
     * 
     */
    public Optional<String> ref() {
        return Optional.ofNullable(this.ref);
    }
    /**
     * @return (Updatable) Value of the tag.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsIdentityProviderJitUserProvGroupMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String idpGroup;
        private @Nullable String ref;
        private String value;
        public Builder() {}
        public Builder(DomainsIdentityProviderJitUserProvGroupMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.idpGroup = defaults.idpGroup;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder idpGroup(String idpGroup) {
            this.idpGroup = Objects.requireNonNull(idpGroup);
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public DomainsIdentityProviderJitUserProvGroupMapping build() {
            final var o = new DomainsIdentityProviderJitUserProvGroupMapping();
            o.idpGroup = idpGroup;
            o.ref = ref;
            o.value = value;
            return o;
        }
    }
}