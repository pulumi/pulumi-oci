// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceInstanceOptions {
    /**
     * @return (Updatable) Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
     * 
     */
    private @Nullable Boolean areLegacyImdsEndpointsDisabled;

    private InstanceInstanceOptions() {}
    /**
     * @return (Updatable) Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
     * 
     */
    public Optional<Boolean> areLegacyImdsEndpointsDisabled() {
        return Optional.ofNullable(this.areLegacyImdsEndpointsDisabled);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceInstanceOptions defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean areLegacyImdsEndpointsDisabled;
        public Builder() {}
        public Builder(InstanceInstanceOptions defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areLegacyImdsEndpointsDisabled = defaults.areLegacyImdsEndpointsDisabled;
        }

        @CustomType.Setter
        public Builder areLegacyImdsEndpointsDisabled(@Nullable Boolean areLegacyImdsEndpointsDisabled) {
            this.areLegacyImdsEndpointsDisabled = areLegacyImdsEndpointsDisabled;
            return this;
        }
        public InstanceInstanceOptions build() {
            final var o = new InstanceInstanceOptions();
            o.areLegacyImdsEndpointsDisabled = areLegacyImdsEndpointsDisabled;
            return o;
        }
    }
}