// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class VirtualServiceDefaultRoutingPolicy {
    /**
     * @return (Updatable) Type of the virtual service routing policy.
     * 
     */
    private String type;

    private VirtualServiceDefaultRoutingPolicy() {}
    /**
     * @return (Updatable) Type of the virtual service routing policy.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VirtualServiceDefaultRoutingPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String type;
        public Builder() {}
        public Builder(VirtualServiceDefaultRoutingPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public VirtualServiceDefaultRoutingPolicy build() {
            final var o = new VirtualServiceDefaultRoutingPolicy();
            o.type = type;
            return o;
        }
    }
}