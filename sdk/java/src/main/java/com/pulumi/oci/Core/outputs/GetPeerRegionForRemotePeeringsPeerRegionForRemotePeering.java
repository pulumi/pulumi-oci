// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPeerRegionForRemotePeeringsPeerRegionForRemotePeering {
    /**
     * @return The region&#39;s name.  Example: `us-phoenix-1`
     * 
     */
    private final String name;

    @CustomType.Constructor
    private GetPeerRegionForRemotePeeringsPeerRegionForRemotePeering(@CustomType.Parameter("name") String name) {
        this.name = name;
    }

    /**
     * @return The region&#39;s name.  Example: `us-phoenix-1`
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPeerRegionForRemotePeeringsPeerRegionForRemotePeering defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetPeerRegionForRemotePeeringsPeerRegionForRemotePeering defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }        public GetPeerRegionForRemotePeeringsPeerRegionForRemotePeering build() {
            return new GetPeerRegionForRemotePeeringsPeerRegionForRemotePeering(name);
        }
    }
}
