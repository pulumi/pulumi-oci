// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ClusterPlacementGroups.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetClusterPlacementGroupCapabilityItem {
    /**
     * @return The user-friendly name of the cluster placement group. The display name for a cluster placement must be unique and you cannot change it. Avoid entering confidential information.
     * 
     */
    private String name;
    /**
     * @return The service that the resource is part of.
     * 
     */
    private String service;

    private GetClusterPlacementGroupCapabilityItem() {}
    /**
     * @return The user-friendly name of the cluster placement group. The display name for a cluster placement must be unique and you cannot change it. Avoid entering confidential information.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The service that the resource is part of.
     * 
     */
    public String service() {
        return this.service;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClusterPlacementGroupCapabilityItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String service;
        public Builder() {}
        public Builder(GetClusterPlacementGroupCapabilityItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.service = defaults.service;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetClusterPlacementGroupCapabilityItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder service(String service) {
            if (service == null) {
              throw new MissingRequiredPropertyException("GetClusterPlacementGroupCapabilityItem", "service");
            }
            this.service = service;
            return this;
        }
        public GetClusterPlacementGroupCapabilityItem build() {
            final var _resultValue = new GetClusterPlacementGroupCapabilityItem();
            _resultValue.name = name;
            _resultValue.service = service;
            return _resultValue;
        }
    }
}
