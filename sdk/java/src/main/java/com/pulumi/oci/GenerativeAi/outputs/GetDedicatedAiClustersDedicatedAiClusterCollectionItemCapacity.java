// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity {
    private String capacityType;
    private Integer totalEndpointCapacity;
    private Integer usedEndpointCapacity;

    private GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity() {}
    public String capacityType() {
        return this.capacityType;
    }
    public Integer totalEndpointCapacity() {
        return this.totalEndpointCapacity;
    }
    public Integer usedEndpointCapacity() {
        return this.usedEndpointCapacity;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String capacityType;
        private Integer totalEndpointCapacity;
        private Integer usedEndpointCapacity;
        public Builder() {}
        public Builder(GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.capacityType = defaults.capacityType;
    	      this.totalEndpointCapacity = defaults.totalEndpointCapacity;
    	      this.usedEndpointCapacity = defaults.usedEndpointCapacity;
        }

        @CustomType.Setter
        public Builder capacityType(String capacityType) {
            if (capacityType == null) {
              throw new MissingRequiredPropertyException("GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity", "capacityType");
            }
            this.capacityType = capacityType;
            return this;
        }
        @CustomType.Setter
        public Builder totalEndpointCapacity(Integer totalEndpointCapacity) {
            if (totalEndpointCapacity == null) {
              throw new MissingRequiredPropertyException("GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity", "totalEndpointCapacity");
            }
            this.totalEndpointCapacity = totalEndpointCapacity;
            return this;
        }
        @CustomType.Setter
        public Builder usedEndpointCapacity(Integer usedEndpointCapacity) {
            if (usedEndpointCapacity == null) {
              throw new MissingRequiredPropertyException("GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity", "usedEndpointCapacity");
            }
            this.usedEndpointCapacity = usedEndpointCapacity;
            return this;
        }
        public GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity build() {
            final var _resultValue = new GetDedicatedAiClustersDedicatedAiClusterCollectionItemCapacity();
            _resultValue.capacityType = capacityType;
            _resultValue.totalEndpointCapacity = totalEndpointCapacity;
            _resultValue.usedEndpointCapacity = usedEndpointCapacity;
            return _resultValue;
        }
    }
}
