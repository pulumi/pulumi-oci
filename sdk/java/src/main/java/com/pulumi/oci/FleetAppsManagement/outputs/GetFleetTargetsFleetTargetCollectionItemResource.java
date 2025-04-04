// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFleetTargetsFleetTargetCollectionItemResource {
    /**
     * @return Resource Display Name.
     * 
     */
    private String resourceDisplayName;
    /**
     * @return Resource Identifier
     * 
     */
    private String resourceId;

    private GetFleetTargetsFleetTargetCollectionItemResource() {}
    /**
     * @return Resource Display Name.
     * 
     */
    public String resourceDisplayName() {
        return this.resourceDisplayName;
    }
    /**
     * @return Resource Identifier
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetTargetsFleetTargetCollectionItemResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String resourceDisplayName;
        private String resourceId;
        public Builder() {}
        public Builder(GetFleetTargetsFleetTargetCollectionItemResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.resourceDisplayName = defaults.resourceDisplayName;
    	      this.resourceId = defaults.resourceId;
        }

        @CustomType.Setter
        public Builder resourceDisplayName(String resourceDisplayName) {
            if (resourceDisplayName == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItemResource", "resourceDisplayName");
            }
            this.resourceDisplayName = resourceDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItemResource", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        public GetFleetTargetsFleetTargetCollectionItemResource build() {
            final var _resultValue = new GetFleetTargetsFleetTargetCollectionItemResource();
            _resultValue.resourceDisplayName = resourceDisplayName;
            _resultValue.resourceId = resourceId;
            return _resultValue;
        }
    }
}
