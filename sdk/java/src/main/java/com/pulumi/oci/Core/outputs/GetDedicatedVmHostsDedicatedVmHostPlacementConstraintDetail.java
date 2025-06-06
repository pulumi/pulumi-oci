// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail {
    /**
     * @return The OCID of the compute bare metal host.
     * 
     */
    private String computeBareMetalHostId;
    /**
     * @return Determines the type of targeted launch.
     * 
     */
    private String type;

    private GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail() {}
    /**
     * @return The OCID of the compute bare metal host.
     * 
     */
    public String computeBareMetalHostId() {
        return this.computeBareMetalHostId;
    }
    /**
     * @return Determines the type of targeted launch.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String computeBareMetalHostId;
        private String type;
        public Builder() {}
        public Builder(GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.computeBareMetalHostId = defaults.computeBareMetalHostId;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder computeBareMetalHostId(String computeBareMetalHostId) {
            if (computeBareMetalHostId == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail", "computeBareMetalHostId");
            }
            this.computeBareMetalHostId = computeBareMetalHostId;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail", "type");
            }
            this.type = type;
            return this;
        }
        public GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail build() {
            final var _resultValue = new GetDedicatedVmHostsDedicatedVmHostPlacementConstraintDetail();
            _resultValue.computeBareMetalHostId = computeBareMetalHostId;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
