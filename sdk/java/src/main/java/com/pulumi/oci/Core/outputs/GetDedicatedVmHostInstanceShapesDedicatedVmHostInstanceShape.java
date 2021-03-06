// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShape {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The name of the virtual machine instance shapes that can be launched on a dedicated VM host.
     * 
     */
    private final String instanceShapeName;

    @CustomType.Constructor
    private GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShape(
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("instanceShapeName") String instanceShapeName) {
        this.availabilityDomain = availabilityDomain;
        this.instanceShapeName = instanceShapeName;
    }

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The name of the virtual machine instance shapes that can be launched on a dedicated VM host.
     * 
     */
    public String instanceShapeName() {
        return this.instanceShapeName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShape defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String availabilityDomain;
        private String instanceShapeName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShape defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.instanceShapeName = defaults.instanceShapeName;
        }

        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder instanceShapeName(String instanceShapeName) {
            this.instanceShapeName = Objects.requireNonNull(instanceShapeName);
            return this;
        }        public GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShape build() {
            return new GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShape(availabilityDomain, instanceShapeName);
        }
    }
}
