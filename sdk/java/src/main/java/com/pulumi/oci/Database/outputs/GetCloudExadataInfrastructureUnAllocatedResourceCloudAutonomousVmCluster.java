// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cloud Exadata infrastructure.
     * 
     */
    private String id;
    /**
     * @return Total unallocated autonomous data storage in the Cloud Autonomous VM Cluster in TBs.
     * 
     */
    private Double unAllocatedAdbStorageInTbs;

    private GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cloud Exadata infrastructure.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Total unallocated autonomous data storage in the Cloud Autonomous VM Cluster in TBs.
     * 
     */
    public Double unAllocatedAdbStorageInTbs() {
        return this.unAllocatedAdbStorageInTbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private Double unAllocatedAdbStorageInTbs;
        public Builder() {}
        public Builder(GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.unAllocatedAdbStorageInTbs = defaults.unAllocatedAdbStorageInTbs;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder unAllocatedAdbStorageInTbs(Double unAllocatedAdbStorageInTbs) {
            if (unAllocatedAdbStorageInTbs == null) {
              throw new MissingRequiredPropertyException("GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster", "unAllocatedAdbStorageInTbs");
            }
            this.unAllocatedAdbStorageInTbs = unAllocatedAdbStorageInTbs;
            return this;
        }
        public GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster build() {
            final var _resultValue = new GetCloudExadataInfrastructureUnAllocatedResourceCloudAutonomousVmCluster();
            _resultValue.id = id;
            _resultValue.unAllocatedAdbStorageInTbs = unAllocatedAdbStorageInTbs;
            return _resultValue;
        }
    }
}
