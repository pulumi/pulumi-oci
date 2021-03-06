// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic {
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    private final List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    private final Integer nicIndex;

    @CustomType.Constructor
    private GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic(
        @CustomType.Parameter("createVnicDetails") List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("nicIndex") Integer nicIndex) {
        this.createVnicDetails = createVnicDetails;
        this.displayName = displayName;
        this.nicIndex = nicIndex;
    }

    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    public List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails() {
        return this.createVnicDetails;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    public Integer nicIndex() {
        return this.nicIndex;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails;
        private String displayName;
        private Integer nicIndex;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.createVnicDetails = defaults.createVnicDetails;
    	      this.displayName = defaults.displayName;
    	      this.nicIndex = defaults.nicIndex;
        }

        public Builder createVnicDetails(List<GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails) {
            this.createVnicDetails = Objects.requireNonNull(createVnicDetails);
            return this;
        }
        public Builder createVnicDetails(GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail... createVnicDetails) {
            return createVnicDetails(List.of(createVnicDetails));
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder nicIndex(Integer nicIndex) {
            this.nicIndex = Objects.requireNonNull(nicIndex);
            return this;
        }        public GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic build() {
            return new GetInstanceConfigurationsInstanceConfigurationInstanceDetailSecondaryVnic(createVnicDetails, displayName, nicIndex);
        }
    }
}
