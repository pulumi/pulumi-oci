// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationInstanceDetailSecondaryVnic {
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    private List<GetInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    private Integer nicIndex;

    private GetInstanceConfigurationInstanceDetailSecondaryVnic() {}
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails() {
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

    public static Builder builder(GetInstanceConfigurationInstanceDetailSecondaryVnic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails;
        private String displayName;
        private Integer nicIndex;
        public Builder() {}
        public Builder(GetInstanceConfigurationInstanceDetailSecondaryVnic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.createVnicDetails = defaults.createVnicDetails;
    	      this.displayName = defaults.displayName;
    	      this.nicIndex = defaults.nicIndex;
        }

        @CustomType.Setter
        public Builder createVnicDetails(List<GetInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail> createVnicDetails) {
            if (createVnicDetails == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailSecondaryVnic", "createVnicDetails");
            }
            this.createVnicDetails = createVnicDetails;
            return this;
        }
        public Builder createVnicDetails(GetInstanceConfigurationInstanceDetailSecondaryVnicCreateVnicDetail... createVnicDetails) {
            return createVnicDetails(List.of(createVnicDetails));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailSecondaryVnic", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder nicIndex(Integer nicIndex) {
            if (nicIndex == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailSecondaryVnic", "nicIndex");
            }
            this.nicIndex = nicIndex;
            return this;
        }
        public GetInstanceConfigurationInstanceDetailSecondaryVnic build() {
            final var _resultValue = new GetInstanceConfigurationInstanceDetailSecondaryVnic();
            _resultValue.createVnicDetails = createVnicDetails;
            _resultValue.displayName = displayName;
            _resultValue.nicIndex = nicIndex;
            return _resultValue;
        }
    }
}
