// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.InstanceConfigurationInstanceDetailsOptionSecondaryVnicCreateVnicDetailsArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs extends com.pulumi.resources.ResourceArgs {

    public static final InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs Empty = new InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs();

    /**
     * Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    @Import(name="createVnicDetails")
    private @Nullable Output<InstanceConfigurationInstanceDetailsOptionSecondaryVnicCreateVnicDetailsArgs> createVnicDetails;

    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    public Optional<Output<InstanceConfigurationInstanceDetailsOptionSecondaryVnicCreateVnicDetailsArgs>> createVnicDetails() {
        return Optional.ofNullable(this.createVnicDetails);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    @Import(name="nicIndex")
    private @Nullable Output<Integer> nicIndex;

    /**
     * @return Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    public Optional<Output<Integer>> nicIndex() {
        return Optional.ofNullable(this.nicIndex);
    }

    private InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs() {}

    private InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs(InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs $) {
        this.createVnicDetails = $.createVnicDetails;
        this.displayName = $.displayName;
        this.nicIndex = $.nicIndex;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs $;

        public Builder() {
            $ = new InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs();
        }

        public Builder(InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs defaults) {
            $ = new InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param createVnicDetails Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
         * 
         * @return builder
         * 
         */
        public Builder createVnicDetails(@Nullable Output<InstanceConfigurationInstanceDetailsOptionSecondaryVnicCreateVnicDetailsArgs> createVnicDetails) {
            $.createVnicDetails = createVnicDetails;
            return this;
        }

        /**
         * @param createVnicDetails Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
         * 
         * @return builder
         * 
         */
        public Builder createVnicDetails(InstanceConfigurationInstanceDetailsOptionSecondaryVnicCreateVnicDetailsArgs createVnicDetails) {
            return createVnicDetails(Output.of(createVnicDetails));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param nicIndex Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
         * 
         * @return builder
         * 
         */
        public Builder nicIndex(@Nullable Output<Integer> nicIndex) {
            $.nicIndex = nicIndex;
            return this;
        }

        /**
         * @param nicIndex Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
         * 
         * @return builder
         * 
         */
        public Builder nicIndex(Integer nicIndex) {
            return nicIndex(Output.of(nicIndex));
        }

        public InstanceConfigurationInstanceDetailsOptionSecondaryVnicArgs build() {
            return $;
        }
    }

}