// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class VirtualNodePoolPlacementConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final VirtualNodePoolPlacementConfigurationArgs Empty = new VirtualNodePoolPlacementConfigurationArgs();

    /**
     * (Updatable) The availability domain in which to place virtual nodes. Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return (Updatable) The availability domain in which to place virtual nodes. Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) The fault domain of this virtual node.
     * 
     */
    @Import(name="faultDomains", required=true)
    private Output<List<String>> faultDomains;

    /**
     * @return (Updatable) The fault domain of this virtual node.
     * 
     */
    public Output<List<String>> faultDomains() {
        return this.faultDomains;
    }

    /**
     * (Updatable) The OCID of the subnet in which to place virtual nodes.
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return (Updatable) The OCID of the subnet in which to place virtual nodes.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private VirtualNodePoolPlacementConfigurationArgs() {}

    private VirtualNodePoolPlacementConfigurationArgs(VirtualNodePoolPlacementConfigurationArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.faultDomains = $.faultDomains;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VirtualNodePoolPlacementConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VirtualNodePoolPlacementConfigurationArgs $;

        public Builder() {
            $ = new VirtualNodePoolPlacementConfigurationArgs();
        }

        public Builder(VirtualNodePoolPlacementConfigurationArgs defaults) {
            $ = new VirtualNodePoolPlacementConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain in which to place virtual nodes. Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain (Updatable) The availability domain in which to place virtual nodes. Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param faultDomains (Updatable) The fault domain of this virtual node.
         * 
         * @return builder
         * 
         */
        public Builder faultDomains(Output<List<String>> faultDomains) {
            $.faultDomains = faultDomains;
            return this;
        }

        /**
         * @param faultDomains (Updatable) The fault domain of this virtual node.
         * 
         * @return builder
         * 
         */
        public Builder faultDomains(List<String> faultDomains) {
            return faultDomains(Output.of(faultDomains));
        }

        /**
         * @param faultDomains (Updatable) The fault domain of this virtual node.
         * 
         * @return builder
         * 
         */
        public Builder faultDomains(String... faultDomains) {
            return faultDomains(List.of(faultDomains));
        }

        /**
         * @param subnetId (Updatable) The OCID of the subnet in which to place virtual nodes.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId (Updatable) The OCID of the subnet in which to place virtual nodes.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public VirtualNodePoolPlacementConfigurationArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("VirtualNodePoolPlacementConfigurationArgs", "availabilityDomain");
            }
            if ($.faultDomains == null) {
                throw new MissingRequiredPropertyException("VirtualNodePoolPlacementConfigurationArgs", "faultDomains");
            }
            if ($.subnetId == null) {
                throw new MissingRequiredPropertyException("VirtualNodePoolPlacementConfigurationArgs", "subnetId");
            }
            return $;
        }
    }

}
