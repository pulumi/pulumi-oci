// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RecoveryServiceSubnetArgs extends com.pulumi.resources.ResourceArgs {

    public static final RecoveryServiceSubnetArgs Empty = new RecoveryServiceSubnetArgs();

    /**
     * (Updatable) The compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-provided name for the recovery service subnet. The &#39;displayName&#39; does not have to be unique, and it can be modified. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-provided name for the recovery service subnet. The &#39;displayName&#39; does not have to be unique, and it can be modified. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) A list of network security group (NSG) OCIDs that are associated with the Recovery Service subnet. You can specify a maximum of 5 unique OCIDs, which implies that you can associate a maximum of 5 NSGs to each Recovery Service subnet. Specify an empty array if you want to remove all the associated NSGs from a Recovery Service subnet. See [Network Security Groups](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/) for more information.
     * 
     */
    @Import(name="nsgIds")
    private @Nullable Output<List<String>> nsgIds;

    /**
     * @return (Updatable) A list of network security group (NSG) OCIDs that are associated with the Recovery Service subnet. You can specify a maximum of 5 unique OCIDs, which implies that you can associate a maximum of 5 NSGs to each Recovery Service subnet. Specify an empty array if you want to remove all the associated NSGs from a Recovery Service subnet. See [Network Security Groups](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/) for more information.
     * 
     */
    public Optional<Output<List<String>>> nsgIds() {
        return Optional.ofNullable(this.nsgIds);
    }

    /**
     * Deprecated. One of the subnets associated with the Recovery Service subnet.
     * 
     * @deprecated
     * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnets&#39; instead.
     * 
     */
    @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnets' instead. */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return Deprecated. One of the subnets associated with the Recovery Service subnet.
     * 
     * @deprecated
     * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnets&#39; instead.
     * 
     */
    @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnets' instead. */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    /**
     * (Updatable) A list of OCIDs of the subnets associated with the Recovery Service subnet.
     * 
     */
    @Import(name="subnets")
    private @Nullable Output<List<String>> subnets;

    /**
     * @return (Updatable) A list of OCIDs of the subnets associated with the Recovery Service subnet.
     * 
     */
    public Optional<Output<List<String>>> subnets() {
        return Optional.ofNullable(this.subnets);
    }

    /**
     * The OCID of the virtual cloud network (VCN) that contains the recovery service subnet. You can create a single recovery service subnet per VCN.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="vcnId", required=true)
    private Output<String> vcnId;

    /**
     * @return The OCID of the virtual cloud network (VCN) that contains the recovery service subnet. You can create a single recovery service subnet per VCN.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> vcnId() {
        return this.vcnId;
    }

    private RecoveryServiceSubnetArgs() {}

    private RecoveryServiceSubnetArgs(RecoveryServiceSubnetArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.nsgIds = $.nsgIds;
        this.subnetId = $.subnetId;
        this.subnets = $.subnets;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RecoveryServiceSubnetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RecoveryServiceSubnetArgs $;

        public Builder() {
            $ = new RecoveryServiceSubnetArgs();
        }

        public Builder(RecoveryServiceSubnetArgs defaults) {
            $ = new RecoveryServiceSubnetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-provided name for the recovery service subnet. The &#39;displayName&#39; does not have to be unique, and it can be modified. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-provided name for the recovery service subnet. The &#39;displayName&#39; does not have to be unique, and it can be modified. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param nsgIds (Updatable) A list of network security group (NSG) OCIDs that are associated with the Recovery Service subnet. You can specify a maximum of 5 unique OCIDs, which implies that you can associate a maximum of 5 NSGs to each Recovery Service subnet. Specify an empty array if you want to remove all the associated NSGs from a Recovery Service subnet. See [Network Security Groups](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/) for more information.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(@Nullable Output<List<String>> nsgIds) {
            $.nsgIds = nsgIds;
            return this;
        }

        /**
         * @param nsgIds (Updatable) A list of network security group (NSG) OCIDs that are associated with the Recovery Service subnet. You can specify a maximum of 5 unique OCIDs, which implies that you can associate a maximum of 5 NSGs to each Recovery Service subnet. Specify an empty array if you want to remove all the associated NSGs from a Recovery Service subnet. See [Network Security Groups](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/) for more information.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(List<String> nsgIds) {
            return nsgIds(Output.of(nsgIds));
        }

        /**
         * @param nsgIds (Updatable) A list of network security group (NSG) OCIDs that are associated with the Recovery Service subnet. You can specify a maximum of 5 unique OCIDs, which implies that you can associate a maximum of 5 NSGs to each Recovery Service subnet. Specify an empty array if you want to remove all the associated NSGs from a Recovery Service subnet. See [Network Security Groups](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/) for more information.
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }

        /**
         * @param subnetId Deprecated. One of the subnets associated with the Recovery Service subnet.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnets&#39; instead.
         * 
         */
        @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnets' instead. */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId Deprecated. One of the subnets associated with the Recovery Service subnet.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnets&#39; instead.
         * 
         */
        @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnets' instead. */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        /**
         * @param subnets (Updatable) A list of OCIDs of the subnets associated with the Recovery Service subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnets(@Nullable Output<List<String>> subnets) {
            $.subnets = subnets;
            return this;
        }

        /**
         * @param subnets (Updatable) A list of OCIDs of the subnets associated with the Recovery Service subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnets(List<String> subnets) {
            return subnets(Output.of(subnets));
        }

        /**
         * @param subnets (Updatable) A list of OCIDs of the subnets associated with the Recovery Service subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnets(String... subnets) {
            return subnets(List.of(subnets));
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) that contains the recovery service subnet. You can create a single recovery service subnet per VCN.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vcnId(Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) that contains the recovery service subnet. You can create a single recovery service subnet per VCN.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public RecoveryServiceSubnetArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("RecoveryServiceSubnetArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("RecoveryServiceSubnetArgs", "displayName");
            }
            if ($.vcnId == null) {
                throw new MissingRequiredPropertyException("RecoveryServiceSubnetArgs", "vcnId");
            }
            return $;
        }
    }

}
