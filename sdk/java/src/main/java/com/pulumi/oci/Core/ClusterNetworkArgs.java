// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.ClusterNetworkInstancePoolArgs;
import com.pulumi.oci.Core.inputs.ClusterNetworkPlacementConfigurationArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterNetworkArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterNetworkArgs Empty = new ClusterNetworkArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The data to create the instance pools in the cluster network.
     * 
     */
    @Import(name="instancePools", required=true)
    private Output<List<ClusterNetworkInstancePoolArgs>> instancePools;

    /**
     * @return (Updatable) The data to create the instance pools in the cluster network.
     * 
     */
    public Output<List<ClusterNetworkInstancePoolArgs>> instancePools() {
        return this.instancePools;
    }

    /**
     * The location for where the instance pools in a cluster network will place instances.
     * 
     */
    @Import(name="placementConfiguration", required=true)
    private Output<ClusterNetworkPlacementConfigurationArgs> placementConfiguration;

    /**
     * @return The location for where the instance pools in a cluster network will place instances.
     * 
     */
    public Output<ClusterNetworkPlacementConfigurationArgs> placementConfiguration() {
        return this.placementConfiguration;
    }

    private ClusterNetworkArgs() {}

    private ClusterNetworkArgs(ClusterNetworkArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.instancePools = $.instancePools;
        this.placementConfiguration = $.placementConfiguration;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterNetworkArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterNetworkArgs $;

        public Builder() {
            $ = new ClusterNetworkArgs();
        }

        public Builder(ClusterNetworkArgs defaults) {
            $ = new ClusterNetworkArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param instancePools (Updatable) The data to create the instance pools in the cluster network.
         * 
         * @return builder
         * 
         */
        public Builder instancePools(Output<List<ClusterNetworkInstancePoolArgs>> instancePools) {
            $.instancePools = instancePools;
            return this;
        }

        /**
         * @param instancePools (Updatable) The data to create the instance pools in the cluster network.
         * 
         * @return builder
         * 
         */
        public Builder instancePools(List<ClusterNetworkInstancePoolArgs> instancePools) {
            return instancePools(Output.of(instancePools));
        }

        /**
         * @param instancePools (Updatable) The data to create the instance pools in the cluster network.
         * 
         * @return builder
         * 
         */
        public Builder instancePools(ClusterNetworkInstancePoolArgs... instancePools) {
            return instancePools(List.of(instancePools));
        }

        /**
         * @param placementConfiguration The location for where the instance pools in a cluster network will place instances.
         * 
         * @return builder
         * 
         */
        public Builder placementConfiguration(Output<ClusterNetworkPlacementConfigurationArgs> placementConfiguration) {
            $.placementConfiguration = placementConfiguration;
            return this;
        }

        /**
         * @param placementConfiguration The location for where the instance pools in a cluster network will place instances.
         * 
         * @return builder
         * 
         */
        public Builder placementConfiguration(ClusterNetworkPlacementConfigurationArgs placementConfiguration) {
            return placementConfiguration(Output.of(placementConfiguration));
        }

        public ClusterNetworkArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.instancePools = Objects.requireNonNull($.instancePools, "expected parameter 'instancePools' to be non-null");
            $.placementConfiguration = Objects.requireNonNull($.placementConfiguration, "expected parameter 'placementConfiguration' to be non-null");
            return $;
        }
    }

}