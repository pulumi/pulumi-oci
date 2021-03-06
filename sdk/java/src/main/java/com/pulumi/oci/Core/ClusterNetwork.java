// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.ClusterNetworkArgs;
import com.pulumi.oci.Core.inputs.ClusterNetworkState;
import com.pulumi.oci.Core.outputs.ClusterNetworkInstancePool;
import com.pulumi.oci.Core.outputs.ClusterNetworkPlacementConfiguration;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Cluster Network resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a cluster network. For more information about cluster networks, see
 * [Managing Cluster Networks](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm).
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * ClusterNetworks can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/clusterNetwork:ClusterNetwork test_cluster_network &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/clusterNetwork:ClusterNetwork")
public class ClusterNetwork extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
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
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The data to create the instance pools in the cluster network.
     * 
     */
    @Export(name="instancePools", type=List.class, parameters={ClusterNetworkInstancePool.class})
    private Output<List<ClusterNetworkInstancePool>> instancePools;

    /**
     * @return (Updatable) The data to create the instance pools in the cluster network.
     * 
     */
    public Output<List<ClusterNetworkInstancePool>> instancePools() {
        return this.instancePools;
    }
    /**
     * The location for where the instance pools in a cluster network will place instances.
     * 
     */
    @Export(name="placementConfiguration", type=ClusterNetworkPlacementConfiguration.class, parameters={})
    private Output<ClusterNetworkPlacementConfiguration> placementConfiguration;

    /**
     * @return The location for where the instance pools in a cluster network will place instances.
     * 
     */
    public Output<ClusterNetworkPlacementConfiguration> placementConfiguration() {
        return this.placementConfiguration;
    }
    /**
     * The current state of the cluster network.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the cluster network.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ClusterNetwork(String name) {
        this(name, ClusterNetworkArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ClusterNetwork(String name, ClusterNetworkArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ClusterNetwork(String name, ClusterNetworkArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/clusterNetwork:ClusterNetwork", name, args == null ? ClusterNetworkArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ClusterNetwork(String name, Output<String> id, @Nullable ClusterNetworkState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/clusterNetwork:ClusterNetwork", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static ClusterNetwork get(String name, Output<String> id, @Nullable ClusterNetworkState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ClusterNetwork(name, id, state, options);
    }
}
