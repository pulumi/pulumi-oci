// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ContainerEngine.NodePoolArgs;
import com.pulumi.oci.ContainerEngine.inputs.NodePoolState;
import com.pulumi.oci.ContainerEngine.outputs.NodePoolInitialNodeLabel;
import com.pulumi.oci.ContainerEngine.outputs.NodePoolNode;
import com.pulumi.oci.ContainerEngine.outputs.NodePoolNodeConfigDetails;
import com.pulumi.oci.ContainerEngine.outputs.NodePoolNodeShapeConfig;
import com.pulumi.oci.ContainerEngine.outputs.NodePoolNodeSource;
import com.pulumi.oci.ContainerEngine.outputs.NodePoolNodeSourceDetails;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
 * 
 * Create a new node pool.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * NodePools can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:ContainerEngine/nodePool:NodePool test_node_pool &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ContainerEngine/nodePool:NodePool")
public class NodePool extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the cluster to which this node pool is attached.
     * 
     */
    @Export(name="clusterId", type=String.class, parameters={})
    private Output<String> clusterId;

    /**
     * @return The OCID of the cluster to which this node pool is attached.
     * 
     */
    public Output<String> clusterId() {
        return this.clusterId;
    }
    /**
     * The OCID of the compartment in which the node pool exists.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment in which the node pool exists.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
     * 
     */
    @Export(name="initialNodeLabels", type=List.class, parameters={NodePoolInitialNodeLabel.class})
    private Output<List<NodePoolInitialNodeLabel>> initialNodeLabels;

    /**
     * @return (Updatable) A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
     * 
     */
    public Output<List<NodePoolInitialNodeLabel>> initialNodeLabels() {
        return this.initialNodeLabels;
    }
    /**
     * (Updatable) The version of Kubernetes to install on the nodes in the node pool.
     * 
     */
    @Export(name="kubernetesVersion", type=String.class, parameters={})
    private Output<String> kubernetesVersion;

    /**
     * @return (Updatable) The version of Kubernetes to install on the nodes in the node pool.
     * 
     */
    public Output<String> kubernetesVersion() {
        return this.kubernetesVersion;
    }
    /**
     * (Updatable) The name of the node pool. Avoid entering confidential information.
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return (Updatable) The name of the node pool. Avoid entering confidential information.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) The configuration of nodes in the node pool. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
     * 
     */
    @Export(name="nodeConfigDetails", type=NodePoolNodeConfigDetails.class, parameters={})
    private Output<NodePoolNodeConfigDetails> nodeConfigDetails;

    /**
     * @return (Updatable) The configuration of nodes in the node pool. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
     * 
     */
    public Output<NodePoolNodeConfigDetails> nodeConfigDetails() {
        return this.nodeConfigDetails;
    }
    /**
     * Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
     * 
     * @deprecated
     * The &#39;node_image_id&#39; field has been deprecated. Please use &#39;node_source_details&#39; instead. If both fields are specified, then &#39;node_source_details&#39; will be used.
     * 
     */
    @Deprecated /* The 'node_image_id' field has been deprecated. Please use 'node_source_details' instead. If both fields are specified, then 'node_source_details' will be used. */
    @Export(name="nodeImageId", type=String.class, parameters={})
    private Output<String> nodeImageId;

    /**
     * @return Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
     * 
     */
    public Output<String> nodeImageId() {
        return this.nodeImageId;
    }
    /**
     * Deprecated. Use `nodeSourceDetails` instead. If you specify values for both, this value is ignored. The name of the image running on the nodes in the node pool. Cannot be used when `node_image_id` is specified.
     * 
     * @deprecated
     * The &#39;node_image_name&#39; field has been deprecated. Please use &#39;node_source_details&#39; instead. If both fields are specified, then &#39;node_source_details&#39; will be used.
     * 
     */
    @Deprecated /* The 'node_image_name' field has been deprecated. Please use 'node_source_details' instead. If both fields are specified, then 'node_source_details' will be used. */
    @Export(name="nodeImageName", type=String.class, parameters={})
    private Output<String> nodeImageName;

    /**
     * @return Deprecated. Use `nodeSourceDetails` instead. If you specify values for both, this value is ignored. The name of the image running on the nodes in the node pool. Cannot be used when `node_image_id` is specified.
     * 
     */
    public Output<String> nodeImageName() {
        return this.nodeImageName;
    }
    /**
     * (Updatable) A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
     * 
     */
    @Export(name="nodeMetadata", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> nodeMetadata;

    /**
     * @return (Updatable) A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
     * 
     */
    public Output<Map<String,Object>> nodeMetadata() {
        return this.nodeMetadata;
    }
    /**
     * (Updatable) The name of the node shape of the nodes in the node pool.
     * 
     */
    @Export(name="nodeShape", type=String.class, parameters={})
    private Output<String> nodeShape;

    /**
     * @return (Updatable) The name of the node shape of the nodes in the node pool.
     * 
     */
    public Output<String> nodeShape() {
        return this.nodeShape;
    }
    /**
     * (Updatable) Specify the configuration of the shape to launch nodes in the node pool.
     * 
     */
    @Export(name="nodeShapeConfig", type=NodePoolNodeShapeConfig.class, parameters={})
    private Output<NodePoolNodeShapeConfig> nodeShapeConfig;

    /**
     * @return (Updatable) Specify the configuration of the shape to launch nodes in the node pool.
     * 
     */
    public Output<NodePoolNodeShapeConfig> nodeShapeConfig() {
        return this.nodeShapeConfig;
    }
    /**
     * (Updatable) Specify the source to use to launch nodes in the node pool. Currently, image is the only supported source.
     * 
     */
    @Export(name="nodeSourceDetails", type=NodePoolNodeSourceDetails.class, parameters={})
    private Output<NodePoolNodeSourceDetails> nodeSourceDetails;

    /**
     * @return (Updatable) Specify the source to use to launch nodes in the node pool. Currently, image is the only supported source.
     * 
     */
    public Output<NodePoolNodeSourceDetails> nodeSourceDetails() {
        return this.nodeSourceDetails;
    }
    /**
     * Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
     * 
     */
    @Export(name="nodeSources", type=List.class, parameters={NodePoolNodeSource.class})
    private Output<List<NodePoolNodeSource>> nodeSources;

    /**
     * @return Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
     * 
     */
    public Output<List<NodePoolNodeSource>> nodeSources() {
        return this.nodeSources;
    }
    /**
     * The nodes in the node pool.
     * 
     */
    @Export(name="nodes", type=List.class, parameters={NodePoolNode.class})
    private Output<List<NodePoolNode>> nodes;

    /**
     * @return The nodes in the node pool.
     * 
     */
    public Output<List<NodePoolNode>> nodes() {
        return this.nodes;
    }
    /**
     * (Updatable) Optional, default to 1. The number of nodes to create in each subnet specified in subnetIds property. When used, subnetIds is required. This property is deprecated, use nodeConfigDetails instead.
     * 
     */
    @Export(name="quantityPerSubnet", type=Integer.class, parameters={})
    private Output<Integer> quantityPerSubnet;

    /**
     * @return (Updatable) Optional, default to 1. The number of nodes to create in each subnet specified in subnetIds property. When used, subnetIds is required. This property is deprecated, use nodeConfigDetails instead.
     * 
     */
    public Output<Integer> quantityPerSubnet() {
        return this.quantityPerSubnet;
    }
    /**
     * (Updatable) The SSH public key on each node in the node pool on launch.
     * 
     */
    @Export(name="sshPublicKey", type=String.class, parameters={})
    private Output<String> sshPublicKey;

    /**
     * @return (Updatable) The SSH public key on each node in the node pool on launch.
     * 
     */
    public Output<String> sshPublicKey() {
        return this.sshPublicKey;
    }
    /**
     * (Updatable) The OCIDs of the subnets in which to place nodes for this node pool. When used, quantityPerSubnet can be provided. This property is deprecated, use nodeConfigDetails. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
     * 
     */
    @Export(name="subnetIds", type=List.class, parameters={String.class})
    private Output<List<String>> subnetIds;

    /**
     * @return (Updatable) The OCIDs of the subnets in which to place nodes for this node pool. When used, quantityPerSubnet can be provided. This property is deprecated, use nodeConfigDetails. Exactly one of the subnetIds or nodeConfigDetails properties must be specified.
     * 
     */
    public Output<List<String>> subnetIds() {
        return this.subnetIds;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NodePool(String name) {
        this(name, NodePoolArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NodePool(String name, NodePoolArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NodePool(String name, NodePoolArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ContainerEngine/nodePool:NodePool", name, args == null ? NodePoolArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private NodePool(String name, Output<String> id, @Nullable NodePoolState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ContainerEngine/nodePool:NodePool", name, state, makeResourceOptions(options, id));
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
    public static NodePool get(String name, Output<String> id, @Nullable NodePoolState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NodePool(name, id, state, options);
    }
}
