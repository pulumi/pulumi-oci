// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Get the details of a node pool.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNodePool = oci.ContainerEngine.getNodePool({
 *     nodePoolId: oci_containerengine_node_pool.test_node_pool.id,
 * });
 * ```
 */
export function getNodePool(args: GetNodePoolArgs, opts?: pulumi.InvokeOptions): Promise<GetNodePoolResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ContainerEngine/getNodePool:getNodePool", {
        "nodePoolId": args.nodePoolId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNodePool.
 */
export interface GetNodePoolArgs {
    /**
     * The OCID of the node pool.
     */
    nodePoolId: string;
}

/**
 * A collection of values returned by getNodePool.
 */
export interface GetNodePoolResult {
    /**
     * The OCID of the cluster to which this node pool is attached.
     */
    readonly clusterId: string;
    /**
     * The OCID of the compartment in which the node pool exists.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the compute instance backing this node.
     */
    readonly id: string;
    /**
     * A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
     */
    readonly initialNodeLabels: outputs.ContainerEngine.GetNodePoolInitialNodeLabel[];
    /**
     * The version of Kubernetes this node is running.
     */
    readonly kubernetesVersion: string;
    /**
     * The name of the node.
     */
    readonly name: string;
    /**
     * The configuration of nodes in the node pool.
     */
    readonly nodeConfigDetails: outputs.ContainerEngine.GetNodePoolNodeConfigDetail[];
    /**
     * Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
     *
     * @deprecated The 'node_image_id' field has been deprecated. Please use 'node_source_details' instead. If both fields are specified, then 'node_source_details' will be used.
     */
    readonly nodeImageId: string;
    /**
     * Deprecated. see `nodeSource`. The name of the image running on the nodes in the node pool.
     *
     * @deprecated The 'node_image_name' field has been deprecated. Please use 'node_source_details' instead. If both fields are specified, then 'node_source_details' will be used.
     */
    readonly nodeImageName: string;
    /**
     * A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
     */
    readonly nodeMetadata: {[key: string]: any};
    /**
     * The OCID of the node pool to which this node belongs.
     */
    readonly nodePoolId: string;
    /**
     * The name of the node shape of the nodes in the node pool.
     */
    readonly nodeShape: string;
    /**
     * The shape configuration of the nodes.
     */
    readonly nodeShapeConfigs: outputs.ContainerEngine.GetNodePoolNodeShapeConfig[];
    /**
     * Source running on the nodes in the node pool.
     */
    readonly nodeSourceDetails: outputs.ContainerEngine.GetNodePoolNodeSourceDetail[];
    /**
     * Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
     */
    readonly nodeSources: outputs.ContainerEngine.GetNodePoolNodeSource[];
    /**
     * The nodes in the node pool.
     */
    readonly nodes: outputs.ContainerEngine.GetNodePoolNode[];
    /**
     * The number of nodes in each subnet.
     */
    readonly quantityPerSubnet: number;
    /**
     * The SSH public key on each node in the node pool on launch.
     */
    readonly sshPublicKey: string;
    /**
     * The OCIDs of the subnets in which to place nodes for this node pool.
     */
    readonly subnetIds: string[];
}

export function getNodePoolOutput(args: GetNodePoolOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNodePoolResult> {
    return pulumi.output(args).apply(a => getNodePool(a, opts))
}

/**
 * A collection of arguments for invoking getNodePool.
 */
export interface GetNodePoolOutputArgs {
    /**
     * The OCID of the node pool.
     */
    nodePoolId: pulumi.Input<string>;
}
