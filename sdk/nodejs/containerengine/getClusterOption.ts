// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Get options available for clusters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterOption = oci.ContainerEngine.getClusterOption({
 *     clusterOptionId: testClusterOptionOciContainerengineClusterOption.id,
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getClusterOption(args: GetClusterOptionArgs, opts?: pulumi.InvokeOptions): Promise<GetClusterOptionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ContainerEngine/getClusterOption:getClusterOption", {
        "clusterOptionId": args.clusterOptionId,
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getClusterOption.
 */
export interface GetClusterOptionArgs {
    /**
     * The id of the option set to retrieve. Use "all" get all options, or use a cluster ID to get options specific to the provided cluster.
     */
    clusterOptionId: string;
    /**
     * The OCID of the compartment.
     */
    compartmentId?: string;
}

/**
 * A collection of values returned by getClusterOption.
 */
export interface GetClusterOptionResult {
    readonly clusterOptionId: string;
    /**
     * Available CNIs and network options for existing and new node pools of the cluster
     */
    readonly clusterPodNetworkOptions: outputs.ContainerEngine.GetClusterOptionClusterPodNetworkOption[];
    readonly compartmentId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Available Kubernetes versions.
     */
    readonly kubernetesVersions: string[];
}
/**
 * This data source provides details about a specific Cluster Option resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Get options available for clusters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterOption = oci.ContainerEngine.getClusterOption({
 *     clusterOptionId: testClusterOptionOciContainerengineClusterOption.id,
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getClusterOptionOutput(args: GetClusterOptionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetClusterOptionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ContainerEngine/getClusterOption:getClusterOption", {
        "clusterOptionId": args.clusterOptionId,
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getClusterOption.
 */
export interface GetClusterOptionOutputArgs {
    /**
     * The id of the option set to retrieve. Use "all" get all options, or use a cluster ID to get options specific to the provided cluster.
     */
    clusterOptionId: pulumi.Input<string>;
    /**
     * The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
}
