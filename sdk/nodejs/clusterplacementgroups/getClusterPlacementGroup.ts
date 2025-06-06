// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Cluster Placement Group resource in Oracle Cloud Infrastructure Cluster Placement Groups service.
 *
 * Gets the specified cluster placement group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterPlacementGroup = oci.ClusterPlacementGroups.getClusterPlacementGroup({
 *     clusterPlacementGroupId: testClusterPlacementGroupOciClusterPlacementGroupsClusterPlacementGroup.id,
 * });
 * ```
 */
export function getClusterPlacementGroup(args: GetClusterPlacementGroupArgs, opts?: pulumi.InvokeOptions): Promise<GetClusterPlacementGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ClusterPlacementGroups/getClusterPlacementGroup:getClusterPlacementGroup", {
        "clusterPlacementGroupId": args.clusterPlacementGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getClusterPlacementGroup.
 */
export interface GetClusterPlacementGroupArgs {
    /**
     * A unique cluster placement group identifier.
     */
    clusterPlacementGroupId: string;
}

/**
 * A collection of values returned by getClusterPlacementGroup.
 */
export interface GetClusterPlacementGroupResult {
    /**
     * The availability domain of the cluster placement group.
     */
    readonly availabilityDomain: string;
    /**
     * A list of resources that you can create in a cluster placement group.
     */
    readonly capabilities: outputs.ClusterPlacementGroups.GetClusterPlacementGroupCapability[];
    readonly clusterPlacementGroupId: string;
    /**
     * The type of cluster placement group.
     */
    readonly clusterPlacementGroupType: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the cluster placement group.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A description of the cluster placement group.
     */
    readonly description: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, lifecycle details for a resource in a Failed state might include information to act on.
     */
    readonly lifecycleDetails: string;
    /**
     * The user-friendly name of the cluster placement group. The display name for a cluster placement must be unique and you cannot change it. Avoid entering confidential information.
     */
    readonly name: string;
    readonly opcDryRun: boolean;
    /**
     * Details that inform cluster placement group provisioning.
     */
    readonly placementInstructions: outputs.ClusterPlacementGroups.GetClusterPlacementGroupPlacementInstruction[];
    /**
     * The current state of the ClusterPlacementGroup.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time the cluster placement group was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    readonly timeCreated: string;
    /**
     * The time the cluster placement group was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Cluster Placement Group resource in Oracle Cloud Infrastructure Cluster Placement Groups service.
 *
 * Gets the specified cluster placement group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterPlacementGroup = oci.ClusterPlacementGroups.getClusterPlacementGroup({
 *     clusterPlacementGroupId: testClusterPlacementGroupOciClusterPlacementGroupsClusterPlacementGroup.id,
 * });
 * ```
 */
export function getClusterPlacementGroupOutput(args: GetClusterPlacementGroupOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetClusterPlacementGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ClusterPlacementGroups/getClusterPlacementGroup:getClusterPlacementGroup", {
        "clusterPlacementGroupId": args.clusterPlacementGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getClusterPlacementGroup.
 */
export interface GetClusterPlacementGroupOutputArgs {
    /**
     * A unique cluster placement group identifier.
     */
    clusterPlacementGroupId: pulumi.Input<string>;
}
