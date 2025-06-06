// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Autonomous Vm Clusters in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of Exadata Cloud@Customer Autonomous VM clusters in the specified compartment. To list Autonomous VM Clusters in the Oracle Cloud, see [ListCloudAutonomousVmClusters](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudAutonomousVmCluster/ListCloudAutonomousVmClusters).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousVmClusters = oci.Database.getAutonomousVmClusters({
 *     compartmentId: compartmentId,
 *     displayName: autonomousVmClusterDisplayName,
 *     exadataInfrastructureId: testExadataInfrastructure.id,
 *     state: autonomousVmClusterState,
 * });
 * ```
 */
export function getAutonomousVmClusters(args: GetAutonomousVmClustersArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousVmClustersResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousVmClusters:getAutonomousVmClusters", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "exadataInfrastructureId": args.exadataInfrastructureId,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousVmClusters.
 */
export interface GetAutonomousVmClustersArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    /**
     * If provided, filters the results for the given Exadata Infrastructure.
     */
    exadataInfrastructureId?: string;
    filters?: inputs.Database.GetAutonomousVmClustersFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getAutonomousVmClusters.
 */
export interface GetAutonomousVmClustersResult {
    /**
     * The list of autonomous_vm_clusters.
     */
    readonly autonomousVmClusters: outputs.Database.GetAutonomousVmClustersAutonomousVmCluster[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
     */
    readonly displayName?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    readonly exadataInfrastructureId?: string;
    readonly filters?: outputs.Database.GetAutonomousVmClustersFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Autonomous VM cluster.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Autonomous Vm Clusters in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of Exadata Cloud@Customer Autonomous VM clusters in the specified compartment. To list Autonomous VM Clusters in the Oracle Cloud, see [ListCloudAutonomousVmClusters](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudAutonomousVmCluster/ListCloudAutonomousVmClusters).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousVmClusters = oci.Database.getAutonomousVmClusters({
 *     compartmentId: compartmentId,
 *     displayName: autonomousVmClusterDisplayName,
 *     exadataInfrastructureId: testExadataInfrastructure.id,
 *     state: autonomousVmClusterState,
 * });
 * ```
 */
export function getAutonomousVmClustersOutput(args: GetAutonomousVmClustersOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousVmClustersResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousVmClusters:getAutonomousVmClusters", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "exadataInfrastructureId": args.exadataInfrastructureId,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousVmClusters.
 */
export interface GetAutonomousVmClustersOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    /**
     * If provided, filters the results for the given Exadata Infrastructure.
     */
    exadataInfrastructureId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetAutonomousVmClustersFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
}
