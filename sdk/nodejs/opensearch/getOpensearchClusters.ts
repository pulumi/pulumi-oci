// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Opensearch Clusters in Oracle Cloud Infrastructure Opensearch service.
 *
 * Returns a list of OpensearchClusters.
 *
 * ## Prerequisites
 *
 * The below policies must be created in compartment before creating OpensearchCluster
 *
 * ##### {Compartment-Name} - Name of  your compartment
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * ```
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOpensearchClusters = oci.Opensearch.getOpensearchClusters({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.opensearch_cluster_display_name,
 *     id: _var.opensearch_cluster_id,
 *     state: _var.opensearch_cluster_state,
 * });
 * ```
 */
export function getOpensearchClusters(args: GetOpensearchClustersArgs, opts?: pulumi.InvokeOptions): Promise<GetOpensearchClustersResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opensearch/getOpensearchClusters:getOpensearchClusters", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getOpensearchClusters.
 */
export interface GetOpensearchClustersArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.Opensearch.GetOpensearchClustersFilter[];
    /**
     * unique OpensearchCluster identifier
     */
    id?: string;
    /**
     * A filter to return only OpensearchClusters their lifecycleState matches the given lifecycleState.
     */
    state?: string;
}

/**
 * A collection of values returned by getOpensearchClusters.
 */
export interface GetOpensearchClustersResult {
    /**
     * The OCID of the compartment where the cluster is located.
     */
    readonly compartmentId: string;
    /**
     * The name of the cluster. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Opensearch.GetOpensearchClustersFilter[];
    /**
     * The OCID of the cluster.
     */
    readonly id?: string;
    /**
     * The list of opensearch_cluster_collection.
     */
    readonly opensearchClusterCollections: outputs.Opensearch.GetOpensearchClustersOpensearchClusterCollection[];
    /**
     * The current state of the cluster.
     */
    readonly state?: string;
}

export function getOpensearchClustersOutput(args: GetOpensearchClustersOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetOpensearchClustersResult> {
    return pulumi.output(args).apply(a => getOpensearchClusters(a, opts))
}

/**
 * A collection of arguments for invoking getOpensearchClusters.
 */
export interface GetOpensearchClustersOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Opensearch.GetOpensearchClustersFilterArgs>[]>;
    /**
     * unique OpensearchCluster identifier
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only OpensearchClusters their lifecycleState matches the given lifecycleState.
     */
    state?: pulumi.Input<string>;
}