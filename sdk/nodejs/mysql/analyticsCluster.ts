// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Analytics Cluster resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * DEPRECATED -- please use HeatWave API instead.
 * Updates the Analytics Cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAnalyticsCluster = new oci.mysql.AnalyticsCluster("testAnalyticsCluster", {
 *     dbSystemId: oci_database_db_system.test_db_system.id,
 *     clusterSize: _var.analytics_cluster_cluster_size,
 *     shapeName: oci_mysql_shape.test_shape.name,
 * });
 * ```
 *
 * ## Import
 *
 * AnalyticsCluster can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Mysql/analyticsCluster:AnalyticsCluster test_analytics_cluster "dbSystems/{dbSystemId}/analyticsCluster"
 * ```
 */
export class AnalyticsCluster extends pulumi.CustomResource {
    /**
     * Get an existing AnalyticsCluster resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AnalyticsClusterState, opts?: pulumi.CustomResourceOptions): AnalyticsCluster {
        return new AnalyticsCluster(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Mysql/analyticsCluster:AnalyticsCluster';

    /**
     * Returns true if the given object is an instance of AnalyticsCluster.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AnalyticsCluster {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AnalyticsCluster.__pulumiType;
    }

    /**
     * An Analytics Cluster Node is a compute host that is part of an Analytics Cluster.
     */
    public /*out*/ readonly clusterNodes!: pulumi.Output<outputs.Mysql.AnalyticsClusterClusterNode[]>;
    /**
     * (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     */
    public readonly clusterSize!: pulumi.Output<number>;
    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly dbSystemId!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycleState.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     */
    public readonly shapeName!: pulumi.Output<string>;
    /**
     * (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a AnalyticsCluster resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AnalyticsClusterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AnalyticsClusterArgs | AnalyticsClusterState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AnalyticsClusterState | undefined;
            resourceInputs["clusterNodes"] = state ? state.clusterNodes : undefined;
            resourceInputs["clusterSize"] = state ? state.clusterSize : undefined;
            resourceInputs["dbSystemId"] = state ? state.dbSystemId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["shapeName"] = state ? state.shapeName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as AnalyticsClusterArgs | undefined;
            if ((!args || args.clusterSize === undefined) && !opts.urn) {
                throw new Error("Missing required property 'clusterSize'");
            }
            if ((!args || args.dbSystemId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'dbSystemId'");
            }
            if ((!args || args.shapeName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shapeName'");
            }
            resourceInputs["clusterSize"] = args ? args.clusterSize : undefined;
            resourceInputs["dbSystemId"] = args ? args.dbSystemId : undefined;
            resourceInputs["shapeName"] = args ? args.shapeName : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["clusterNodes"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AnalyticsCluster.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AnalyticsCluster resources.
 */
export interface AnalyticsClusterState {
    /**
     * An Analytics Cluster Node is a compute host that is part of an Analytics Cluster.
     */
    clusterNodes?: pulumi.Input<pulumi.Input<inputs.Mysql.AnalyticsClusterClusterNode>[]>;
    /**
     * (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     */
    clusterSize?: pulumi.Input<number>;
    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbSystemId?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycleState.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     */
    shapeName?: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AnalyticsCluster resource.
 */
export interface AnalyticsClusterArgs {
    /**
     * (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     */
    clusterSize: pulumi.Input<number>;
    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbSystemId: pulumi.Input<string>;
    /**
     * (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
     */
    shapeName: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
     */
    state?: pulumi.Input<string>;
}
