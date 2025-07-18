// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Compute Hosts in Oracle Cloud Infrastructure Core service.
 *
 * Generates a list of summary host details
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComputeHosts = oci.Core.getComputeHosts({
 *     compartmentId: compartmentId,
 *     availabilityDomain: computeHostAvailabilityDomain,
 *     computeHostGroupId: testComputeHostGroup.id,
 *     computeHostHealth: computeHostComputeHostHealth,
 *     computeHostLifecycleState: computeHostComputeHostLifecycleState,
 *     displayName: computeHostDisplayName,
 *     networkResourceId: testResource.id,
 * });
 * ```
 */
export function getComputeHosts(args: GetComputeHostsArgs, opts?: pulumi.InvokeOptions): Promise<GetComputeHostsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getComputeHosts:getComputeHosts", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "computeHostGroupId": args.computeHostGroupId,
        "computeHostHealth": args.computeHostHealth,
        "computeHostLifecycleState": args.computeHostLifecycleState,
        "displayName": args.displayName,
        "filters": args.filters,
        "networkResourceId": args.networkResourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getComputeHosts.
 */
export interface GetComputeHostsArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group.
     */
    computeHostGroupId?: string;
    /**
     * A filter to return only ComputeHostSummary resources that match the given Compute Host health State OCID exactly.
     */
    computeHostHealth?: string;
    /**
     * A filter to return only ComputeHostSummary resources that match the given Compute Host lifecycle State OCID exactly.
     */
    computeHostLifecycleState?: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetComputeHostsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host network resoruce.
     * * Customer-unique HPC island ID
     * * Customer-unique network block ID
     * * Customer-unique local block ID
     */
    networkResourceId?: string;
}

/**
 * A collection of values returned by getComputeHosts.
 */
export interface GetComputeHostsResult {
    /**
     * The availability domain of the compute host.  Example: `Uocm:US-CHICAGO-1-AD-2`
     */
    readonly availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
     */
    readonly compartmentId: string;
    /**
     * The list of compute_host_collection.
     */
    readonly computeHostCollections: outputs.Core.GetComputeHostsComputeHostCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
     */
    readonly computeHostGroupId?: string;
    readonly computeHostHealth?: string;
    readonly computeHostLifecycleState?: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetComputeHostsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A free-form description detailing why the host is in its current state.
     */
    readonly lifecycleDetails: {[key: string]: string};
    readonly networkResourceId?: string;
}
/**
 * This data source provides the list of Compute Hosts in Oracle Cloud Infrastructure Core service.
 *
 * Generates a list of summary host details
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComputeHosts = oci.Core.getComputeHosts({
 *     compartmentId: compartmentId,
 *     availabilityDomain: computeHostAvailabilityDomain,
 *     computeHostGroupId: testComputeHostGroup.id,
 *     computeHostHealth: computeHostComputeHostHealth,
 *     computeHostLifecycleState: computeHostComputeHostLifecycleState,
 *     displayName: computeHostDisplayName,
 *     networkResourceId: testResource.id,
 * });
 * ```
 */
export function getComputeHostsOutput(args: GetComputeHostsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetComputeHostsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getComputeHosts:getComputeHosts", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "computeHostGroupId": args.computeHostGroupId,
        "computeHostHealth": args.computeHostHealth,
        "computeHostLifecycleState": args.computeHostLifecycleState,
        "displayName": args.displayName,
        "filters": args.filters,
        "networkResourceId": args.networkResourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getComputeHosts.
 */
export interface GetComputeHostsOutputArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group.
     */
    computeHostGroupId?: pulumi.Input<string>;
    /**
     * A filter to return only ComputeHostSummary resources that match the given Compute Host health State OCID exactly.
     */
    computeHostHealth?: pulumi.Input<string>;
    /**
     * A filter to return only ComputeHostSummary resources that match the given Compute Host lifecycle State OCID exactly.
     */
    computeHostLifecycleState?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetComputeHostsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host network resoruce.
     * * Customer-unique HPC island ID
     * * Customer-unique network block ID
     * * Customer-unique local block ID
     */
    networkResourceId?: pulumi.Input<string>;
}
