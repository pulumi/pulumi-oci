// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Dedicated Vm Hosts in Oracle Cloud Infrastructure Core service.
 *
 * Returns the list of dedicated virtual machine hosts that match the specified criteria in the specified compartment.
 *
 * You can limit the list by specifying a dedicated virtual machine host display name. The list will include all the identically-named
 * dedicated virtual machine hosts in the compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDedicatedVmHosts = oci.Core.getDedicatedVmHosts({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.dedicated_vm_host_availability_domain,
 *     displayName: _var.dedicated_vm_host_display_name,
 *     instanceShapeName: _var.dedicated_vm_host_instance_shape_name,
 *     remainingMemoryInGbsGreaterThanOrEqualTo: _var.dedicated_vm_host_remaining_memory_in_gbs_greater_than_or_equal_to,
 *     remainingOcpusGreaterThanOrEqualTo: _var.dedicated_vm_host_remaining_ocpus_greater_than_or_equal_to,
 *     state: _var.dedicated_vm_host_state,
 * });
 * ```
 */
export function getDedicatedVmHosts(args: GetDedicatedVmHostsArgs, opts?: pulumi.InvokeOptions): Promise<GetDedicatedVmHostsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getDedicatedVmHosts:getDedicatedVmHosts", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "instanceShapeName": args.instanceShapeName,
        "remainingMemoryInGbsGreaterThanOrEqualTo": args.remainingMemoryInGbsGreaterThanOrEqualTo,
        "remainingOcpusGreaterThanOrEqualTo": args.remainingOcpusGreaterThanOrEqualTo,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDedicatedVmHosts.
 */
export interface GetDedicatedVmHostsArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetDedicatedVmHostsFilter[];
    /**
     * The name for the instance's shape.
     */
    instanceShapeName?: string;
    /**
     * The remaining memory of the dedicated VM host, in GBs.
     */
    remainingMemoryInGbsGreaterThanOrEqualTo?: number;
    /**
     * The available OCPUs of the dedicated VM host.
     */
    remainingOcpusGreaterThanOrEqualTo?: number;
    /**
     * A filter to only return resources that match the given lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getDedicatedVmHosts.
 */
export interface GetDedicatedVmHostsResult {
    /**
     * The availability domain the dedicated virtual machine host is running in.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment that contains the dedicated virtual machine host.
     */
    readonly compartmentId: string;
    /**
     * The list of dedicated_vm_hosts.
     */
    readonly dedicatedVmHosts: outputs.Core.GetDedicatedVmHostsDedicatedVmHost[];
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetDedicatedVmHostsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly instanceShapeName?: string;
    readonly remainingMemoryInGbsGreaterThanOrEqualTo?: number;
    readonly remainingOcpusGreaterThanOrEqualTo?: number;
    /**
     * The current state of the dedicated VM host.
     */
    readonly state?: string;
}

export function getDedicatedVmHostsOutput(args: GetDedicatedVmHostsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDedicatedVmHostsResult> {
    return pulumi.output(args).apply(a => getDedicatedVmHosts(a, opts))
}

/**
 * A collection of arguments for invoking getDedicatedVmHosts.
 */
export interface GetDedicatedVmHostsOutputArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetDedicatedVmHostsFilterArgs>[]>;
    /**
     * The name for the instance's shape.
     */
    instanceShapeName?: pulumi.Input<string>;
    /**
     * The remaining memory of the dedicated VM host, in GBs.
     */
    remainingMemoryInGbsGreaterThanOrEqualTo?: pulumi.Input<number>;
    /**
     * The available OCPUs of the dedicated VM host.
     */
    remainingOcpusGreaterThanOrEqualTo?: pulumi.Input<number>;
    /**
     * A filter to only return resources that match the given lifecycle state.
     */
    state?: pulumi.Input<string>;
}