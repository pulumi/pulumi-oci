// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Dedicated Vm Hosts Instances in Oracle Cloud Infrastructure Core service.
 *
 * Returns the list of instances on the dedicated virtual machine hosts that match the specified criteria.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDedicatedVmHostsInstances = oci.Core.getDedicatedVmHostInstances({
 *     compartmentId: _var.compartment_id,
 *     dedicatedVmHostId: oci_core_dedicated_vm_host.test_dedicated_vm_host.id,
 *     availabilityDomain: _var.dedicated_vm_hosts_instance_availability_domain,
 * });
 * ```
 */
export function getDedicatedVmHostInstances(args: GetDedicatedVmHostInstancesArgs, opts?: pulumi.InvokeOptions): Promise<GetDedicatedVmHostInstancesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getDedicatedVmHostInstances:getDedicatedVmHostInstances", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "dedicatedVmHostId": args.dedicatedVmHostId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDedicatedVmHostInstances.
 */
export interface GetDedicatedVmHostInstancesArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * The OCID of the dedicated VM host.
     */
    dedicatedVmHostId: string;
    filters?: inputs.Core.GetDedicatedVmHostInstancesFilter[];
}

/**
 * A collection of values returned by getDedicatedVmHostInstances.
 */
export interface GetDedicatedVmHostInstancesResult {
    /**
     * The availability domain the virtual machine instance is running in.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment that contains the virtual machine instance.
     */
    readonly compartmentId: string;
    readonly dedicatedVmHostId: string;
    /**
     * The list of dedicated_vm_host_instances.
     */
    readonly dedicatedVmHostInstances: outputs.Core.GetDedicatedVmHostInstancesDedicatedVmHostInstance[];
    readonly filters?: outputs.Core.GetDedicatedVmHostInstancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}

export function getDedicatedVmHostInstancesOutput(args: GetDedicatedVmHostInstancesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDedicatedVmHostInstancesResult> {
    return pulumi.output(args).apply(a => getDedicatedVmHostInstances(a, opts))
}

/**
 * A collection of arguments for invoking getDedicatedVmHostInstances.
 */
export interface GetDedicatedVmHostInstancesOutputArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The OCID of the dedicated VM host.
     */
    dedicatedVmHostId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetDedicatedVmHostInstancesFilterArgs>[]>;
}