// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sddcs in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
 *
 * Lists the SDDCs in the specified compartment. The list can be
 * filtered by display name or availability domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSddcs = oci.Ocvp.getSddcs({
 *     compartmentId: _var.compartment_id,
 *     computeAvailabilityDomain: _var.sddc_compute_availability_domain,
 *     displayName: _var.sddc_display_name,
 *     state: _var.sddc_state,
 * });
 * ```
 */
export function getSddcs(args: GetSddcsArgs, opts?: pulumi.InvokeOptions): Promise<GetSddcsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Ocvp/getSddcs:getSddcs", {
        "compartmentId": args.compartmentId,
        "computeAvailabilityDomain": args.computeAvailabilityDomain,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getSddcs.
 */
export interface GetSddcsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * The name of the availability domain that the Compute instances are running in.  Example: `Uocm:PHX-AD-1`
     */
    computeAvailabilityDomain?: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Ocvp.GetSddcsFilter[];
    /**
     * The lifecycle state of the resource.
     */
    state?: string;
}

/**
 * A collection of values returned by getSddcs.
 */
export interface GetSddcsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
     */
    readonly compartmentId: string;
    /**
     * The availability domain the ESXi hosts are running in. For Multi-AD SDDC, it is `multi-AD`.  Example: `Uocm:PHX-AD-1`, `multi-AD`
     */
    readonly computeAvailabilityDomain?: string;
    /**
     * A descriptive name for the SDDC. It must be unique, start with a letter, and contain only letters, digits, whitespaces, dashes and underscores. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Ocvp.GetSddcsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of sddc_collection.
     */
    readonly sddcCollections: outputs.Ocvp.GetSddcsSddcCollection[];
    /**
     * The current state of the SDDC.
     */
    readonly state?: string;
}

export function getSddcsOutput(args: GetSddcsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSddcsResult> {
    return pulumi.output(args).apply(a => getSddcs(a, opts))
}

/**
 * A collection of arguments for invoking getSddcs.
 */
export interface GetSddcsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The name of the availability domain that the Compute instances are running in.  Example: `Uocm:PHX-AD-1`
     */
    computeAvailabilityDomain?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Ocvp.GetSddcsFilterArgs>[]>;
    /**
     * The lifecycle state of the resource.
     */
    state?: pulumi.Input<string>;
}