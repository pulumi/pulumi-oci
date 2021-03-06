// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Supported Vmware Software Versions in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
 *
 * Lists the versions of bundled VMware software supported by the Oracle Cloud
 * VMware Solution.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSupportedVmwareSoftwareVersions = oci.Ocvp.getSupportedVmwareSoftwareVersions({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getSupportedVmwareSoftwareVersions(args: GetSupportedVmwareSoftwareVersionsArgs, opts?: pulumi.InvokeOptions): Promise<GetSupportedVmwareSoftwareVersionsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Ocvp/getSupportedVmwareSoftwareVersions:getSupportedVmwareSoftwareVersions", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getSupportedVmwareSoftwareVersions.
 */
export interface GetSupportedVmwareSoftwareVersionsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.Ocvp.GetSupportedVmwareSoftwareVersionsFilter[];
}

/**
 * A collection of values returned by getSupportedVmwareSoftwareVersions.
 */
export interface GetSupportedVmwareSoftwareVersionsResult {
    readonly compartmentId: string;
    readonly filters?: outputs.Ocvp.GetSupportedVmwareSoftwareVersionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A list of the supported versions of bundled VMware software.
     */
    readonly items: outputs.Ocvp.GetSupportedVmwareSoftwareVersionsItem[];
}

export function getSupportedVmwareSoftwareVersionsOutput(args: GetSupportedVmwareSoftwareVersionsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSupportedVmwareSoftwareVersionsResult> {
    return pulumi.output(args).apply(a => getSupportedVmwareSoftwareVersions(a, opts))
}

/**
 * A collection of arguments for invoking getSupportedVmwareSoftwareVersions.
 */
export interface GetSupportedVmwareSoftwareVersionsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Ocvp.GetSupportedVmwareSoftwareVersionsFilterArgs>[]>;
}
