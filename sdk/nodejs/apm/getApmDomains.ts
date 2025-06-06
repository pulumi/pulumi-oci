// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Apm Domains in Oracle Cloud Infrastructure Apm service.
 *
 * Lists all APM domains for the specified tenant compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApmDomains = oci.Apm.getApmDomains({
 *     compartmentId: compartmentId,
 *     displayName: apmDomainDisplayName,
 *     state: apmDomainState,
 * });
 * ```
 */
export function getApmDomains(args: GetApmDomainsArgs, opts?: pulumi.InvokeOptions): Promise<GetApmDomainsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Apm/getApmDomains:getApmDomains", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getApmDomains.
 */
export interface GetApmDomainsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.Apm.GetApmDomainsFilter[];
    /**
     * A filter to return only resources that match the given life-cycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getApmDomains.
 */
export interface GetApmDomainsResult {
    /**
     * The list of apm_domains.
     */
    readonly apmDomains: outputs.Apm.GetApmDomainsApmDomain[];
    /**
     * The OCID of the compartment corresponding to the APM domain.
     */
    readonly compartmentId: string;
    /**
     * Display name of the APM domain, which can be updated.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Apm.GetApmDomainsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current lifecycle state of the APM domain.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Apm Domains in Oracle Cloud Infrastructure Apm service.
 *
 * Lists all APM domains for the specified tenant compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApmDomains = oci.Apm.getApmDomains({
 *     compartmentId: compartmentId,
 *     displayName: apmDomainDisplayName,
 *     state: apmDomainState,
 * });
 * ```
 */
export function getApmDomainsOutput(args: GetApmDomainsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetApmDomainsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Apm/getApmDomains:getApmDomains", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getApmDomains.
 */
export interface GetApmDomainsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Apm.GetApmDomainsFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given life-cycle state.
     */
    state?: pulumi.Input<string>;
}
