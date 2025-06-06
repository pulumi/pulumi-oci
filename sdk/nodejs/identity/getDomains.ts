// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Domains in Oracle Cloud Infrastructure Identity service.
 *
 * List all domains that are homed or have a replica region in current region.
 * - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDomains = oci.Identity.getDomains({
 *     compartmentId: compartmentId,
 *     displayName: domainDisplayName,
 *     homeRegionUrl: domainHomeRegionUrl,
 *     isHiddenOnLogin: domainIsHiddenOnLogin,
 *     licenseType: domainLicenseType,
 *     name: domainName,
 *     state: domainState,
 *     type: domainType,
 *     url: domainUrl,
 * });
 * ```
 */
export function getDomains(args: GetDomainsArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomains:getDomains", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "homeRegionUrl": args.homeRegionUrl,
        "isHiddenOnLogin": args.isHiddenOnLogin,
        "licenseType": args.licenseType,
        "name": args.name,
        "state": args.state,
        "type": args.type,
        "url": args.url,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomains.
 */
export interface GetDomainsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: string;
    /**
     * The mutable display name of the domain
     */
    displayName?: string;
    filters?: inputs.Identity.GetDomainsFilter[];
    /**
     * The region specific domain URL
     */
    homeRegionUrl?: string;
    /**
     * Indicate if the domain is visible at login screen or not
     */
    isHiddenOnLogin?: boolean;
    /**
     * The domain license type
     */
    licenseType?: string;
    /**
     * A filter to only return resources that match the given name exactly.
     */
    name?: string;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: string;
    /**
     * The domain type
     */
    type?: string;
    /**
     * The region agnostic domain URL
     */
    url?: string;
}

/**
 * A collection of values returned by getDomains.
 */
export interface GetDomainsResult {
    /**
     * The OCID of the compartment containing the domain.
     */
    readonly compartmentId: string;
    /**
     * The mutable display name of the domain
     */
    readonly displayName?: string;
    /**
     * The list of domains.
     */
    readonly domains: outputs.Identity.GetDomainsDomain[];
    readonly filters?: outputs.Identity.GetDomainsFilter[];
    /**
     * Region specific domain URL.
     */
    readonly homeRegionUrl?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates whether domain is hidden on login screen or not.
     */
    readonly isHiddenOnLogin?: boolean;
    /**
     * The License type of Domain
     */
    readonly licenseType?: string;
    readonly name?: string;
    /**
     * The current state.
     */
    readonly state?: string;
    /**
     * The type of the domain.
     */
    readonly type?: string;
    /**
     * Region agnostic domain URL.
     */
    readonly url?: string;
}
/**
 * This data source provides the list of Domains in Oracle Cloud Infrastructure Identity service.
 *
 * List all domains that are homed or have a replica region in current region.
 * - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDomains = oci.Identity.getDomains({
 *     compartmentId: compartmentId,
 *     displayName: domainDisplayName,
 *     homeRegionUrl: domainHomeRegionUrl,
 *     isHiddenOnLogin: domainIsHiddenOnLogin,
 *     licenseType: domainLicenseType,
 *     name: domainName,
 *     state: domainState,
 *     type: domainType,
 *     url: domainUrl,
 * });
 * ```
 */
export function getDomainsOutput(args: GetDomainsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDomainsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getDomains:getDomains", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "homeRegionUrl": args.homeRegionUrl,
        "isHiddenOnLogin": args.isHiddenOnLogin,
        "licenseType": args.licenseType,
        "name": args.name,
        "state": args.state,
        "type": args.type,
        "url": args.url,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomains.
 */
export interface GetDomainsOutputArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The mutable display name of the domain
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Identity.GetDomainsFilterArgs>[]>;
    /**
     * The region specific domain URL
     */
    homeRegionUrl?: pulumi.Input<string>;
    /**
     * Indicate if the domain is visible at login screen or not
     */
    isHiddenOnLogin?: pulumi.Input<boolean>;
    /**
     * The domain license type
     */
    licenseType?: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given name exactly.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
    /**
     * The domain type
     */
    type?: pulumi.Input<string>;
    /**
     * The region agnostic domain URL
     */
    url?: pulumi.Input<string>;
}
