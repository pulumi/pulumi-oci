// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Domain Governances in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Return a (paginated) list of domain governance entities.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDomainGovernances = oci.Tenantmanagercontrolplane.getDomainGovernances({
 *     compartmentId: compartmentId,
 *     domainGovernanceId: testDomainGovernance.id,
 *     domainId: testDomain.id,
 *     name: domainGovernanceName,
 *     state: domainGovernanceState,
 * });
 * ```
 */
export function getDomainGovernances(args: GetDomainGovernancesArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainGovernancesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Tenantmanagercontrolplane/getDomainGovernances:getDomainGovernances", {
        "compartmentId": args.compartmentId,
        "domainGovernanceId": args.domainGovernanceId,
        "domainId": args.domainId,
        "filters": args.filters,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainGovernances.
 */
export interface GetDomainGovernancesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * The domain governance OCID.
     */
    domainGovernanceId?: string;
    /**
     * The domain OCID.
     */
    domainId?: string;
    filters?: inputs.Tenantmanagercontrolplane.GetDomainGovernancesFilter[];
    /**
     * A filter to return only resources that exactly match the name given.
     */
    name?: string;
    /**
     * The lifecycle state of the resource.
     */
    state?: string;
}

/**
 * A collection of values returned by getDomainGovernances.
 */
export interface GetDomainGovernancesResult {
    readonly compartmentId: string;
    /**
     * The list of domain_governance_collection.
     */
    readonly domainGovernanceCollections: outputs.Tenantmanagercontrolplane.GetDomainGovernancesDomainGovernanceCollection[];
    readonly domainGovernanceId?: string;
    /**
     * The OCID of the domain associated with this domain governance entity.
     */
    readonly domainId?: string;
    readonly filters?: outputs.Tenantmanagercontrolplane.GetDomainGovernancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly name?: string;
    /**
     * Lifecycle state of the domain governance entity.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Domain Governances in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Return a (paginated) list of domain governance entities.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDomainGovernances = oci.Tenantmanagercontrolplane.getDomainGovernances({
 *     compartmentId: compartmentId,
 *     domainGovernanceId: testDomainGovernance.id,
 *     domainId: testDomain.id,
 *     name: domainGovernanceName,
 *     state: domainGovernanceState,
 * });
 * ```
 */
export function getDomainGovernancesOutput(args: GetDomainGovernancesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDomainGovernancesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Tenantmanagercontrolplane/getDomainGovernances:getDomainGovernances", {
        "compartmentId": args.compartmentId,
        "domainGovernanceId": args.domainGovernanceId,
        "domainId": args.domainId,
        "filters": args.filters,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainGovernances.
 */
export interface GetDomainGovernancesOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The domain governance OCID.
     */
    domainGovernanceId?: pulumi.Input<string>;
    /**
     * The domain OCID.
     */
    domainId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Tenantmanagercontrolplane.GetDomainGovernancesFilterArgs>[]>;
    /**
     * A filter to return only resources that exactly match the name given.
     */
    name?: pulumi.Input<string>;
    /**
     * The lifecycle state of the resource.
     */
    state?: pulumi.Input<string>;
}
