// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Organization Tenancies in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Gets a list of tenancies in the organization.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOrganizationTenancies = oci.Tenantmanagercontrolplane.getOrganizationTenancies({
 *     organizationId: testOrganization.id,
 * });
 * ```
 */
export function getOrganizationTenancies(args: GetOrganizationTenanciesArgs, opts?: pulumi.InvokeOptions): Promise<GetOrganizationTenanciesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Tenantmanagercontrolplane/getOrganizationTenancies:getOrganizationTenancies", {
        "filters": args.filters,
        "organizationId": args.organizationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOrganizationTenancies.
 */
export interface GetOrganizationTenanciesArgs {
    filters?: inputs.Tenantmanagercontrolplane.GetOrganizationTenanciesFilter[];
    /**
     * OCID of the organization.
     */
    organizationId: string;
}

/**
 * A collection of values returned by getOrganizationTenancies.
 */
export interface GetOrganizationTenanciesResult {
    readonly filters?: outputs.Tenantmanagercontrolplane.GetOrganizationTenanciesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly organizationId: string;
    /**
     * The list of organization_tenancy_collection.
     */
    readonly organizationTenancyCollections: outputs.Tenantmanagercontrolplane.GetOrganizationTenanciesOrganizationTenancyCollection[];
}
/**
 * This data source provides the list of Organization Tenancies in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Gets a list of tenancies in the organization.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOrganizationTenancies = oci.Tenantmanagercontrolplane.getOrganizationTenancies({
 *     organizationId: testOrganization.id,
 * });
 * ```
 */
export function getOrganizationTenanciesOutput(args: GetOrganizationTenanciesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetOrganizationTenanciesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Tenantmanagercontrolplane/getOrganizationTenancies:getOrganizationTenancies", {
        "filters": args.filters,
        "organizationId": args.organizationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOrganizationTenancies.
 */
export interface GetOrganizationTenanciesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Tenantmanagercontrolplane.GetOrganizationTenanciesFilterArgs>[]>;
    /**
     * OCID of the organization.
     */
    organizationId: pulumi.Input<string>;
}
