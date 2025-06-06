// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Organization Tenancy resource in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Gets information about the organization's tenancy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOrganizationTenancy = oci.Tenantmanagercontrolplane.getOrganizationTenancy({
 *     organizationId: testOrganization.id,
 *     tenancyId: testTenancy.id,
 * });
 * ```
 */
export function getOrganizationTenancy(args: GetOrganizationTenancyArgs, opts?: pulumi.InvokeOptions): Promise<GetOrganizationTenancyResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Tenantmanagercontrolplane/getOrganizationTenancy:getOrganizationTenancy", {
        "organizationId": args.organizationId,
        "tenancyId": args.tenancyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOrganizationTenancy.
 */
export interface GetOrganizationTenancyArgs {
    /**
     * OCID of the organization.
     */
    organizationId: string;
    /**
     * OCID of the tenancy to retrieve.
     */
    tenancyId: string;
}

/**
 * A collection of values returned by getOrganizationTenancy.
 */
export interface GetOrganizationTenancyResult {
    /**
     * The governance status of the tenancy.
     */
    readonly governanceStatus: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Parameter to indicate the tenancy is approved for transfer to another organization.
     */
    readonly isApprovedForTransfer: boolean;
    /**
     * Name of the tenancy.
     */
    readonly name: string;
    readonly organizationId: string;
    /**
     * Role of the organization tenancy.
     */
    readonly role: string;
    /**
     * Lifecycle state of the organization tenancy.
     */
    readonly state: string;
    /**
     * OCID of the tenancy.
     */
    readonly tenancyId: string;
    /**
     * Date and time when the tenancy joined the organization.
     */
    readonly timeJoined: string;
    /**
     * Date and time when the tenancy left the organization.
     */
    readonly timeLeft: string;
}
/**
 * This data source provides details about a specific Organization Tenancy resource in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Gets information about the organization's tenancy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOrganizationTenancy = oci.Tenantmanagercontrolplane.getOrganizationTenancy({
 *     organizationId: testOrganization.id,
 *     tenancyId: testTenancy.id,
 * });
 * ```
 */
export function getOrganizationTenancyOutput(args: GetOrganizationTenancyOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetOrganizationTenancyResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Tenantmanagercontrolplane/getOrganizationTenancy:getOrganizationTenancy", {
        "organizationId": args.organizationId,
        "tenancyId": args.tenancyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOrganizationTenancy.
 */
export interface GetOrganizationTenancyOutputArgs {
    /**
     * OCID of the organization.
     */
    organizationId: pulumi.Input<string>;
    /**
     * OCID of the tenancy to retrieve.
     */
    tenancyId: pulumi.Input<string>;
}
