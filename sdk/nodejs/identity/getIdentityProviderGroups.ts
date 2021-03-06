// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Identity Provider Groups in Oracle Cloud Infrastructure Identity service.
 *
 * **Deprecated.** For more information, see [Deprecated IAM Service APIs](https://docs.cloud.oracle.com/iaas/Content/Identity/Reference/deprecatediamapis.htm).
 *
 * Lists the identity provider groups.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdentityProviderGroups = oci.Identity.getIdentityProviderGroups({
 *     identityProviderId: oci_identity_identity_provider.test_identity_provider.id,
 *     name: _var.identity_provider_group_name,
 *     state: _var.identity_provider_group_state,
 * });
 * ```
 */
export function getIdentityProviderGroups(args: GetIdentityProviderGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetIdentityProviderGroupsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Identity/getIdentityProviderGroups:getIdentityProviderGroups", {
        "filters": args.filters,
        "identityProviderId": args.identityProviderId,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getIdentityProviderGroups.
 */
export interface GetIdentityProviderGroupsArgs {
    filters?: inputs.Identity.GetIdentityProviderGroupsFilter[];
    /**
     * The OCID of the identity provider.
     */
    identityProviderId: string;
    /**
     * A filter to only return resources that match the given name exactly.
     */
    name?: string;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getIdentityProviderGroups.
 */
export interface GetIdentityProviderGroupsResult {
    readonly filters?: outputs.Identity.GetIdentityProviderGroupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of identity_provider_groups.
     */
    readonly identityProviderGroups: outputs.Identity.GetIdentityProviderGroupsIdentityProviderGroup[];
    /**
     * The OCID of the `IdentityProvider` this group belongs to.
     */
    readonly identityProviderId: string;
    /**
     * Display name of the group
     */
    readonly name?: string;
    readonly state?: string;
}

export function getIdentityProviderGroupsOutput(args: GetIdentityProviderGroupsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetIdentityProviderGroupsResult> {
    return pulumi.output(args).apply(a => getIdentityProviderGroups(a, opts))
}

/**
 * A collection of arguments for invoking getIdentityProviderGroups.
 */
export interface GetIdentityProviderGroupsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Identity.GetIdentityProviderGroupsFilterArgs>[]>;
    /**
     * The OCID of the identity provider.
     */
    identityProviderId: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given name exactly.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
}
