// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Fusion Environment Admin Users in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * List all FusionEnvironment admin users
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentAdminUsers = oci.Functions.getFusionEnvironmentAdminUsers({
 *     fusionEnvironmentId: oci_fusion_apps_fusion_environment.test_fusion_environment.id,
 * });
 * ```
 */
export function getFusionEnvironmentAdminUsers(args: GetFusionEnvironmentAdminUsersArgs, opts?: pulumi.InvokeOptions): Promise<GetFusionEnvironmentAdminUsersResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Functions/getFusionEnvironmentAdminUsers:getFusionEnvironmentAdminUsers", {
        "filters": args.filters,
        "fusionEnvironmentId": args.fusionEnvironmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFusionEnvironmentAdminUsers.
 */
export interface GetFusionEnvironmentAdminUsersArgs {
    filters?: inputs.Functions.GetFusionEnvironmentAdminUsersFilter[];
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: string;
}

/**
 * A collection of values returned by getFusionEnvironmentAdminUsers.
 */
export interface GetFusionEnvironmentAdminUsersResult {
    /**
     * The list of admin_user_collection.
     */
    readonly adminUserCollections: outputs.Functions.GetFusionEnvironmentAdminUsersAdminUserCollection[];
    readonly filters?: outputs.Functions.GetFusionEnvironmentAdminUsersFilter[];
    readonly fusionEnvironmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}

export function getFusionEnvironmentAdminUsersOutput(args: GetFusionEnvironmentAdminUsersOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetFusionEnvironmentAdminUsersResult> {
    return pulumi.output(args).apply(a => getFusionEnvironmentAdminUsers(a, opts))
}

/**
 * A collection of arguments for invoking getFusionEnvironmentAdminUsers.
 */
export interface GetFusionEnvironmentAdminUsersOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Functions.GetFusionEnvironmentAdminUsersFilterArgs>[]>;
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
}