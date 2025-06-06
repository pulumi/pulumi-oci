// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Autonomous Db Preview Versions in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of supported Autonomous Database versions. Note that preview version software is only available for
 * Autonomous Database Serverless (https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html) databases.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDbPreviewVersions = oci.Database.getAutonomousDbPreviewVersions({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getAutonomousDbPreviewVersions(args: GetAutonomousDbPreviewVersionsArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousDbPreviewVersionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousDbPreviewVersions:getAutonomousDbPreviewVersions", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDbPreviewVersions.
 */
export interface GetAutonomousDbPreviewVersionsArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    filters?: inputs.Database.GetAutonomousDbPreviewVersionsFilter[];
}

/**
 * A collection of values returned by getAutonomousDbPreviewVersions.
 */
export interface GetAutonomousDbPreviewVersionsResult {
    /**
     * The list of autonomous_db_preview_versions.
     */
    readonly autonomousDbPreviewVersions: outputs.Database.GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersion[];
    readonly compartmentId: string;
    readonly filters?: outputs.Database.GetAutonomousDbPreviewVersionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Autonomous Db Preview Versions in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of supported Autonomous Database versions. Note that preview version software is only available for
 * Autonomous Database Serverless (https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html) databases.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDbPreviewVersions = oci.Database.getAutonomousDbPreviewVersions({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getAutonomousDbPreviewVersionsOutput(args: GetAutonomousDbPreviewVersionsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousDbPreviewVersionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousDbPreviewVersions:getAutonomousDbPreviewVersions", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDbPreviewVersions.
 */
export interface GetAutonomousDbPreviewVersionsOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetAutonomousDbPreviewVersionsFilterArgs>[]>;
}
