// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Remediation Run resource in Oracle Cloud Infrastructure Adm service.
 *
 * Returns the details of the specified remediation run.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRemediationRun = oci.Adm.getRemediationRun({
 *     remediationRunId: testRemediationRunOciAdmRemediationRun.id,
 * });
 * ```
 */
export function getRemediationRun(args: GetRemediationRunArgs, opts?: pulumi.InvokeOptions): Promise<GetRemediationRunResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Adm/getRemediationRun:getRemediationRun", {
        "remediationRunId": args.remediationRunId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRemediationRun.
 */
export interface GetRemediationRunArgs {
    /**
     * Unique Remediation Run identifier path parameter.
     */
    remediationRunId: string;
}

/**
 * A collection of values returned by getRemediationRun.
 */
export interface GetRemediationRunResult {
    /**
     * The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
     */
    readonly compartmentId: string;
    /**
     * The type of the current stage of the remediation run.
     */
    readonly currentStageType: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The name of the remediation run.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
     */
    readonly id: string;
    /**
     * The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
     */
    readonly remediationRecipeId: string;
    readonly remediationRunId: string;
    /**
     * The source that triggered the Remediation Recipe.
     */
    readonly remediationRunSource: string;
    /**
     * The list of remediation run stage summaries.
     */
    readonly stages: outputs.Adm.GetRemediationRunStage[];
    /**
     * The current lifecycle state of the remediation run.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    readonly timeCreated: string;
    /**
     * The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    readonly timeFinished: string;
    /**
     * The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    readonly timeStarted: string;
    /**
     * The date and time the remediation run was last updated (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Remediation Run resource in Oracle Cloud Infrastructure Adm service.
 *
 * Returns the details of the specified remediation run.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRemediationRun = oci.Adm.getRemediationRun({
 *     remediationRunId: testRemediationRunOciAdmRemediationRun.id,
 * });
 * ```
 */
export function getRemediationRunOutput(args: GetRemediationRunOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetRemediationRunResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Adm/getRemediationRun:getRemediationRun", {
        "remediationRunId": args.remediationRunId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRemediationRun.
 */
export interface GetRemediationRunOutputArgs {
    /**
     * Unique Remediation Run identifier path parameter.
     */
    remediationRunId: pulumi.Input<string>;
}
