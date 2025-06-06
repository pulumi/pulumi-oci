// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Security Assessment resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified security assessment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSecurityAssessment = oci.DataSafe.getSecurityAssessment({
 *     securityAssessmentId: testSecurityAssessmentOciDataSafeSecurityAssessment.id,
 * });
 * ```
 */
export function getSecurityAssessment(args: GetSecurityAssessmentArgs, opts?: pulumi.InvokeOptions): Promise<GetSecurityAssessmentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSecurityAssessment:getSecurityAssessment", {
        "securityAssessmentId": args.securityAssessmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSecurityAssessment.
 */
export interface GetSecurityAssessmentArgs {
    /**
     * The OCID of the security assessment.
     */
    securityAssessmentId: string;
}

/**
 * A collection of values returned by getSecurityAssessment.
 */
export interface GetSecurityAssessmentResult {
    /**
     * The OCID of the compartment that contains the security assessment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The description of the security assessment.
     */
    readonly description: string;
    /**
     * The display name of the security assessment.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the security assessment.
     */
    readonly id: string;
    /**
     * List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
     */
    readonly ignoredAssessmentIds: string[];
    /**
     * List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
     */
    readonly ignoredTargets: string[];
    /**
     * Indicates whether the assessment is scheduled to run.
     */
    readonly isAssessmentScheduled: boolean;
    /**
     * Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
     */
    readonly isBaseline: boolean;
    /**
     * Indicates whether or not the security assessment deviates from the baseline.
     */
    readonly isDeviatedFromBaseline: boolean;
    /**
     * The OCID of the baseline against which the latest security assessment was compared.
     */
    readonly lastComparedBaselineId: string;
    /**
     * Details about the current state of the security assessment.
     */
    readonly lifecycleDetails: string;
    /**
     * The summary of findings for the security assessment.
     */
    readonly link: string;
    /**
     * Schedule of the assessment that runs periodically in the specified format: - <version-string>;<version-specific-schedule>
     */
    readonly schedule: string;
    /**
     * The OCID of the security assessment that is responsible for creating this scheduled save assessment.
     */
    readonly scheduleSecurityAssessmentId: string;
    readonly securityAssessmentId: string;
    /**
     * The current state of the security assessment.
     */
    readonly state: string;
    /**
     * Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
     */
    readonly statistics: outputs.DataSafe.GetSecurityAssessmentStatistic[];
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    readonly targetId: string;
    /**
     * Array of database target OCIDs.
     */
    readonly targetIds: string[];
    /**
     * The version of the target database.
     */
    readonly targetVersion: string;
    /**
     * The date and time the security assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The date and time the security assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeLastAssessed: string;
    /**
     * The date and time the security assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeUpdated: string;
    /**
     * Indicates whether the security assessment was created by system or by a user.
     */
    readonly triggeredBy: string;
    /**
     * The type of this security assessment. The possible types are:
     */
    readonly type: string;
}
/**
 * This data source provides details about a specific Security Assessment resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified security assessment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSecurityAssessment = oci.DataSafe.getSecurityAssessment({
 *     securityAssessmentId: testSecurityAssessmentOciDataSafeSecurityAssessment.id,
 * });
 * ```
 */
export function getSecurityAssessmentOutput(args: GetSecurityAssessmentOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSecurityAssessmentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSecurityAssessment:getSecurityAssessment", {
        "securityAssessmentId": args.securityAssessmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSecurityAssessment.
 */
export interface GetSecurityAssessmentOutputArgs {
    /**
     * The OCID of the security assessment.
     */
    securityAssessmentId: pulumi.Input<string>;
}
