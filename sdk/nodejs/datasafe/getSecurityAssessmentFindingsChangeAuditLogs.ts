// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Security Assessment Findings Change Audit Logs in Oracle Cloud Infrastructure Data Safe service.
 *
 * List all changes made by user to risk level of findings of the specified assessment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSecurityAssessmentFindingsChangeAuditLogs = oci.DataSafe.getSecurityAssessmentFindingsChangeAuditLogs({
 *     securityAssessmentId: testSecurityAssessment.id,
 *     findingKey: securityAssessmentFindingsChangeAuditLogFindingKey,
 *     findingTitle: securityAssessmentFindingsChangeAuditLogFindingTitle,
 *     isRiskDeferred: securityAssessmentFindingsChangeAuditLogIsRiskDeferred,
 *     modifiedBy: securityAssessmentFindingsChangeAuditLogModifiedBy,
 *     severity: securityAssessmentFindingsChangeAuditLogSeverity,
 *     timeUpdatedGreaterThanOrEqualTo: securityAssessmentFindingsChangeAuditLogTimeUpdatedGreaterThanOrEqualTo,
 *     timeUpdatedLessThan: securityAssessmentFindingsChangeAuditLogTimeUpdatedLessThan,
 *     timeValidUntilGreaterThanOrEqualTo: securityAssessmentFindingsChangeAuditLogTimeValidUntilGreaterThanOrEqualTo,
 *     timeValidUntilLessThan: securityAssessmentFindingsChangeAuditLogTimeValidUntilLessThan,
 * });
 * ```
 */
export function getSecurityAssessmentFindingsChangeAuditLogs(args: GetSecurityAssessmentFindingsChangeAuditLogsArgs, opts?: pulumi.InvokeOptions): Promise<GetSecurityAssessmentFindingsChangeAuditLogsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSecurityAssessmentFindingsChangeAuditLogs:getSecurityAssessmentFindingsChangeAuditLogs", {
        "filters": args.filters,
        "findingKey": args.findingKey,
        "findingTitle": args.findingTitle,
        "isRiskDeferred": args.isRiskDeferred,
        "modifiedBy": args.modifiedBy,
        "securityAssessmentId": args.securityAssessmentId,
        "severity": args.severity,
        "timeUpdatedGreaterThanOrEqualTo": args.timeUpdatedGreaterThanOrEqualTo,
        "timeUpdatedLessThan": args.timeUpdatedLessThan,
        "timeValidUntilGreaterThanOrEqualTo": args.timeValidUntilGreaterThanOrEqualTo,
        "timeValidUntilLessThan": args.timeValidUntilLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSecurityAssessmentFindingsChangeAuditLogs.
 */
export interface GetSecurityAssessmentFindingsChangeAuditLogsArgs {
    filters?: inputs.DataSafe.GetSecurityAssessmentFindingsChangeAuditLogsFilter[];
    /**
     * The unique key that identifies the finding. It is a string and unique within a security assessment.
     */
    findingKey?: string;
    /**
     * The unique title that identifies the finding. It is a string and unique within a security assessment.
     */
    findingTitle?: string;
    /**
     * A filter to check findings whose risks were deferred by the user.
     */
    isRiskDeferred?: boolean;
    /**
     * A filter to check which user modified the risk level of the finding.
     */
    modifiedBy?: string;
    /**
     * The OCID of the security assessment.
     */
    securityAssessmentId: string;
    /**
     * A filter to return only findings of a particular risk level.
     */
    severity?: string;
    /**
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedGreaterThanOrEqualTo?: string;
    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedLessThan?: string;
    /**
     * Specifying `TimeValidUntilGreaterThanOrEqualToQueryParam` parameter  will retrieve all items for which the risk level modification by user will  no longer be valid greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     *
     * **Example:** 2016-12-19T00:00:00.000Z
     */
    timeValidUntilGreaterThanOrEqualTo?: string;
    /**
     * Specifying `TimeValidUntilLessThanQueryParam` parameter will retrieve all items for which the risk level modification by user will  be valid until less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     *
     * **Example:** 2016-12-19T00:00:00.000Z
     */
    timeValidUntilLessThan?: string;
}

/**
 * A collection of values returned by getSecurityAssessmentFindingsChangeAuditLogs.
 */
export interface GetSecurityAssessmentFindingsChangeAuditLogsResult {
    readonly filters?: outputs.DataSafe.GetSecurityAssessmentFindingsChangeAuditLogsFilter[];
    /**
     * The unique key that identifies the finding.
     */
    readonly findingKey?: string;
    /**
     * The short title for the finding whose risk is being modified.
     */
    readonly findingTitle?: string;
    /**
     * The list of findings_change_audit_log_collection.
     */
    readonly findingsChangeAuditLogCollections: outputs.DataSafe.GetSecurityAssessmentFindingsChangeAuditLogsFindingsChangeAuditLogCollection[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Determines if the user has deferred the risk level of this finding when he is ok with it  and does not plan to do anything about it.
     */
    readonly isRiskDeferred?: boolean;
    /**
     * The user who initiated change of risk level of the finding
     */
    readonly modifiedBy?: string;
    readonly securityAssessmentId: string;
    /**
     * The original severity / risk level of the finding as determined by security assessment.
     */
    readonly severity?: string;
    readonly timeUpdatedGreaterThanOrEqualTo?: string;
    readonly timeUpdatedLessThan?: string;
    readonly timeValidUntilGreaterThanOrEqualTo?: string;
    readonly timeValidUntilLessThan?: string;
}
/**
 * This data source provides the list of Security Assessment Findings Change Audit Logs in Oracle Cloud Infrastructure Data Safe service.
 *
 * List all changes made by user to risk level of findings of the specified assessment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSecurityAssessmentFindingsChangeAuditLogs = oci.DataSafe.getSecurityAssessmentFindingsChangeAuditLogs({
 *     securityAssessmentId: testSecurityAssessment.id,
 *     findingKey: securityAssessmentFindingsChangeAuditLogFindingKey,
 *     findingTitle: securityAssessmentFindingsChangeAuditLogFindingTitle,
 *     isRiskDeferred: securityAssessmentFindingsChangeAuditLogIsRiskDeferred,
 *     modifiedBy: securityAssessmentFindingsChangeAuditLogModifiedBy,
 *     severity: securityAssessmentFindingsChangeAuditLogSeverity,
 *     timeUpdatedGreaterThanOrEqualTo: securityAssessmentFindingsChangeAuditLogTimeUpdatedGreaterThanOrEqualTo,
 *     timeUpdatedLessThan: securityAssessmentFindingsChangeAuditLogTimeUpdatedLessThan,
 *     timeValidUntilGreaterThanOrEqualTo: securityAssessmentFindingsChangeAuditLogTimeValidUntilGreaterThanOrEqualTo,
 *     timeValidUntilLessThan: securityAssessmentFindingsChangeAuditLogTimeValidUntilLessThan,
 * });
 * ```
 */
export function getSecurityAssessmentFindingsChangeAuditLogsOutput(args: GetSecurityAssessmentFindingsChangeAuditLogsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSecurityAssessmentFindingsChangeAuditLogsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSecurityAssessmentFindingsChangeAuditLogs:getSecurityAssessmentFindingsChangeAuditLogs", {
        "filters": args.filters,
        "findingKey": args.findingKey,
        "findingTitle": args.findingTitle,
        "isRiskDeferred": args.isRiskDeferred,
        "modifiedBy": args.modifiedBy,
        "securityAssessmentId": args.securityAssessmentId,
        "severity": args.severity,
        "timeUpdatedGreaterThanOrEqualTo": args.timeUpdatedGreaterThanOrEqualTo,
        "timeUpdatedLessThan": args.timeUpdatedLessThan,
        "timeValidUntilGreaterThanOrEqualTo": args.timeValidUntilGreaterThanOrEqualTo,
        "timeValidUntilLessThan": args.timeValidUntilLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSecurityAssessmentFindingsChangeAuditLogs.
 */
export interface GetSecurityAssessmentFindingsChangeAuditLogsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSecurityAssessmentFindingsChangeAuditLogsFilterArgs>[]>;
    /**
     * The unique key that identifies the finding. It is a string and unique within a security assessment.
     */
    findingKey?: pulumi.Input<string>;
    /**
     * The unique title that identifies the finding. It is a string and unique within a security assessment.
     */
    findingTitle?: pulumi.Input<string>;
    /**
     * A filter to check findings whose risks were deferred by the user.
     */
    isRiskDeferred?: pulumi.Input<boolean>;
    /**
     * A filter to check which user modified the risk level of the finding.
     */
    modifiedBy?: pulumi.Input<string>;
    /**
     * The OCID of the security assessment.
     */
    securityAssessmentId: pulumi.Input<string>;
    /**
     * A filter to return only findings of a particular risk level.
     */
    severity?: pulumi.Input<string>;
    /**
     * Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     */
    timeUpdatedLessThan?: pulumi.Input<string>;
    /**
     * Specifying `TimeValidUntilGreaterThanOrEqualToQueryParam` parameter  will retrieve all items for which the risk level modification by user will  no longer be valid greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     *
     * **Example:** 2016-12-19T00:00:00.000Z
     */
    timeValidUntilGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Specifying `TimeValidUntilLessThanQueryParam` parameter will retrieve all items for which the risk level modification by user will  be valid until less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     *
     * **Example:** 2016-12-19T00:00:00.000Z
     */
    timeValidUntilLessThan?: pulumi.Input<string>;
}
