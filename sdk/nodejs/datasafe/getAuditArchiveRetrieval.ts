// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Audit Archive Retrieval resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified archive retreival.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAuditArchiveRetrieval = oci.DataSafe.getAuditArchiveRetrieval({
 *     auditArchiveRetrievalId: oci_data_safe_audit_archive_retrieval.test_audit_archive_retrieval.id,
 * });
 * ```
 */
export function getAuditArchiveRetrieval(args: GetAuditArchiveRetrievalArgs, opts?: pulumi.InvokeOptions): Promise<GetAuditArchiveRetrievalResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataSafe/getAuditArchiveRetrieval:getAuditArchiveRetrieval", {
        "auditArchiveRetrievalId": args.auditArchiveRetrievalId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAuditArchiveRetrieval.
 */
export interface GetAuditArchiveRetrievalArgs {
    /**
     * OCID of the archive retrieval.
     */
    auditArchiveRetrievalId: string;
}

/**
 * A collection of values returned by getAuditArchiveRetrieval.
 */
export interface GetAuditArchiveRetrievalResult {
    readonly auditArchiveRetrievalId: string;
    /**
     * Total count of audit events to be retrieved from the archive for the specified date range.
     */
    readonly auditEventCount: string;
    /**
     * The OCID of the compartment that contains archive retrieval.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Description of the archive retrieval.
     */
    readonly description: string;
    /**
     * The display name of the archive retrieval. The name does not have to be unique, and is changeable.
     */
    readonly displayName: string;
    /**
     * End month of the archive retrieval, in the format defined by RFC3339.
     */
    readonly endDate: string;
    /**
     * The Error details of a failed archive retrieval.
     */
    readonly errorInfo: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the archive retrieval.
     */
    readonly id: string;
    /**
     * Details about the current state of the archive retrieval.
     */
    readonly lifecycleDetails: string;
    /**
     * Start month of the archive retrieval, in the format defined by RFC3339.
     */
    readonly startDate: string;
    /**
     * The current state of the archive retrieval.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The OCID of the target associated with the archive retrieval.
     */
    readonly targetId: string;
    /**
     * The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
     */
    readonly timeCompleted: string;
    /**
     * The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
     */
    readonly timeOfExpiry: string;
    /**
     * The date time when archive retrieval was requested, in the format defined by RFC3339.
     */
    readonly timeRequested: string;
}

export function getAuditArchiveRetrievalOutput(args: GetAuditArchiveRetrievalOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAuditArchiveRetrievalResult> {
    return pulumi.output(args).apply(a => getAuditArchiveRetrieval(a, opts))
}

/**
 * A collection of arguments for invoking getAuditArchiveRetrieval.
 */
export interface GetAuditArchiveRetrievalOutputArgs {
    /**
     * OCID of the archive retrieval.
     */
    auditArchiveRetrievalId: pulumi.Input<string>;
}