// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides Masking Report Management resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified masking report.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingReportManagement = new oci.datasafe.MaskingReportManagement("test_masking_report_management", {
 *     targetId: testTargetDatabase.id,
 *     maskingPolicyId: testMaskingPolicy.id,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class MaskingReportManagement extends pulumi.CustomResource {
    /**
     * Get an existing MaskingReportManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MaskingReportManagementState, opts?: pulumi.CustomResourceOptions): MaskingReportManagement {
        return new MaskingReportManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/maskingReportManagement:MaskingReportManagement';

    /**
     * Returns true if the given object is an instance of MaskingReportManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MaskingReportManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MaskingReportManagement.__pulumiType;
    }

    /**
     * The OCID of the compartment that contains the masking report.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Indicates if the temporary tables created during the masking operation were dropped after masking.
     */
    public /*out*/ readonly isDropTempTablesEnabled!: pulumi.Output<boolean>;
    /**
     * Indicates if redo logging was enabled during the masking operation.
     */
    public /*out*/ readonly isRedoLoggingEnabled!: pulumi.Output<boolean>;
    /**
     * Indicates if statistics gathering was enabled during the masking operation.
     */
    public /*out*/ readonly isRefreshStatsEnabled!: pulumi.Output<boolean>;
    /**
     * The OCID of the masking policy.
     */
    public readonly maskingPolicyId!: pulumi.Output<string>;
    /**
     * The OCID of the masking work request that resulted in this masking report.
     */
    public /*out*/ readonly maskingWorkRequestId!: pulumi.Output<string>;
    /**
     * Indicates if parallel execution was enabled during the masking operation.
     */
    public /*out*/ readonly parallelDegree!: pulumi.Output<string>;
    /**
     * Indicates how invalid objects were recompiled post the masking operation.
     */
    public /*out*/ readonly recompile!: pulumi.Output<string>;
    /**
     * The current state of the masking report.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The OCID of the target database masked.
     */
    public readonly targetId!: pulumi.Output<string>;
    /**
     * The date and time the masking report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time data masking finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    public /*out*/ readonly timeMaskingFinished!: pulumi.Output<string>;
    /**
     * The date and time data masking started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    public /*out*/ readonly timeMaskingStarted!: pulumi.Output<string>;
    /**
     * The total number of masked columns.
     */
    public /*out*/ readonly totalMaskedColumns!: pulumi.Output<string>;
    /**
     * The total number of unique objects (tables and editioning views) that contain the masked columns.
     */
    public /*out*/ readonly totalMaskedObjects!: pulumi.Output<string>;
    /**
     * The total number of unique schemas that contain the masked columns.
     */
    public /*out*/ readonly totalMaskedSchemas!: pulumi.Output<string>;
    /**
     * The total number of unique sensitive types associated with the masked columns.
     */
    public /*out*/ readonly totalMaskedSensitiveTypes!: pulumi.Output<string>;
    /**
     * The total number of masked values.
     */
    public /*out*/ readonly totalMaskedValues!: pulumi.Output<string>;

    /**
     * Create a MaskingReportManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: MaskingReportManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MaskingReportManagementArgs | MaskingReportManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MaskingReportManagementState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["isDropTempTablesEnabled"] = state ? state.isDropTempTablesEnabled : undefined;
            resourceInputs["isRedoLoggingEnabled"] = state ? state.isRedoLoggingEnabled : undefined;
            resourceInputs["isRefreshStatsEnabled"] = state ? state.isRefreshStatsEnabled : undefined;
            resourceInputs["maskingPolicyId"] = state ? state.maskingPolicyId : undefined;
            resourceInputs["maskingWorkRequestId"] = state ? state.maskingWorkRequestId : undefined;
            resourceInputs["parallelDegree"] = state ? state.parallelDegree : undefined;
            resourceInputs["recompile"] = state ? state.recompile : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["targetId"] = state ? state.targetId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeMaskingFinished"] = state ? state.timeMaskingFinished : undefined;
            resourceInputs["timeMaskingStarted"] = state ? state.timeMaskingStarted : undefined;
            resourceInputs["totalMaskedColumns"] = state ? state.totalMaskedColumns : undefined;
            resourceInputs["totalMaskedObjects"] = state ? state.totalMaskedObjects : undefined;
            resourceInputs["totalMaskedSchemas"] = state ? state.totalMaskedSchemas : undefined;
            resourceInputs["totalMaskedSensitiveTypes"] = state ? state.totalMaskedSensitiveTypes : undefined;
            resourceInputs["totalMaskedValues"] = state ? state.totalMaskedValues : undefined;
        } else {
            const args = argsOrState as MaskingReportManagementArgs | undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["maskingPolicyId"] = args ? args.maskingPolicyId : undefined;
            resourceInputs["targetId"] = args ? args.targetId : undefined;
            resourceInputs["isDropTempTablesEnabled"] = undefined /*out*/;
            resourceInputs["isRedoLoggingEnabled"] = undefined /*out*/;
            resourceInputs["isRefreshStatsEnabled"] = undefined /*out*/;
            resourceInputs["maskingWorkRequestId"] = undefined /*out*/;
            resourceInputs["parallelDegree"] = undefined /*out*/;
            resourceInputs["recompile"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeMaskingFinished"] = undefined /*out*/;
            resourceInputs["timeMaskingStarted"] = undefined /*out*/;
            resourceInputs["totalMaskedColumns"] = undefined /*out*/;
            resourceInputs["totalMaskedObjects"] = undefined /*out*/;
            resourceInputs["totalMaskedSchemas"] = undefined /*out*/;
            resourceInputs["totalMaskedSensitiveTypes"] = undefined /*out*/;
            resourceInputs["totalMaskedValues"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MaskingReportManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MaskingReportManagement resources.
 */
export interface MaskingReportManagementState {
    /**
     * The OCID of the compartment that contains the masking report.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Indicates if the temporary tables created during the masking operation were dropped after masking.
     */
    isDropTempTablesEnabled?: pulumi.Input<boolean>;
    /**
     * Indicates if redo logging was enabled during the masking operation.
     */
    isRedoLoggingEnabled?: pulumi.Input<boolean>;
    /**
     * Indicates if statistics gathering was enabled during the masking operation.
     */
    isRefreshStatsEnabled?: pulumi.Input<boolean>;
    /**
     * The OCID of the masking policy.
     */
    maskingPolicyId?: pulumi.Input<string>;
    /**
     * The OCID of the masking work request that resulted in this masking report.
     */
    maskingWorkRequestId?: pulumi.Input<string>;
    /**
     * Indicates if parallel execution was enabled during the masking operation.
     */
    parallelDegree?: pulumi.Input<string>;
    /**
     * Indicates how invalid objects were recompiled post the masking operation.
     */
    recompile?: pulumi.Input<string>;
    /**
     * The current state of the masking report.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the target database masked.
     */
    targetId?: pulumi.Input<string>;
    /**
     * The date and time the masking report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time data masking finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    timeMaskingFinished?: pulumi.Input<string>;
    /**
     * The date and time data masking started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    timeMaskingStarted?: pulumi.Input<string>;
    /**
     * The total number of masked columns.
     */
    totalMaskedColumns?: pulumi.Input<string>;
    /**
     * The total number of unique objects (tables and editioning views) that contain the masked columns.
     */
    totalMaskedObjects?: pulumi.Input<string>;
    /**
     * The total number of unique schemas that contain the masked columns.
     */
    totalMaskedSchemas?: pulumi.Input<string>;
    /**
     * The total number of unique sensitive types associated with the masked columns.
     */
    totalMaskedSensitiveTypes?: pulumi.Input<string>;
    /**
     * The total number of masked values.
     */
    totalMaskedValues?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MaskingReportManagement resource.
 */
export interface MaskingReportManagementArgs {
    /**
     * The OCID of the compartment that contains the masking report.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The OCID of the masking policy.
     */
    maskingPolicyId?: pulumi.Input<string>;
    /**
     * The OCID of the target database masked.
     */
    targetId?: pulumi.Input<string>;
}
