// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Masking Policy resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Creates a new masking policy and associates it with a sensitive data model or a target database.
 *
 * To use a sensitive data model as the source of masking columns, set the columnSource attribute to
 * SENSITIVE_DATA_MODEL and provide the sensitiveDataModelId attribute. After creating a masking policy,
 * you can use the AddMaskingColumnsFromSdm operation to automatically add all the columns from
 * the associated sensitive data model. In this case, the target database associated with the
 * sensitive data model is used for column and masking format validations.
 *
 * You can also create a masking policy without using a sensitive data model. In this case,
 * you need to associate your masking policy with a target database by setting the columnSource
 * attribute to TARGET and providing the targetId attribute. The specified target database
 * is used for column and masking format validations.
 *
 * After creating a masking policy, you can use the CreateMaskingColumn or PatchMaskingColumns
 * operation to manually add columns to the policy. You need to add the parent columns only,
 * and it automatically adds the child columns (in referential relationship with the parent columns)
 * from the associated sensitive data model or target database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingPolicy = new oci.datasafe.MaskingPolicy("test_masking_policy", {
 *     columnSources: [{
 *         columnSource: maskingPolicyColumnSourceColumnSource,
 *         sensitiveDataModelId: testSensitiveDataModel.id,
 *         targetId: testTarget.id,
 *     }],
 *     compartmentId: compartmentId,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: maskingPolicyDescription,
 *     displayName: maskingPolicyDisplayName,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isDropTempTablesEnabled: maskingPolicyIsDropTempTablesEnabled,
 *     isRedoLoggingEnabled: maskingPolicyIsRedoLoggingEnabled,
 *     isRefreshStatsEnabled: maskingPolicyIsRefreshStatsEnabled,
 *     parallelDegree: maskingPolicyParallelDegree,
 *     postMaskingScript: maskingPolicyPostMaskingScript,
 *     preMaskingScript: maskingPolicyPreMaskingScript,
 *     recompile: maskingPolicyRecompile,
 * });
 * ```
 *
 * ## Import
 *
 * MaskingPolicies can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataSafe/maskingPolicy:MaskingPolicy test_masking_policy "id"
 * ```
 */
export class MaskingPolicy extends pulumi.CustomResource {
    /**
     * Get an existing MaskingPolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MaskingPolicyState, opts?: pulumi.CustomResourceOptions): MaskingPolicy {
        return new MaskingPolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/maskingPolicy:MaskingPolicy';

    /**
     * Returns true if the given object is an instance of MaskingPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MaskingPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MaskingPolicy.__pulumiType;
    }

    /**
     * (Updatable) An optional property when incremented triggers Add Masking Columns From Sdm. Could be set to any integer value.
     */
    public readonly addMaskingColumnsFromSdmTrigger!: pulumi.Output<number | undefined>;
    /**
     * (Updatable) Details to associate a column source with a masking policy.
     */
    public readonly columnSources!: pulumi.Output<outputs.DataSafe.MaskingPolicyColumnSource[]>;
    /**
     * (Updatable) The OCID of the compartment where the masking policy should be created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The description of the masking policy.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the masking policy. The name does not have to be unique, and it's changeable.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) An optional property when incremented triggers Generate Health Report. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly generateHealthReportTrigger!: pulumi.Output<number | undefined>;
    /**
     * (Updatable) Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default. Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive  data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want  to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables  must be dropped before the database is available for unprivileged users.
     */
    public readonly isDropTempTablesEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked  data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking, you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.
     */
    public readonly isRedoLoggingEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics gathering. The masking process gathers statistics on masked database tables after masking completes.
     */
    public readonly isRefreshStatsEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism), 'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree of parallelism. Parallel execution helps effectively use multiple CPUs and improve masking performance. Refer to the Oracle Database parallel execution framework when choosing an explicit degree of parallelism.
     */
    public readonly parallelDegree!: pulumi.Output<string>;
    /**
     * (Updatable) A post-masking script, which can contain SQL and PL/SQL statements. It's executed after the core masking script generated using the masking policy. It's usually used to perform additional transformation or cleanup work after masking.
     */
    public readonly postMaskingScript!: pulumi.Output<string>;
    /**
     * (Updatable) A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before  the core masking script generated using the masking policy. It's usually used to perform any preparation or prerequisite work before masking data.
     */
    public readonly preMaskingScript!: pulumi.Output<string>;
    /**
     * (Updatable) Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),  'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree attribute is used. Use the built-in UTL_RECOMP package to recompile any remaining invalid objects after masking completes.
     */
    public readonly recompile!: pulumi.Output<string>;
    /**
     * The current state of the masking policy.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the masking policy was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the masking policy was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a MaskingPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MaskingPolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MaskingPolicyArgs | MaskingPolicyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MaskingPolicyState | undefined;
            resourceInputs["addMaskingColumnsFromSdmTrigger"] = state ? state.addMaskingColumnsFromSdmTrigger : undefined;
            resourceInputs["columnSources"] = state ? state.columnSources : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["generateHealthReportTrigger"] = state ? state.generateHealthReportTrigger : undefined;
            resourceInputs["isDropTempTablesEnabled"] = state ? state.isDropTempTablesEnabled : undefined;
            resourceInputs["isRedoLoggingEnabled"] = state ? state.isRedoLoggingEnabled : undefined;
            resourceInputs["isRefreshStatsEnabled"] = state ? state.isRefreshStatsEnabled : undefined;
            resourceInputs["parallelDegree"] = state ? state.parallelDegree : undefined;
            resourceInputs["postMaskingScript"] = state ? state.postMaskingScript : undefined;
            resourceInputs["preMaskingScript"] = state ? state.preMaskingScript : undefined;
            resourceInputs["recompile"] = state ? state.recompile : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as MaskingPolicyArgs | undefined;
            if ((!args || args.columnSources === undefined) && !opts.urn) {
                throw new Error("Missing required property 'columnSources'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["addMaskingColumnsFromSdmTrigger"] = args ? args.addMaskingColumnsFromSdmTrigger : undefined;
            resourceInputs["columnSources"] = args ? args.columnSources : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["generateHealthReportTrigger"] = args ? args.generateHealthReportTrigger : undefined;
            resourceInputs["isDropTempTablesEnabled"] = args ? args.isDropTempTablesEnabled : undefined;
            resourceInputs["isRedoLoggingEnabled"] = args ? args.isRedoLoggingEnabled : undefined;
            resourceInputs["isRefreshStatsEnabled"] = args ? args.isRefreshStatsEnabled : undefined;
            resourceInputs["parallelDegree"] = args ? args.parallelDegree : undefined;
            resourceInputs["postMaskingScript"] = args ? args.postMaskingScript : undefined;
            resourceInputs["preMaskingScript"] = args ? args.preMaskingScript : undefined;
            resourceInputs["recompile"] = args ? args.recompile : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MaskingPolicy.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MaskingPolicy resources.
 */
export interface MaskingPolicyState {
    /**
     * (Updatable) An optional property when incremented triggers Add Masking Columns From Sdm. Could be set to any integer value.
     */
    addMaskingColumnsFromSdmTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) Details to associate a column source with a masking policy.
     */
    columnSources?: pulumi.Input<pulumi.Input<inputs.DataSafe.MaskingPolicyColumnSource>[]>;
    /**
     * (Updatable) The OCID of the compartment where the masking policy should be created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The description of the masking policy.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the masking policy. The name does not have to be unique, and it's changeable.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) An optional property when incremented triggers Generate Health Report. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    generateHealthReportTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default. Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive  data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want  to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables  must be dropped before the database is available for unprivileged users.
     */
    isDropTempTablesEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked  data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking, you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.
     */
    isRedoLoggingEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics gathering. The masking process gathers statistics on masked database tables after masking completes.
     */
    isRefreshStatsEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism), 'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree of parallelism. Parallel execution helps effectively use multiple CPUs and improve masking performance. Refer to the Oracle Database parallel execution framework when choosing an explicit degree of parallelism.
     */
    parallelDegree?: pulumi.Input<string>;
    /**
     * (Updatable) A post-masking script, which can contain SQL and PL/SQL statements. It's executed after the core masking script generated using the masking policy. It's usually used to perform additional transformation or cleanup work after masking.
     */
    postMaskingScript?: pulumi.Input<string>;
    /**
     * (Updatable) A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before  the core masking script generated using the masking policy. It's usually used to perform any preparation or prerequisite work before masking data.
     */
    preMaskingScript?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),  'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree attribute is used. Use the built-in UTL_RECOMP package to recompile any remaining invalid objects after masking completes.
     */
    recompile?: pulumi.Input<string>;
    /**
     * The current state of the masking policy.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the masking policy was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the masking policy was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MaskingPolicy resource.
 */
export interface MaskingPolicyArgs {
    /**
     * (Updatable) An optional property when incremented triggers Add Masking Columns From Sdm. Could be set to any integer value.
     */
    addMaskingColumnsFromSdmTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) Details to associate a column source with a masking policy.
     */
    columnSources: pulumi.Input<pulumi.Input<inputs.DataSafe.MaskingPolicyColumnSource>[]>;
    /**
     * (Updatable) The OCID of the compartment where the masking policy should be created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The description of the masking policy.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the masking policy. The name does not have to be unique, and it's changeable.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) An optional property when incremented triggers Generate Health Report. Could be set to any integer value.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    generateHealthReportTrigger?: pulumi.Input<number>;
    /**
     * (Updatable) Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default. Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive  data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want  to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables  must be dropped before the database is available for unprivileged users.
     */
    isDropTempTablesEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked  data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking, you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.
     */
    isRedoLoggingEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics gathering. The masking process gathers statistics on masked database tables after masking completes.
     */
    isRefreshStatsEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism), 'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree of parallelism. Parallel execution helps effectively use multiple CPUs and improve masking performance. Refer to the Oracle Database parallel execution framework when choosing an explicit degree of parallelism.
     */
    parallelDegree?: pulumi.Input<string>;
    /**
     * (Updatable) A post-masking script, which can contain SQL and PL/SQL statements. It's executed after the core masking script generated using the masking policy. It's usually used to perform additional transformation or cleanup work after masking.
     */
    postMaskingScript?: pulumi.Input<string>;
    /**
     * (Updatable) A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before  the core masking script generated using the masking policy. It's usually used to perform any preparation or prerequisite work before masking data.
     */
    preMaskingScript?: pulumi.Input<string>;
    /**
     * (Updatable) Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),  'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree attribute is used. Use the built-in UTL_RECOMP package to recompile any remaining invalid objects after masking completes.
     */
    recompile?: pulumi.Input<string>;
}
