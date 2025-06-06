// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Log Analytics Unprocessed Data Bucket Management resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * This API configures a bucket to store unprocessed payloads.
 * While processing there could be reasons a payload cannot be processed (mismatched structure, corrupted archive format, etc),
 * if configured the payload would be uploaded to the bucket for verification.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLogAnalyticsUnprocessedDataBucketManagement = new oci.loganalytics.LogAnalyticsUnprocessedDataBucketManagement("test_log_analytics_unprocessed_data_bucket_management", {
 *     bucket: logAnalyticsUnprocessedDataBucketManagementBucket,
 *     namespace: logAnalyticsUnprocessedDataBucketManagementNamespace,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for LogAnalyticsUnprocessedDataBucketManagement
 */
export class LogAnalyticsUnprocessedDataBucketManagement extends pulumi.CustomResource {
    /**
     * Get an existing LogAnalyticsUnprocessedDataBucketManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LogAnalyticsUnprocessedDataBucketManagementState, opts?: pulumi.CustomResourceOptions): LogAnalyticsUnprocessedDataBucketManagement {
        return new LogAnalyticsUnprocessedDataBucketManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:LogAnalytics/logAnalyticsUnprocessedDataBucketManagement:LogAnalyticsUnprocessedDataBucketManagement';

    /**
     * Returns true if the given object is an instance of LogAnalyticsUnprocessedDataBucketManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LogAnalyticsUnprocessedDataBucketManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LogAnalyticsUnprocessedDataBucketManagement.__pulumiType;
    }

    /**
     * Name of the Object Storage bucket.
     */
    public readonly bucket!: pulumi.Output<string>;
    /**
     * Flag that specifies if this configuration is enabled or not.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * The Logging Analytics namespace used for the request. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly namespace!: pulumi.Output<string>;
    /**
     * The time when this record is created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The latest time when this record is updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a LogAnalyticsUnprocessedDataBucketManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: LogAnalyticsUnprocessedDataBucketManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LogAnalyticsUnprocessedDataBucketManagementArgs | LogAnalyticsUnprocessedDataBucketManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as LogAnalyticsUnprocessedDataBucketManagementState | undefined;
            resourceInputs["bucket"] = state ? state.bucket : undefined;
            resourceInputs["isEnabled"] = state ? state.isEnabled : undefined;
            resourceInputs["namespace"] = state ? state.namespace : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as LogAnalyticsUnprocessedDataBucketManagementArgs | undefined;
            if ((!args || args.bucket === undefined) && !opts.urn) {
                throw new Error("Missing required property 'bucket'");
            }
            if ((!args || args.namespace === undefined) && !opts.urn) {
                throw new Error("Missing required property 'namespace'");
            }
            resourceInputs["bucket"] = args ? args.bucket : undefined;
            resourceInputs["isEnabled"] = args ? args.isEnabled : undefined;
            resourceInputs["namespace"] = args ? args.namespace : undefined;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(LogAnalyticsUnprocessedDataBucketManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LogAnalyticsUnprocessedDataBucketManagement resources.
 */
export interface LogAnalyticsUnprocessedDataBucketManagementState {
    /**
     * Name of the Object Storage bucket.
     */
    bucket?: pulumi.Input<string>;
    /**
     * Flag that specifies if this configuration is enabled or not.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * The Logging Analytics namespace used for the request. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    namespace?: pulumi.Input<string>;
    /**
     * The time when this record is created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The latest time when this record is updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a LogAnalyticsUnprocessedDataBucketManagement resource.
 */
export interface LogAnalyticsUnprocessedDataBucketManagementArgs {
    /**
     * Name of the Object Storage bucket.
     */
    bucket: pulumi.Input<string>;
    /**
     * Flag that specifies if this configuration is enabled or not.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * The Logging Analytics namespace used for the request. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    namespace: pulumi.Input<string>;
}
