// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Objects in Oracle Cloud Infrastructure Object Storage service.
 *
 * Lists the objects in a bucket. By default, ListObjects returns object names only. See the `fields`
 * parameter for other fields that you can optionally include in ListObjects response.
 *
 * ListObjects returns at most 1000 objects. To paginate through more objects, use the returned 'nextStartWith'
 * value with the 'start' parameter. To filter which objects ListObjects returns, use the 'start' and 'end'
 * parameters.
 *
 * To use this and other API operations, you must be authorized in an IAM policy. If you are not authorized,
 * talk to an administrator. If you are an administrator who needs to write policies to give users access, see
 * [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
 */
export function getObjects(args: GetObjectsArgs, opts?: pulumi.InvokeOptions): Promise<GetObjectsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ObjectStorage/getObjects:getObjects", {
        "bucket": args.bucket,
        "delimiter": args.delimiter,
        "end": args.end,
        "filters": args.filters,
        "namespace": args.namespace,
        "prefix": args.prefix,
        "start": args.start,
        "startAfter": args.startAfter,
    }, opts);
}

/**
 * A collection of arguments for invoking getObjects.
 */
export interface GetObjectsArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: string;
    /**
     * When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only '/' is a supported delimiter character at this time.
     */
    delimiter?: string;
    /**
     * Returns object names which are lexicographically strictly less than this parameter.
     */
    end?: string;
    filters?: inputs.ObjectStorage.GetObjectsFilter[];
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: string;
    /**
     * The string to use for matching against the start of object names in a list query.
     */
    prefix?: string;
    /**
     * Returns object names which are lexicographically greater than or equal to this parameter.
     */
    start?: string;
    /**
     * Returns object names which are lexicographically strictly greater than this parameter.
     */
    startAfter?: string;
}

/**
 * A collection of values returned by getObjects.
 */
export interface GetObjectsResult {
    readonly bucket: string;
    readonly delimiter?: string;
    readonly end?: string;
    readonly filters?: outputs.ObjectStorage.GetObjectsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly namespace: string;
    /**
     * The list of list_objects.
     */
    readonly objects: outputs.ObjectStorage.GetObjectsObject[];
    readonly prefix?: string;
    readonly prefixes: string[];
    readonly start?: string;
    readonly startAfter?: string;
}
/**
 * This data source provides the list of Objects in Oracle Cloud Infrastructure Object Storage service.
 *
 * Lists the objects in a bucket. By default, ListObjects returns object names only. See the `fields`
 * parameter for other fields that you can optionally include in ListObjects response.
 *
 * ListObjects returns at most 1000 objects. To paginate through more objects, use the returned 'nextStartWith'
 * value with the 'start' parameter. To filter which objects ListObjects returns, use the 'start' and 'end'
 * parameters.
 *
 * To use this and other API operations, you must be authorized in an IAM policy. If you are not authorized,
 * talk to an administrator. If you are an administrator who needs to write policies to give users access, see
 * [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
 */
export function getObjectsOutput(args: GetObjectsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetObjectsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ObjectStorage/getObjects:getObjects", {
        "bucket": args.bucket,
        "delimiter": args.delimiter,
        "end": args.end,
        "filters": args.filters,
        "namespace": args.namespace,
        "prefix": args.prefix,
        "start": args.start,
        "startAfter": args.startAfter,
    }, opts);
}

/**
 * A collection of arguments for invoking getObjects.
 */
export interface GetObjectsOutputArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: pulumi.Input<string>;
    /**
     * When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only '/' is a supported delimiter character at this time.
     */
    delimiter?: pulumi.Input<string>;
    /**
     * Returns object names which are lexicographically strictly less than this parameter.
     */
    end?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ObjectStorage.GetObjectsFilterArgs>[]>;
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: pulumi.Input<string>;
    /**
     * The string to use for matching against the start of object names in a list query.
     */
    prefix?: pulumi.Input<string>;
    /**
     * Returns object names which are lexicographically greater than or equal to this parameter.
     */
    start?: pulumi.Input<string>;
    /**
     * Returns object names which are lexicographically strictly greater than this parameter.
     */
    startAfter?: pulumi.Input<string>;
}
