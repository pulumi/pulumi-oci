// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Api Validation resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets the API validation results.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApiValidation = oci.ApiGateway.getApiValidation({
 *     apiId: testApi.id,
 * });
 * ```
 */
export function getApiValidation(args: GetApiValidationArgs, opts?: pulumi.InvokeOptions): Promise<GetApiValidationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ApiGateway/getApiValidation:getApiValidation", {
        "apiId": args.apiId,
    }, opts);
}

/**
 * A collection of arguments for invoking getApiValidation.
 */
export interface GetApiValidationArgs {
    /**
     * The ocid of the API.
     */
    apiId: string;
}

/**
 * A collection of values returned by getApiValidation.
 */
export interface GetApiValidationResult {
    readonly apiId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * API validation results.
     */
    readonly validations: outputs.ApiGateway.GetApiValidationValidation[];
}
/**
 * This data source provides details about a specific Api Validation resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets the API validation results.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApiValidation = oci.ApiGateway.getApiValidation({
 *     apiId: testApi.id,
 * });
 * ```
 */
export function getApiValidationOutput(args: GetApiValidationOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetApiValidationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ApiGateway/getApiValidation:getApiValidation", {
        "apiId": args.apiId,
    }, opts);
}

/**
 * A collection of arguments for invoking getApiValidation.
 */
export interface GetApiValidationOutputArgs {
    /**
     * The ocid of the API.
     */
    apiId: pulumi.Input<string>;
}
