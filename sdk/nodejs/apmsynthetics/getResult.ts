// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Result resource in Oracle Cloud Infrastructure Apm Synthetics service.
 *
 * Gets the results for a specific execution of a monitor identified by OCID. The results are in a HAR file, Screenshot, Console Log or Network details.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testResult = oci.ApmSynthetics.getResult({
 *     apmDomainId: oci_apm_synthetics_apm_domain.test_apm_domain.id,
 *     executionTime: _var.result_execution_time,
 *     monitorId: oci_apm_synthetics_monitor.test_monitor.id,
 *     resultContentType: _var.result_result_content_type,
 *     resultType: _var.result_result_type,
 *     vantagePoint: _var.result_vantage_point,
 * });
 * ```
 */
export function getResult(args: GetResultArgs, opts?: pulumi.InvokeOptions): Promise<GetResultResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ApmSynthetics/getResult:getResult", {
        "apmDomainId": args.apmDomainId,
        "executionTime": args.executionTime,
        "monitorId": args.monitorId,
        "resultContentType": args.resultContentType,
        "resultType": args.resultType,
        "vantagePoint": args.vantagePoint,
    }, opts);
}

/**
 * A collection of arguments for invoking getResult.
 */
export interface GetResultArgs {
    /**
     * The APM domain ID the request is intended for.
     */
    apmDomainId: string;
    /**
     * The time the object was posted.
     */
    executionTime: string;
    /**
     * The OCID of the monitor.
     */
    monitorId: string;
    /**
     * The result content type: zip or raw.
     */
    resultContentType: string;
    /**
     * The result type: har, screenshot, log, or network.
     */
    resultType: string;
    /**
     * The vantagePoint name.
     */
    vantagePoint: string;
}

/**
 * A collection of values returned by getResult.
 */
export interface GetResultResult {
    readonly apmDomainId: string;
    /**
     * The specific point of time when the result of an execution is collected.
     */
    readonly executionTime: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
     */
    readonly monitorId: string;
    /**
     * Type of result content. Example: Zip or Raw file.
     */
    readonly resultContentType: string;
    /**
     * Monitor result data set.
     */
    readonly resultDataSets: outputs.ApmSynthetics.GetResultResultDataSet[];
    /**
     * Type of result. Example: HAR, Screenshot, Log or Network.
     */
    readonly resultType: string;
    /**
     * The name of the public or dedicated vantage point.
     */
    readonly vantagePoint: string;
}

export function getResultOutput(args: GetResultOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetResultResult> {
    return pulumi.output(args).apply(a => getResult(a, opts))
}

/**
 * A collection of arguments for invoking getResult.
 */
export interface GetResultOutputArgs {
    /**
     * The APM domain ID the request is intended for.
     */
    apmDomainId: pulumi.Input<string>;
    /**
     * The time the object was posted.
     */
    executionTime: pulumi.Input<string>;
    /**
     * The OCID of the monitor.
     */
    monitorId: pulumi.Input<string>;
    /**
     * The result content type: zip or raw.
     */
    resultContentType: pulumi.Input<string>;
    /**
     * The result type: har, screenshot, log, or network.
     */
    resultType: pulumi.Input<string>;
    /**
     * The vantagePoint name.
     */
    vantagePoint: pulumi.Input<string>;
}