// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Discovery Job resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * API to get the details of discovery Job by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDiscoveryJob = oci.StackMonitoring.getDiscoveryJob({
 *     discoveryJobId: oci_stack_monitoring_discovery_job.test_discovery_job.id,
 * });
 * ```
 */
export function getDiscoveryJob(args: GetDiscoveryJobArgs, opts?: pulumi.InvokeOptions): Promise<GetDiscoveryJobResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:StackMonitoring/getDiscoveryJob:getDiscoveryJob", {
        "discoveryJobId": args.discoveryJobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDiscoveryJob.
 */
export interface GetDiscoveryJobArgs {
    /**
     * The Discovery Job ID
     */
    discoveryJobId: string;
}

/**
 * A collection of values returned by getDiscoveryJob.
 */
export interface GetDiscoveryJobResult {
    /**
     * The OCID of the Compartment
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Client who submits discovery job.
     */
    readonly discoveryClient: string;
    /**
     * The request of DiscoveryJob Resource details.
     */
    readonly discoveryDetails: outputs.StackMonitoring.GetDiscoveryJobDiscoveryDetail[];
    readonly discoveryJobId: string;
    /**
     * Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
     */
    readonly discoveryType: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of Discovery job
     */
    readonly id: string;
    /**
     * The current state of the DiscoveryJob Resource.
     */
    readonly state: string;
    /**
     * Specifies the status of the discovery job
     */
    readonly status: string;
    /**
     * The short summary of the status of the discovery job
     */
    readonly statusMessage: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The OCID of Tenant
     */
    readonly tenantId: string;
    /**
     * The time the discovery Job was updated.
     */
    readonly timeUpdated: string;
    /**
     * The OCID of user in which the job is submitted
     */
    readonly userId: string;
}

export function getDiscoveryJobOutput(args: GetDiscoveryJobOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDiscoveryJobResult> {
    return pulumi.output(args).apply(a => getDiscoveryJob(a, opts))
}

/**
 * A collection of arguments for invoking getDiscoveryJob.
 */
export interface GetDiscoveryJobOutputArgs {
    /**
     * The Discovery Job ID
     */
    discoveryJobId: pulumi.Input<string>;
}