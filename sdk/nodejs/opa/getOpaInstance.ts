// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
 *
 * Gets a OpaInstance by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOpaInstance = oci.Opa.getOpaInstance({
 *     opaInstanceId: oci_opa_opa_instance.test_opa_instance.id,
 * });
 * ```
 */
export function getOpaInstance(args: GetOpaInstanceArgs, opts?: pulumi.InvokeOptions): Promise<GetOpaInstanceResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Opa/getOpaInstance:getOpaInstance", {
        "opaInstanceId": args.opaInstanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOpaInstance.
 */
export interface GetOpaInstanceArgs {
    /**
     * unique OpaInstance identifier
     */
    opaInstanceId: string;
}

/**
 * A collection of values returned by getOpaInstance.
 */
export interface GetOpaInstanceResult {
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    /**
     * The entitlement used for billing purposes
     */
    readonly consumptionModel: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Description of the Process Automation instance.
     */
    readonly description: string;
    /**
     * OpaInstance Identifier, can be renamed
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Unique identifier that is immutable on creation
     */
    readonly id: string;
    readonly idcsAt: string;
    /**
     * This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    readonly identityAppDisplayName: string;
    /**
     * This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
     */
    readonly identityAppGuid: string;
    /**
     * This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    readonly identityAppOpcServiceInstanceGuid: string;
    /**
     * This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
     */
    readonly identityDomainUrl: string;
    /**
     * OPA Instance URL
     */
    readonly instanceUrl: string;
    /**
     * indicates if breakGlass is enabled for the opa instance.
     */
    readonly isBreakglassEnabled: boolean;
    /**
     * MeteringType Identifier
     */
    readonly meteringType: string;
    readonly opaInstanceId: string;
    /**
     * Shape of the instance.
     */
    readonly shapeName: string;
    /**
     * The current state of the OpaInstance.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time when OpaInstance was created. An RFC3339 formatted datetime string
     */
    readonly timeCreated: string;
    /**
     * The time the OpaInstance was updated. An RFC3339 formatted datetime string
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Opa Instance resource in Oracle Cloud Infrastructure Opa service.
 *
 * Gets a OpaInstance by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOpaInstance = oci.Opa.getOpaInstance({
 *     opaInstanceId: oci_opa_opa_instance.test_opa_instance.id,
 * });
 * ```
 */
export function getOpaInstanceOutput(args: GetOpaInstanceOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetOpaInstanceResult> {
    return pulumi.output(args).apply((a: any) => getOpaInstance(a, opts))
}

/**
 * A collection of arguments for invoking getOpaInstance.
 */
export interface GetOpaInstanceOutputArgs {
    /**
     * unique OpaInstance identifier
     */
    opaInstanceId: pulumi.Input<string>;
}