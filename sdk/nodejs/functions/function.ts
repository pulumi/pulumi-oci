// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Function resource in Oracle Cloud Infrastructure Functions service.
 *
 * Creates a new function.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFunction = new oci.functions.Function("testFunction", {
 *     applicationId: oci_functions_application.test_application.id,
 *     displayName: _var.function_display_name,
 *     image: _var.function_image,
 *     memoryInMbs: _var.function_memory_in_mbs,
 *     config: _var.function_config,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     imageDigest: _var.function_image_digest,
 *     provisionedConcurrencyConfig: {
 *         strategy: _var.function_provisioned_concurrency_config_strategy,
 *         count: _var.function_provisioned_concurrency_config_count,
 *     },
 *     timeoutInSeconds: _var.function_timeout_in_seconds,
 *     traceConfig: {
 *         isEnabled: _var.function_trace_config_is_enabled,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Functions can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Functions/function:Function test_function "id"
 * ```
 */
export class Function extends pulumi.CustomResource {
    /**
     * Get an existing Function resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FunctionState, opts?: pulumi.CustomResourceOptions): Function {
        return new Function(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Functions/function:Function';

    /**
     * Returns true if the given object is an instance of Function.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Function {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Function.__pulumiType;
    }

    /**
     * The OCID of the application this function belongs to.
     */
    public readonly applicationId!: pulumi.Output<string>;
    /**
     * The OCID of the compartment that contains the function.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
     */
    public readonly config!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     */
    public readonly image!: pulumi.Output<string>;
    /**
     * (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     */
    public readonly imageDigest!: pulumi.Output<string>;
    /**
     * The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
     */
    public /*out*/ readonly invokeEndpoint!: pulumi.Output<string>;
    /**
     * (Updatable) Maximum usable memory for the function (MiB).
     */
    public readonly memoryInMbs!: pulumi.Output<string>;
    /**
     * (Updatable) Define the strategy for provisioned concurrency for the function.
     */
    public readonly provisionedConcurrencyConfig!: pulumi.Output<outputs.Functions.FunctionProvisionedConcurrencyConfig>;
    /**
     * The current state of the function.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) Timeout for executions of the function. Value in seconds.
     */
    public readonly timeoutInSeconds!: pulumi.Output<number>;
    /**
     * (Updatable) Define the tracing configuration for a function.
     */
    public readonly traceConfig!: pulumi.Output<outputs.Functions.FunctionTraceConfig>;

    /**
     * Create a Function resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FunctionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FunctionArgs | FunctionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FunctionState | undefined;
            resourceInputs["applicationId"] = state ? state.applicationId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["config"] = state ? state.config : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["image"] = state ? state.image : undefined;
            resourceInputs["imageDigest"] = state ? state.imageDigest : undefined;
            resourceInputs["invokeEndpoint"] = state ? state.invokeEndpoint : undefined;
            resourceInputs["memoryInMbs"] = state ? state.memoryInMbs : undefined;
            resourceInputs["provisionedConcurrencyConfig"] = state ? state.provisionedConcurrencyConfig : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["timeoutInSeconds"] = state ? state.timeoutInSeconds : undefined;
            resourceInputs["traceConfig"] = state ? state.traceConfig : undefined;
        } else {
            const args = argsOrState as FunctionArgs | undefined;
            if ((!args || args.applicationId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'applicationId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.image === undefined) && !opts.urn) {
                throw new Error("Missing required property 'image'");
            }
            if ((!args || args.memoryInMbs === undefined) && !opts.urn) {
                throw new Error("Missing required property 'memoryInMbs'");
            }
            resourceInputs["applicationId"] = args ? args.applicationId : undefined;
            resourceInputs["config"] = args ? args.config : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["image"] = args ? args.image : undefined;
            resourceInputs["imageDigest"] = args ? args.imageDigest : undefined;
            resourceInputs["memoryInMbs"] = args ? args.memoryInMbs : undefined;
            resourceInputs["provisionedConcurrencyConfig"] = args ? args.provisionedConcurrencyConfig : undefined;
            resourceInputs["timeoutInSeconds"] = args ? args.timeoutInSeconds : undefined;
            resourceInputs["traceConfig"] = args ? args.traceConfig : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["invokeEndpoint"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Function.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Function resources.
 */
export interface FunctionState {
    /**
     * The OCID of the application this function belongs to.
     */
    applicationId?: pulumi.Input<string>;
    /**
     * The OCID of the compartment that contains the function.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
     */
    config?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     */
    image?: pulumi.Input<string>;
    /**
     * (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     */
    imageDigest?: pulumi.Input<string>;
    /**
     * The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
     */
    invokeEndpoint?: pulumi.Input<string>;
    /**
     * (Updatable) Maximum usable memory for the function (MiB).
     */
    memoryInMbs?: pulumi.Input<string>;
    /**
     * (Updatable) Define the strategy for provisioned concurrency for the function.
     */
    provisionedConcurrencyConfig?: pulumi.Input<inputs.Functions.FunctionProvisionedConcurrencyConfig>;
    /**
     * The current state of the function.
     */
    state?: pulumi.Input<string>;
    /**
     * The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) Timeout for executions of the function. Value in seconds.
     */
    timeoutInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) Define the tracing configuration for a function.
     */
    traceConfig?: pulumi.Input<inputs.Functions.FunctionTraceConfig>;
}

/**
 * The set of arguments for constructing a Function resource.
 */
export interface FunctionArgs {
    /**
     * The OCID of the application this function belongs to.
     */
    applicationId: pulumi.Input<string>;
    /**
     * (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
     */
    config?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     */
    image: pulumi.Input<string>;
    /**
     * (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     */
    imageDigest?: pulumi.Input<string>;
    /**
     * (Updatable) Maximum usable memory for the function (MiB).
     */
    memoryInMbs: pulumi.Input<string>;
    /**
     * (Updatable) Define the strategy for provisioned concurrency for the function.
     */
    provisionedConcurrencyConfig?: pulumi.Input<inputs.Functions.FunctionProvisionedConcurrencyConfig>;
    /**
     * (Updatable) Timeout for executions of the function. Value in seconds.
     */
    timeoutInSeconds?: pulumi.Input<number>;
    /**
     * (Updatable) Define the tracing configuration for a function.
     */
    traceConfig?: pulumi.Input<inputs.Functions.FunctionTraceConfig>;
}