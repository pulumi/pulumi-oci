// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Model resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Creates a new model.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModel = new oci.datascience.Model("testModel", {
 *     compartmentId: _var.compartment_id,
 *     projectId: oci_datascience_project.test_project.id,
 *     customMetadataLists: [{
 *         category: _var.model_custom_metadata_list_category,
 *         description: _var.model_custom_metadata_list_description,
 *         key: _var.model_custom_metadata_list_key,
 *         value: _var.model_custom_metadata_list_value,
 *     }],
 *     definedMetadataLists: [{
 *         category: _var.model_defined_metadata_list_category,
 *         description: _var.model_defined_metadata_list_description,
 *         key: _var.model_defined_metadata_list_key,
 *         value: _var.model_defined_metadata_list_value,
 *     }],
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.model_description,
 *     displayName: _var.model_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     inputSchema: _var.model_input_schema,
 *     outputSchema: _var.model_output_schema,
 * });
 * ```
 *
 * ## Import
 *
 * Models can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataScience/model:Model test_model "id"
 * ```
 */
export class Model extends pulumi.CustomResource {
    /**
     * Get an existing Model resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ModelState, opts?: pulumi.CustomResourceOptions): Model {
        return new Model(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataScience/model:Model';

    /**
     * Returns true if the given object is an instance of Model.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Model {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Model.__pulumiType;
    }

    public readonly artifactContentDisposition!: pulumi.Output<string>;
    public readonly artifactContentLength!: pulumi.Output<string>;
    public /*out*/ readonly artifactContentMd5!: pulumi.Output<string>;
    public /*out*/ readonly artifactLastModified!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model.
     */
    public /*out*/ readonly createdBy!: pulumi.Output<string>;
    /**
     * (Updatable) An array of custom metadata details for the model.
     */
    public readonly customMetadataLists!: pulumi.Output<outputs.DataScience.ModelCustomMetadataList[]>;
    /**
     * (Updatable) An array of defined metadata details for the model.
     */
    public readonly definedMetadataLists!: pulumi.Output<outputs.DataScience.ModelDefinedMetadataList[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A short description of the model.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     */
    public readonly displayName!: pulumi.Output<string>;
    public /*out*/ readonly emptyModel!: pulumi.Output<boolean>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Input schema file content in String format
     */
    public readonly inputSchema!: pulumi.Output<string>;
    public readonly modelArtifact!: pulumi.Output<string>;
    /**
     * Output schema file content in String format
     */
    public readonly outputSchema!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     */
    public readonly projectId!: pulumi.Output<string>;
    /**
     * The state of the model.
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Model resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ModelArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ModelArgs | ModelState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ModelState | undefined;
            resourceInputs["artifactContentDisposition"] = state ? state.artifactContentDisposition : undefined;
            resourceInputs["artifactContentLength"] = state ? state.artifactContentLength : undefined;
            resourceInputs["artifactContentMd5"] = state ? state.artifactContentMd5 : undefined;
            resourceInputs["artifactLastModified"] = state ? state.artifactLastModified : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createdBy"] = state ? state.createdBy : undefined;
            resourceInputs["customMetadataLists"] = state ? state.customMetadataLists : undefined;
            resourceInputs["definedMetadataLists"] = state ? state.definedMetadataLists : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["emptyModel"] = state ? state.emptyModel : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["inputSchema"] = state ? state.inputSchema : undefined;
            resourceInputs["modelArtifact"] = state ? state.modelArtifact : undefined;
            resourceInputs["outputSchema"] = state ? state.outputSchema : undefined;
            resourceInputs["projectId"] = state ? state.projectId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as ModelArgs | undefined;
            if ((!args || args.artifactContentLength === undefined) && !opts.urn) {
                throw new Error("Missing required property 'artifactContentLength'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.modelArtifact === undefined) && !opts.urn) {
                throw new Error("Missing required property 'modelArtifact'");
            }
            if ((!args || args.projectId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'projectId'");
            }
            resourceInputs["artifactContentDisposition"] = args ? args.artifactContentDisposition : undefined;
            resourceInputs["artifactContentLength"] = args ? args.artifactContentLength : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["customMetadataLists"] = args ? args.customMetadataLists : undefined;
            resourceInputs["definedMetadataLists"] = args ? args.definedMetadataLists : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["inputSchema"] = args ? args.inputSchema : undefined;
            resourceInputs["modelArtifact"] = args ? args.modelArtifact : undefined;
            resourceInputs["outputSchema"] = args ? args.outputSchema : undefined;
            resourceInputs["projectId"] = args ? args.projectId : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["artifactContentMd5"] = undefined /*out*/;
            resourceInputs["artifactLastModified"] = undefined /*out*/;
            resourceInputs["createdBy"] = undefined /*out*/;
            resourceInputs["emptyModel"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Model.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Model resources.
 */
export interface ModelState {
    artifactContentDisposition?: pulumi.Input<string>;
    artifactContentLength?: pulumi.Input<string>;
    artifactContentMd5?: pulumi.Input<string>;
    artifactLastModified?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model.
     */
    createdBy?: pulumi.Input<string>;
    /**
     * (Updatable) An array of custom metadata details for the model.
     */
    customMetadataLists?: pulumi.Input<pulumi.Input<inputs.DataScience.ModelCustomMetadataList>[]>;
    /**
     * (Updatable) An array of defined metadata details for the model.
     */
    definedMetadataLists?: pulumi.Input<pulumi.Input<inputs.DataScience.ModelDefinedMetadataList>[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A short description of the model.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     */
    displayName?: pulumi.Input<string>;
    emptyModel?: pulumi.Input<boolean>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Input schema file content in String format
     */
    inputSchema?: pulumi.Input<string>;
    modelArtifact?: pulumi.Input<string>;
    /**
     * Output schema file content in String format
     */
    outputSchema?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     */
    projectId?: pulumi.Input<string>;
    /**
     * The state of the model.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Model resource.
 */
export interface ModelArgs {
    artifactContentDisposition?: pulumi.Input<string>;
    artifactContentLength: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) An array of custom metadata details for the model.
     */
    customMetadataLists?: pulumi.Input<pulumi.Input<inputs.DataScience.ModelCustomMetadataList>[]>;
    /**
     * (Updatable) An array of defined metadata details for the model.
     */
    definedMetadataLists?: pulumi.Input<pulumi.Input<inputs.DataScience.ModelDefinedMetadataList>[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A short description of the model.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Input schema file content in String format
     */
    inputSchema?: pulumi.Input<string>;
    modelArtifact: pulumi.Input<string>;
    /**
     * Output schema file content in String format
     */
    outputSchema?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     */
    projectId: pulumi.Input<string>;
    /**
     * The state of the model.
     */
    state?: pulumi.Input<string>;
}