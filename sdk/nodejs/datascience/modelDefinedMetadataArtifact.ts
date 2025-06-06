// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Model Defined Metadata Artifact resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Creates model defined metadata artifact for specified model.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelDefinedMetadataArtifact = new oci.datascience.ModelDefinedMetadataArtifact("test_model_defined_metadata_artifact", {
 *     modelDefinedMetadatumArtifact: modelDefinedMetadataArtifactModelDefinedMetadatumArtifact,
 *     contentLength: modelDefinedMetadataArtifactContentLength,
 *     metadatumKeyName: testKey.name,
 *     modelId: testModel.id,
 *     contentDisposition: modelDefinedMetadataArtifactContentDisposition,
 * });
 * ```
 *
 * ## Import
 *
 * ModelDefinedMetadataArtifacts can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataScience/modelDefinedMetadataArtifact:ModelDefinedMetadataArtifact test_model_defined_metadata_artifact "id"
 * ```
 */
export class ModelDefinedMetadataArtifact extends pulumi.CustomResource {
    /**
     * Get an existing ModelDefinedMetadataArtifact resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ModelDefinedMetadataArtifactState, opts?: pulumi.CustomResourceOptions): ModelDefinedMetadataArtifact {
        return new ModelDefinedMetadataArtifact(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataScience/modelDefinedMetadataArtifact:ModelDefinedMetadataArtifact';

    /**
     * Returns true if the given object is an instance of ModelDefinedMetadataArtifact.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ModelDefinedMetadataArtifact {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ModelDefinedMetadataArtifact.__pulumiType;
    }

    /**
     * (Updatable) This header allows you to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. If this optional field is not populated in the request, then the OCID of the model is used for the file name when downloading. Example: `{"Content-Disposition": "attachment" "filename"="model.tar.gz" "Content-Length": "2347" "Content-Type": "application/gzip"}`
     */
    public readonly contentDisposition!: pulumi.Output<string>;
    /**
     * (Updatable) The content length of the body.
     */
    public readonly contentLength!: pulumi.Output<string>;
    /**
     * The name of the model metadatum in the metadata.
     */
    public readonly metadatumKeyName!: pulumi.Output<string>;
    /**
     * (Updatable) The model defined metadata artifact to upload.
     */
    public readonly modelDefinedMetadatumArtifact!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly modelId!: pulumi.Output<string>;

    /**
     * Create a ModelDefinedMetadataArtifact resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ModelDefinedMetadataArtifactArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ModelDefinedMetadataArtifactArgs | ModelDefinedMetadataArtifactState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ModelDefinedMetadataArtifactState | undefined;
            resourceInputs["contentDisposition"] = state ? state.contentDisposition : undefined;
            resourceInputs["contentLength"] = state ? state.contentLength : undefined;
            resourceInputs["metadatumKeyName"] = state ? state.metadatumKeyName : undefined;
            resourceInputs["modelDefinedMetadatumArtifact"] = state ? state.modelDefinedMetadatumArtifact : undefined;
            resourceInputs["modelId"] = state ? state.modelId : undefined;
        } else {
            const args = argsOrState as ModelDefinedMetadataArtifactArgs | undefined;
            if ((!args || args.contentLength === undefined) && !opts.urn) {
                throw new Error("Missing required property 'contentLength'");
            }
            if ((!args || args.metadatumKeyName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'metadatumKeyName'");
            }
            if ((!args || args.modelDefinedMetadatumArtifact === undefined) && !opts.urn) {
                throw new Error("Missing required property 'modelDefinedMetadatumArtifact'");
            }
            if ((!args || args.modelId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'modelId'");
            }
            resourceInputs["contentDisposition"] = args ? args.contentDisposition : undefined;
            resourceInputs["contentLength"] = args ? args.contentLength : undefined;
            resourceInputs["metadatumKeyName"] = args ? args.metadatumKeyName : undefined;
            resourceInputs["modelDefinedMetadatumArtifact"] = args ? args.modelDefinedMetadatumArtifact : undefined;
            resourceInputs["modelId"] = args ? args.modelId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ModelDefinedMetadataArtifact.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ModelDefinedMetadataArtifact resources.
 */
export interface ModelDefinedMetadataArtifactState {
    /**
     * (Updatable) This header allows you to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. If this optional field is not populated in the request, then the OCID of the model is used for the file name when downloading. Example: `{"Content-Disposition": "attachment" "filename"="model.tar.gz" "Content-Length": "2347" "Content-Type": "application/gzip"}`
     */
    contentDisposition?: pulumi.Input<string>;
    /**
     * (Updatable) The content length of the body.
     */
    contentLength?: pulumi.Input<string>;
    /**
     * The name of the model metadatum in the metadata.
     */
    metadatumKeyName?: pulumi.Input<string>;
    /**
     * (Updatable) The model defined metadata artifact to upload.
     */
    modelDefinedMetadatumArtifact?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    modelId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ModelDefinedMetadataArtifact resource.
 */
export interface ModelDefinedMetadataArtifactArgs {
    /**
     * (Updatable) This header allows you to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. If this optional field is not populated in the request, then the OCID of the model is used for the file name when downloading. Example: `{"Content-Disposition": "attachment" "filename"="model.tar.gz" "Content-Length": "2347" "Content-Type": "application/gzip"}`
     */
    contentDisposition?: pulumi.Input<string>;
    /**
     * (Updatable) The content length of the body.
     */
    contentLength: pulumi.Input<string>;
    /**
     * The name of the model metadatum in the metadata.
     */
    metadatumKeyName: pulumi.Input<string>;
    /**
     * (Updatable) The model defined metadata artifact to upload.
     */
    modelDefinedMetadatumArtifact: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    modelId: pulumi.Input<string>;
}
