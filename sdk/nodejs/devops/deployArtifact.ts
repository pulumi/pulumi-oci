// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.
 *
 * Creates a new deployment artifact.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployArtifact = new oci.devops.DeployArtifact("test_deploy_artifact", {
 *     argumentSubstitutionMode: deployArtifactArgumentSubstitutionMode,
 *     deployArtifactSource: {
 *         deployArtifactSourceType: deployArtifactDeployArtifactSourceDeployArtifactSourceType,
 *         base64encodedContent: deployArtifactDeployArtifactSourceBase64encodedContent,
 *         chartUrl: deployArtifactDeployArtifactSourceChartUrl,
 *         deployArtifactPath: deployArtifactDeployArtifactSourceDeployArtifactPath,
 *         deployArtifactVersion: deployArtifactDeployArtifactSourceDeployArtifactVersion,
 *         helmArtifactSourceType: deployArtifactDeployArtifactSourceHelmArtifactSourceType,
 *         helmVerificationKeySource: {
 *             verificationKeySourceType: deployArtifactDeployArtifactSourceHelmVerificationKeySourceVerificationKeySourceType,
 *             currentPublicKey: deployArtifactDeployArtifactSourceHelmVerificationKeySourceCurrentPublicKey,
 *             previousPublicKey: deployArtifactDeployArtifactSourceHelmVerificationKeySourcePreviousPublicKey,
 *             vaultSecretId: testSecret.id,
 *         },
 *         imageDigest: deployArtifactDeployArtifactSourceImageDigest,
 *         imageUri: deployArtifactDeployArtifactSourceImageUri,
 *         repositoryId: testRepository.id,
 *     },
 *     deployArtifactType: deployArtifactDeployArtifactType,
 *     projectId: testProject.id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: deployArtifactDescription,
 *     displayName: deployArtifactDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * DeployArtifacts can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DevOps/deployArtifact:DeployArtifact test_deploy_artifact "id"
 * ```
 */
export class DeployArtifact extends pulumi.CustomResource {
    /**
     * Get an existing DeployArtifact resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DeployArtifactState, opts?: pulumi.CustomResourceOptions): DeployArtifact {
        return new DeployArtifact(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DevOps/deployArtifact:DeployArtifact';

    /**
     * Returns true if the given object is an instance of DeployArtifact.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DeployArtifact {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DeployArtifact.__pulumiType;
    }

    /**
     * (Updatable) Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
     */
    public readonly argumentSubstitutionMode!: pulumi.Output<string>;
    /**
     * The OCID of a compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Specifies source of an artifact.
     */
    public readonly deployArtifactSource!: pulumi.Output<outputs.DevOps.DeployArtifactDeployArtifactSource>;
    /**
     * (Updatable) Type of the deployment artifact.
     */
    public readonly deployArtifactType!: pulumi.Output<string>;
    /**
     * (Updatable) Optional description about the deployment artifact.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Deployment artifact display name. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A detailed message describing the current state. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly projectId!: pulumi.Output<string>;
    /**
     * Current state of the deployment artifact.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Time the deployment artifact was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time the deployment artifact was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a DeployArtifact resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DeployArtifactArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DeployArtifactArgs | DeployArtifactState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DeployArtifactState | undefined;
            resourceInputs["argumentSubstitutionMode"] = state ? state.argumentSubstitutionMode : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["deployArtifactSource"] = state ? state.deployArtifactSource : undefined;
            resourceInputs["deployArtifactType"] = state ? state.deployArtifactType : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["projectId"] = state ? state.projectId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as DeployArtifactArgs | undefined;
            if ((!args || args.argumentSubstitutionMode === undefined) && !opts.urn) {
                throw new Error("Missing required property 'argumentSubstitutionMode'");
            }
            if ((!args || args.deployArtifactSource === undefined) && !opts.urn) {
                throw new Error("Missing required property 'deployArtifactSource'");
            }
            if ((!args || args.deployArtifactType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'deployArtifactType'");
            }
            if ((!args || args.projectId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'projectId'");
            }
            resourceInputs["argumentSubstitutionMode"] = args ? args.argumentSubstitutionMode : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["deployArtifactSource"] = args ? args.deployArtifactSource : undefined;
            resourceInputs["deployArtifactType"] = args ? args.deployArtifactType : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["projectId"] = args ? args.projectId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DeployArtifact.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DeployArtifact resources.
 */
export interface DeployArtifactState {
    /**
     * (Updatable) Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
     */
    argumentSubstitutionMode?: pulumi.Input<string>;
    /**
     * The OCID of a compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Specifies source of an artifact.
     */
    deployArtifactSource?: pulumi.Input<inputs.DevOps.DeployArtifactDeployArtifactSource>;
    /**
     * (Updatable) Type of the deployment artifact.
     */
    deployArtifactType?: pulumi.Input<string>;
    /**
     * (Updatable) Optional description about the deployment artifact.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Deployment artifact display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A detailed message describing the current state. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    projectId?: pulumi.Input<string>;
    /**
     * Current state of the deployment artifact.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Time the deployment artifact was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time the deployment artifact was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DeployArtifact resource.
 */
export interface DeployArtifactArgs {
    /**
     * (Updatable) Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
     */
    argumentSubstitutionMode: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Specifies source of an artifact.
     */
    deployArtifactSource: pulumi.Input<inputs.DevOps.DeployArtifactDeployArtifactSource>;
    /**
     * (Updatable) Type of the deployment artifact.
     */
    deployArtifactType: pulumi.Input<string>;
    /**
     * (Updatable) Optional description about the deployment artifact.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Deployment artifact display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    projectId: pulumi.Input<string>;
}
