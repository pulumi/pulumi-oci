// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Container Repository resource in Oracle Cloud Infrastructure Artifacts service.
 *
 * Create a new empty container repository. Avoid entering confidential information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testContainerRepository = new oci.artifacts.ContainerRepository("testContainerRepository", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.container_repository_display_name,
 *     isImmutable: _var.container_repository_is_immutable,
 *     isPublic: _var.container_repository_is_public,
 *     readme: {
 *         content: _var.container_repository_readme_content,
 *         format: _var.container_repository_readme_format,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * ContainerRepositories can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Artifacts/containerRepository:ContainerRepository test_container_repository "container/repositories/{repositoryId}"
 * ```
 */
export class ContainerRepository extends pulumi.CustomResource {
    /**
     * Get an existing ContainerRepository resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ContainerRepositoryState, opts?: pulumi.CustomResourceOptions): ContainerRepository {
        return new ContainerRepository(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Artifacts/containerRepository:ContainerRepository';

    /**
     * Returns true if the given object is an instance of ContainerRepository.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ContainerRepository {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ContainerRepository.__pulumiType;
    }

    /**
     * Total storage size in GBs that will be charged.
     */
    public /*out*/ readonly billableSizeInGbs!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The id of the user or principal that created the resource.
     */
    public /*out*/ readonly createdBy!: pulumi.Output<string>;
    /**
     * The container repository name.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Total number of images.
     */
    public /*out*/ readonly imageCount!: pulumi.Output<number>;
    /**
     * (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
     */
    public readonly isImmutable!: pulumi.Output<boolean>;
    /**
     * (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
     */
    public readonly isPublic!: pulumi.Output<boolean>;
    /**
     * Total number of layers.
     */
    public /*out*/ readonly layerCount!: pulumi.Output<number>;
    /**
     * Total storage in bytes consumed by layers.
     */
    public /*out*/ readonly layersSizeInBytes!: pulumi.Output<string>;
    /**
     * (Updatable) Container repository readme.
     */
    public readonly readme!: pulumi.Output<outputs.Artifacts.ContainerRepositoryReadme>;
    /**
     * The current state of the container repository.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * An RFC 3339 timestamp indicating when the repository was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * An RFC 3339 timestamp indicating when an image was last pushed to the repository.
     */
    public /*out*/ readonly timeLastPushed!: pulumi.Output<string>;

    /**
     * Create a ContainerRepository resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ContainerRepositoryArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ContainerRepositoryArgs | ContainerRepositoryState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ContainerRepositoryState | undefined;
            resourceInputs["billableSizeInGbs"] = state ? state.billableSizeInGbs : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createdBy"] = state ? state.createdBy : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["imageCount"] = state ? state.imageCount : undefined;
            resourceInputs["isImmutable"] = state ? state.isImmutable : undefined;
            resourceInputs["isPublic"] = state ? state.isPublic : undefined;
            resourceInputs["layerCount"] = state ? state.layerCount : undefined;
            resourceInputs["layersSizeInBytes"] = state ? state.layersSizeInBytes : undefined;
            resourceInputs["readme"] = state ? state.readme : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeLastPushed"] = state ? state.timeLastPushed : undefined;
        } else {
            const args = argsOrState as ContainerRepositoryArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["isImmutable"] = args ? args.isImmutable : undefined;
            resourceInputs["isPublic"] = args ? args.isPublic : undefined;
            resourceInputs["readme"] = args ? args.readme : undefined;
            resourceInputs["billableSizeInGbs"] = undefined /*out*/;
            resourceInputs["createdBy"] = undefined /*out*/;
            resourceInputs["imageCount"] = undefined /*out*/;
            resourceInputs["layerCount"] = undefined /*out*/;
            resourceInputs["layersSizeInBytes"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeLastPushed"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ContainerRepository.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ContainerRepository resources.
 */
export interface ContainerRepositoryState {
    /**
     * Total storage size in GBs that will be charged.
     */
    billableSizeInGbs?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The id of the user or principal that created the resource.
     */
    createdBy?: pulumi.Input<string>;
    /**
     * The container repository name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Total number of images.
     */
    imageCount?: pulumi.Input<number>;
    /**
     * (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
     */
    isImmutable?: pulumi.Input<boolean>;
    /**
     * (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
     */
    isPublic?: pulumi.Input<boolean>;
    /**
     * Total number of layers.
     */
    layerCount?: pulumi.Input<number>;
    /**
     * Total storage in bytes consumed by layers.
     */
    layersSizeInBytes?: pulumi.Input<string>;
    /**
     * (Updatable) Container repository readme.
     */
    readme?: pulumi.Input<inputs.Artifacts.ContainerRepositoryReadme>;
    /**
     * The current state of the container repository.
     */
    state?: pulumi.Input<string>;
    /**
     * An RFC 3339 timestamp indicating when the repository was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * An RFC 3339 timestamp indicating when an image was last pushed to the repository.
     */
    timeLastPushed?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ContainerRepository resource.
 */
export interface ContainerRepositoryArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The container repository name.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
     */
    isImmutable?: pulumi.Input<boolean>;
    /**
     * (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
     */
    isPublic?: pulumi.Input<boolean>;
    /**
     * (Updatable) Container repository readme.
     */
    readme?: pulumi.Input<inputs.Artifacts.ContainerRepositoryReadme>;
}
