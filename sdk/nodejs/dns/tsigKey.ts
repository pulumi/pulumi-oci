// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Tsig Key resource in Oracle Cloud Infrastructure DNS service.
 *
 * Creates a new TSIG key in the specified compartment. There is no
 * `opc-retry-token` header since TSIG key names must be globally unique.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTsigKey = new oci.dns.TsigKey("testTsigKey", {
 *     algorithm: _var.tsig_key_algorithm,
 *     compartmentId: _var.compartment_id,
 *     secret: _var.tsig_key_secret,
 *     definedTags: _var.tsig_key_defined_tags,
 *     freeformTags: _var.tsig_key_freeform_tags,
 * });
 * ```
 *
 * ## Import
 *
 * TsigKeys can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Dns/tsigKey:TsigKey test_tsig_key "id"
 * ```
 */
export class TsigKey extends pulumi.CustomResource {
    /**
     * Get an existing TsigKey resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: TsigKeyState, opts?: pulumi.CustomResourceOptions): TsigKey {
        return new TsigKey(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Dns/tsigKey:TsigKey';

    /**
     * Returns true if the given object is an instance of TsigKey.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is TsigKey {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === TsigKey.__pulumiType;
    }

    /**
     * TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     */
    public readonly algorithm!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the compartment containing the TSIG key.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A globally unique domain name identifying the key for a given pair of hosts.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * A base64 string encoding the binary shared secret.
     */
    public readonly secret!: pulumi.Output<string>;
    /**
     * The canonical absolute URL of the resource.
     */
    public /*out*/ readonly self!: pulumi.Output<string>;
    /**
     * The current state of the resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the resource was created, expressed in RFC 3339 timestamp format.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a TsigKey resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: TsigKeyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: TsigKeyArgs | TsigKeyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as TsigKeyState | undefined;
            resourceInputs["algorithm"] = state ? state.algorithm : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["secret"] = state ? state.secret : undefined;
            resourceInputs["self"] = state ? state.self : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as TsigKeyArgs | undefined;
            if ((!args || args.algorithm === undefined) && !opts.urn) {
                throw new Error("Missing required property 'algorithm'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.secret === undefined) && !opts.urn) {
                throw new Error("Missing required property 'secret'");
            }
            resourceInputs["algorithm"] = args ? args.algorithm : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["secret"] = args ? args.secret : undefined;
            resourceInputs["self"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(TsigKey.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering TsigKey resources.
 */
export interface TsigKeyState {
    /**
     * TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     */
    algorithm?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the compartment containing the TSIG key.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A globally unique domain name identifying the key for a given pair of hosts.
     */
    name?: pulumi.Input<string>;
    /**
     * A base64 string encoding the binary shared secret.
     */
    secret?: pulumi.Input<string>;
    /**
     * The canonical absolute URL of the resource.
     */
    self?: pulumi.Input<string>;
    /**
     * The current state of the resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the resource was created, expressed in RFC 3339 timestamp format.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a TsigKey resource.
 */
export interface TsigKeyArgs {
    /**
     * TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     */
    algorithm: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the compartment containing the TSIG key.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A globally unique domain name identifying the key for a given pair of hosts.
     */
    name?: pulumi.Input<string>;
    /**
     * A base64 string encoding the binary shared secret.
     */
    secret: pulumi.Input<string>;
}