// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Generate Scoped Access Token resource in Oracle Cloud Infrastructure Identity Data Plane service.
 *
 * Based on the calling principal and the input payload, derive the claims and create a security token.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testGenerateScopedAccessToken = new oci.identitydataplane.GeneratedScopedAccessToken("testGenerateScopedAccessToken", {
 *     publicKey: _var.generate_scoped_access_token_public_key,
 *     scope: _var.generate_scoped_access_token_scope,
 * });
 * ```
 *
 * ## Import
 *
 * GenerateScopedAccessToken can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken test_generate_scoped_access_token "id"
 * ```
 */
export class GeneratedScopedAccessToken extends pulumi.CustomResource {
    /**
     * Get an existing GeneratedScopedAccessToken resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: GeneratedScopedAccessTokenState, opts?: pulumi.CustomResourceOptions): GeneratedScopedAccessToken {
        return new GeneratedScopedAccessToken(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken';

    /**
     * Returns true if the given object is an instance of GeneratedScopedAccessToken.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is GeneratedScopedAccessToken {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === GeneratedScopedAccessToken.__pulumiType;
    }

    /**
     * A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
     */
    public readonly publicKey!: pulumi.Output<string>;
    /**
     * Scope definition for the scoped access token
     */
    public readonly scope!: pulumi.Output<string>;
    /**
     * The security token, signed by auth service
     */
    public /*out*/ readonly token!: pulumi.Output<string>;

    /**
     * Create a GeneratedScopedAccessToken resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: GeneratedScopedAccessTokenArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: GeneratedScopedAccessTokenArgs | GeneratedScopedAccessTokenState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as GeneratedScopedAccessTokenState | undefined;
            resourceInputs["publicKey"] = state ? state.publicKey : undefined;
            resourceInputs["scope"] = state ? state.scope : undefined;
            resourceInputs["token"] = state ? state.token : undefined;
        } else {
            const args = argsOrState as GeneratedScopedAccessTokenArgs | undefined;
            if ((!args || args.publicKey === undefined) && !opts.urn) {
                throw new Error("Missing required property 'publicKey'");
            }
            if ((!args || args.scope === undefined) && !opts.urn) {
                throw new Error("Missing required property 'scope'");
            }
            resourceInputs["publicKey"] = args ? args.publicKey : undefined;
            resourceInputs["scope"] = args ? args.scope : undefined;
            resourceInputs["token"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(GeneratedScopedAccessToken.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering GeneratedScopedAccessToken resources.
 */
export interface GeneratedScopedAccessTokenState {
    /**
     * A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
     */
    publicKey?: pulumi.Input<string>;
    /**
     * Scope definition for the scoped access token
     */
    scope?: pulumi.Input<string>;
    /**
     * The security token, signed by auth service
     */
    token?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a GeneratedScopedAccessToken resource.
 */
export interface GeneratedScopedAccessTokenArgs {
    /**
     * A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
     */
    publicKey: pulumi.Input<string>;
    /**
     * Scope definition for the scoped access token
     */
    scope: pulumi.Input<string>;
}