// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Generated Key resource in Oracle Cloud Infrastructure Kms service.
 *
 * Generates a key that you can use to encrypt or decrypt data.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testGeneratedKey = new oci.kms.GeneratedKey("test_generated_key", {
 *     cryptoEndpoint: generatedKeyCryptoEndpoint,
 *     includePlaintextKey: generatedKeyIncludePlaintextKey,
 *     keyId: testKey.id,
 *     keyShape: {
 *         algorithm: generatedKeyKeyShapeAlgorithm,
 *         length: generatedKeyKeyShapeLength,
 *         curveId: testCurve.id,
 *     },
 *     associatedData: generatedKeyAssociatedData,
 *     loggingContext: generatedKeyLoggingContext,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class GeneratedKey extends pulumi.CustomResource {
    /**
     * Get an existing GeneratedKey resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: GeneratedKeyState, opts?: pulumi.CustomResourceOptions): GeneratedKey {
        return new GeneratedKey(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Kms/generatedKey:GeneratedKey';

    /**
     * Returns true if the given object is an instance of GeneratedKey.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is GeneratedKey {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === GeneratedKey.__pulumiType;
    }

    /**
     * Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
     */
    public readonly associatedData!: pulumi.Output<{[key: string]: string} | undefined>;
    /**
     * The encrypted data encryption key generated from a master encryption key.
     */
    public /*out*/ readonly ciphertext!: pulumi.Output<string>;
    /**
     * The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
     */
    public readonly cryptoEndpoint!: pulumi.Output<string>;
    /**
     * If true, the generated key is also returned unencrypted.
     */
    public readonly includePlaintextKey!: pulumi.Output<boolean>;
    /**
     * The OCID of the master encryption key to encrypt the generated data encryption key with.
     */
    public readonly keyId!: pulumi.Output<string>;
    /**
     * The cryptographic properties of a key.
     */
    public readonly keyShape!: pulumi.Output<outputs.Kms.GeneratedKeyKeyShape>;
    /**
     * Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly loggingContext!: pulumi.Output<{[key: string]: string} | undefined>;
    /**
     * The plaintext data encryption key, a base64-encoded sequence of random bytes, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
     */
    public /*out*/ readonly plaintext!: pulumi.Output<string>;
    /**
     * The checksum of the plaintext data encryption key, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
     */
    public /*out*/ readonly plaintextChecksum!: pulumi.Output<string>;

    /**
     * Create a GeneratedKey resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: GeneratedKeyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: GeneratedKeyArgs | GeneratedKeyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as GeneratedKeyState | undefined;
            resourceInputs["associatedData"] = state ? state.associatedData : undefined;
            resourceInputs["ciphertext"] = state ? state.ciphertext : undefined;
            resourceInputs["cryptoEndpoint"] = state ? state.cryptoEndpoint : undefined;
            resourceInputs["includePlaintextKey"] = state ? state.includePlaintextKey : undefined;
            resourceInputs["keyId"] = state ? state.keyId : undefined;
            resourceInputs["keyShape"] = state ? state.keyShape : undefined;
            resourceInputs["loggingContext"] = state ? state.loggingContext : undefined;
            resourceInputs["plaintext"] = state ? state.plaintext : undefined;
            resourceInputs["plaintextChecksum"] = state ? state.plaintextChecksum : undefined;
        } else {
            const args = argsOrState as GeneratedKeyArgs | undefined;
            if ((!args || args.cryptoEndpoint === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cryptoEndpoint'");
            }
            if ((!args || args.includePlaintextKey === undefined) && !opts.urn) {
                throw new Error("Missing required property 'includePlaintextKey'");
            }
            if ((!args || args.keyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'keyId'");
            }
            if ((!args || args.keyShape === undefined) && !opts.urn) {
                throw new Error("Missing required property 'keyShape'");
            }
            resourceInputs["associatedData"] = args ? args.associatedData : undefined;
            resourceInputs["cryptoEndpoint"] = args ? args.cryptoEndpoint : undefined;
            resourceInputs["includePlaintextKey"] = args ? args.includePlaintextKey : undefined;
            resourceInputs["keyId"] = args ? args.keyId : undefined;
            resourceInputs["keyShape"] = args ? args.keyShape : undefined;
            resourceInputs["loggingContext"] = args ? args.loggingContext : undefined;
            resourceInputs["ciphertext"] = undefined /*out*/;
            resourceInputs["plaintext"] = undefined /*out*/;
            resourceInputs["plaintextChecksum"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(GeneratedKey.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering GeneratedKey resources.
 */
export interface GeneratedKeyState {
    /**
     * Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
     */
    associatedData?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The encrypted data encryption key generated from a master encryption key.
     */
    ciphertext?: pulumi.Input<string>;
    /**
     * The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
     */
    cryptoEndpoint?: pulumi.Input<string>;
    /**
     * If true, the generated key is also returned unencrypted.
     */
    includePlaintextKey?: pulumi.Input<boolean>;
    /**
     * The OCID of the master encryption key to encrypt the generated data encryption key with.
     */
    keyId?: pulumi.Input<string>;
    /**
     * The cryptographic properties of a key.
     */
    keyShape?: pulumi.Input<inputs.Kms.GeneratedKeyKeyShape>;
    /**
     * Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    loggingContext?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The plaintext data encryption key, a base64-encoded sequence of random bytes, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
     */
    plaintext?: pulumi.Input<string>;
    /**
     * The checksum of the plaintext data encryption key, which is included if the [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) request includes the `includePlaintextKey` parameter and sets its value to "true".
     */
    plaintextChecksum?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a GeneratedKey resource.
 */
export interface GeneratedKeyArgs {
    /**
     * Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
     */
    associatedData?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
     */
    cryptoEndpoint: pulumi.Input<string>;
    /**
     * If true, the generated key is also returned unencrypted.
     */
    includePlaintextKey: pulumi.Input<boolean>;
    /**
     * The OCID of the master encryption key to encrypt the generated data encryption key with.
     */
    keyId: pulumi.Input<string>;
    /**
     * The cryptographic properties of a key.
     */
    keyShape: pulumi.Input<inputs.Kms.GeneratedKeyKeyShape>;
    /**
     * Information that provides context for audit logging. You can provide this additional data by formatting it as key-value pairs to include in audit logs when audit logging is enabled. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    loggingContext?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
}
