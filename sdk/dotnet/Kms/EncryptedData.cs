// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms
{
    /// <summary>
    /// This resource provides the Encrypted Data resource in Oracle Cloud Infrastructure Kms service.
    /// 
    /// Encrypts data using the given [EncryptDataDetails](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/datatypes/EncryptDataDetails) resource.
    /// Plaintext included in the example request is a base64-encoded value of a UTF-8 string.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testEncryptedData = new Oci.Kms.EncryptedData("test_encrypted_data", new()
    ///     {
    ///         CryptoEndpoint = encryptedDataCryptoEndpoint,
    ///         KeyId = testKey.Id,
    ///         Plaintext = encryptedDataPlaintext,
    ///         AssociatedData = encryptedDataAssociatedData,
    ///         EncryptionAlgorithm = encryptedDataEncryptionAlgorithm,
    ///         KeyVersionId = testKeyVersion.Id,
    ///         LoggingContext = encryptedDataLoggingContext,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:Kms/encryptedData:EncryptedData")]
    public partial class EncryptedData : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        /// </summary>
        [Output("associatedData")]
        public Output<ImmutableDictionary<string, string>?> AssociatedData { get; private set; } = null!;

        /// <summary>
        /// The encrypted data.
        /// </summary>
        [Output("ciphertext")]
        public Output<string> Ciphertext { get; private set; } = null!;

        /// <summary>
        /// The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        /// </summary>
        [Output("cryptoEndpoint")]
        public Output<string> CryptoEndpoint { get; private set; } = null!;

        /// <summary>
        /// The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP). `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash and uses OAEP.
        /// </summary>
        [Output("encryptionAlgorithm")]
        public Output<string> EncryptionAlgorithm { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key to encrypt with.
        /// </summary>
        [Output("keyId")]
        public Output<string> KeyId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key version used to encrypt the ciphertext.
        /// </summary>
        [Output("keyVersionId")]
        public Output<string> KeyVersionId { get; private set; } = null!;

        /// <summary>
        /// Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        /// </summary>
        [Output("loggingContext")]
        public Output<ImmutableDictionary<string, string>?> LoggingContext { get; private set; } = null!;

        /// <summary>
        /// The plaintext data to encrypt.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("plaintext")]
        public Output<string> Plaintext { get; private set; } = null!;


        /// <summary>
        /// Create a EncryptedData resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public EncryptedData(string name, EncryptedDataArgs args, CustomResourceOptions? options = null)
            : base("oci:Kms/encryptedData:EncryptedData", name, args ?? new EncryptedDataArgs(), MakeResourceOptions(options, ""))
        {
        }

        private EncryptedData(string name, Input<string> id, EncryptedDataState? state = null, CustomResourceOptions? options = null)
            : base("oci:Kms/encryptedData:EncryptedData", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing EncryptedData resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static EncryptedData Get(string name, Input<string> id, EncryptedDataState? state = null, CustomResourceOptions? options = null)
        {
            return new EncryptedData(name, id, state, options);
        }
    }

    public sealed class EncryptedDataArgs : global::Pulumi.ResourceArgs
    {
        [Input("associatedData")]
        private InputMap<string>? _associatedData;

        /// <summary>
        /// Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        /// </summary>
        public InputMap<string> AssociatedData
        {
            get => _associatedData ?? (_associatedData = new InputMap<string>());
            set => _associatedData = value;
        }

        /// <summary>
        /// The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        /// </summary>
        [Input("cryptoEndpoint", required: true)]
        public Input<string> CryptoEndpoint { get; set; } = null!;

        /// <summary>
        /// The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP). `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash and uses OAEP.
        /// </summary>
        [Input("encryptionAlgorithm")]
        public Input<string>? EncryptionAlgorithm { get; set; }

        /// <summary>
        /// The OCID of the key to encrypt with.
        /// </summary>
        [Input("keyId", required: true)]
        public Input<string> KeyId { get; set; } = null!;

        /// <summary>
        /// The OCID of the key version used to encrypt the ciphertext.
        /// </summary>
        [Input("keyVersionId")]
        public Input<string>? KeyVersionId { get; set; }

        [Input("loggingContext")]
        private InputMap<string>? _loggingContext;

        /// <summary>
        /// Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        /// </summary>
        public InputMap<string> LoggingContext
        {
            get => _loggingContext ?? (_loggingContext = new InputMap<string>());
            set => _loggingContext = value;
        }

        /// <summary>
        /// The plaintext data to encrypt.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("plaintext", required: true)]
        public Input<string> Plaintext { get; set; } = null!;

        public EncryptedDataArgs()
        {
        }
        public static new EncryptedDataArgs Empty => new EncryptedDataArgs();
    }

    public sealed class EncryptedDataState : global::Pulumi.ResourceArgs
    {
        [Input("associatedData")]
        private InputMap<string>? _associatedData;

        /// <summary>
        /// Information that can be used to provide an encryption context for the encrypted data. The length of the string representation of the associated data must be fewer than 4096 characters.
        /// </summary>
        public InputMap<string> AssociatedData
        {
            get => _associatedData ?? (_associatedData = new InputMap<string>());
            set => _associatedData = value;
        }

        /// <summary>
        /// The encrypted data.
        /// </summary>
        [Input("ciphertext")]
        public Input<string>? Ciphertext { get; set; }

        /// <summary>
        /// The service endpoint to perform cryptographic operations against. Cryptographic operations include 'Encrypt,' 'Decrypt,' and 'GenerateDataEncryptionKey' operations. see Vault Crypto endpoint.
        /// </summary>
        [Input("cryptoEndpoint")]
        public Input<string>? CryptoEndpoint { get; set; }

        /// <summary>
        /// The encryption algorithm to use to encrypt and decrypt data with a customer-managed key. `AES_256_GCM` indicates that the key is a symmetric key that uses the Advanced Encryption Standard (AES) algorithm and that the mode of encryption is the Galois/Counter Mode (GCM). `RSA_OAEP_SHA_1` indicates that the key is an asymmetric key that uses the RSA encryption algorithm and uses Optimal Asymmetric Encryption Padding (OAEP). `RSA_OAEP_SHA_256` indicates that the key is an asymmetric key that uses the RSA encryption algorithm with a SHA-256 hash and uses OAEP.
        /// </summary>
        [Input("encryptionAlgorithm")]
        public Input<string>? EncryptionAlgorithm { get; set; }

        /// <summary>
        /// The OCID of the key to encrypt with.
        /// </summary>
        [Input("keyId")]
        public Input<string>? KeyId { get; set; }

        /// <summary>
        /// The OCID of the key version used to encrypt the ciphertext.
        /// </summary>
        [Input("keyVersionId")]
        public Input<string>? KeyVersionId { get; set; }

        [Input("loggingContext")]
        private InputMap<string>? _loggingContext;

        /// <summary>
        /// Information that provides context for audit logging. You can provide this additional data as key-value pairs to include in the audit logs when audit logging is enabled.
        /// </summary>
        public InputMap<string> LoggingContext
        {
            get => _loggingContext ?? (_loggingContext = new InputMap<string>());
            set => _loggingContext = value;
        }

        /// <summary>
        /// The plaintext data to encrypt.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("plaintext")]
        public Input<string>? Plaintext { get; set; }

        public EncryptedDataState()
        {
        }
        public static new EncryptedDataState Empty => new EncryptedDataState();
    }
}
