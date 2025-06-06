// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms
{
    public static class GetKey
    {
        /// <summary>
        /// This data source provides details about a specific Key resource in Oracle Cloud Infrastructure Kms service.
        /// 
        /// Gets information about the specified master encryption key.
        /// 
        /// As a management operation, this call is subject to a Key Management limit that applies to the total number
        /// of requests across all management read operations. Key Management might throttle this call to reject an
        /// otherwise valid request when the total rate of management read operations exceeds 10 requests per second for
        /// a given tenancy.
        /// 
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
        ///     var testKey = Oci.Kms.GetKey.Invoke(new()
        ///     {
        ///         KeyId = testKeyOciKmsKey.Id,
        ///         ManagementEndpoint = keyManagementEndpoint,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetKeyResult> InvokeAsync(GetKeyArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetKeyResult>("oci:Kms/getKey:getKey", args ?? new GetKeyArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Key resource in Oracle Cloud Infrastructure Kms service.
        /// 
        /// Gets information about the specified master encryption key.
        /// 
        /// As a management operation, this call is subject to a Key Management limit that applies to the total number
        /// of requests across all management read operations. Key Management might throttle this call to reject an
        /// otherwise valid request when the total rate of management read operations exceeds 10 requests per second for
        /// a given tenancy.
        /// 
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
        ///     var testKey = Oci.Kms.GetKey.Invoke(new()
        ///     {
        ///         KeyId = testKeyOciKmsKey.Id,
        ///         ManagementEndpoint = keyManagementEndpoint,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetKeyResult> Invoke(GetKeyInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetKeyResult>("oci:Kms/getKey:getKey", args ?? new GetKeyInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Key resource in Oracle Cloud Infrastructure Kms service.
        /// 
        /// Gets information about the specified master encryption key.
        /// 
        /// As a management operation, this call is subject to a Key Management limit that applies to the total number
        /// of requests across all management read operations. Key Management might throttle this call to reject an
        /// otherwise valid request when the total rate of management read operations exceeds 10 requests per second for
        /// a given tenancy.
        /// 
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
        ///     var testKey = Oci.Kms.GetKey.Invoke(new()
        ///     {
        ///         KeyId = testKeyOciKmsKey.Id,
        ///         ManagementEndpoint = keyManagementEndpoint,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetKeyResult> Invoke(GetKeyInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetKeyResult>("oci:Kms/getKey:getKey", args ?? new GetKeyInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetKeyArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the key.
        /// </summary>
        [Input("keyId", required: true)]
        public string KeyId { get; set; } = null!;

        /// <summary>
        /// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
        /// </summary>
        [Input("managementEndpoint", required: true)]
        public string ManagementEndpoint { get; set; } = null!;

        public GetKeyArgs()
        {
        }
        public static new GetKeyArgs Empty => new GetKeyArgs();
    }

    public sealed class GetKeyInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the key.
        /// </summary>
        [Input("keyId", required: true)]
        public Input<string> KeyId { get; set; } = null!;

        /// <summary>
        /// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
        /// </summary>
        [Input("managementEndpoint", required: true)]
        public Input<string> ManagementEndpoint { get; set; } = null!;

        public GetKeyInvokeArgs()
        {
        }
        public static new GetKeyInvokeArgs Empty => new GetKeyInvokeArgs();
    }


    [OutputType]
    public sealed class GetKeyResult
    {
        /// <summary>
        /// The details of auto rotation schedule for the Key being create updated or imported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyAutoKeyRotationDetailResult> AutoKeyRotationDetails;
        /// <summary>
        /// The OCID of the compartment that contains this master encryption key.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
        /// </summary>
        public readonly string CurrentKeyVersion;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        public readonly string DesiredState;
        /// <summary>
        /// A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Key reference data to be returned to the customer as a response.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyExternalKeyReferenceDetailResult> ExternalKeyReferenceDetails;
        public readonly ImmutableArray<Outputs.GetKeyExternalKeyReferenceResult> ExternalKeyReferences;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the key.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A parameter specifying whether the auto key rotation is enabled or not.
        /// </summary>
        public readonly bool IsAutoRotationEnabled;
        /// <summary>
        /// A Boolean value that indicates whether the Key belongs to primary Vault or replica vault.
        /// </summary>
        public readonly bool IsPrimary;
        public readonly string KeyId;
        /// <summary>
        /// The cryptographic properties of a key.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyKeyShapeResult> KeyShapes;
        public readonly string ManagementEndpoint;
        /// <summary>
        /// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default, a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported. A protection mode of `EXTERNAL` mean that the key persists on the customer's external key manager which is hosted externally outside of oracle. Oracle only hold a reference to that key. All cryptographic operations that use a key with a protection mode of `EXTERNAL` are performed by external key manager.
        /// </summary>
        public readonly string ProtectionMode;
        /// <summary>
        /// Key replica details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyReplicaDetailResult> ReplicaDetails;
        /// <summary>
        /// Details where key was backed up.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyRestoreFromFileResult> RestoreFromFiles;
        /// <summary>
        /// Details where key was backed up
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyRestoreFromObjectStoreResult> RestoreFromObjectStores;
        /// <summary>
        /// When flipped, triggers restore if restore options are provided. Values of 0 or 1 are supported.
        /// </summary>
        public readonly bool RestoreTrigger;
        /// <summary>
        /// The OCID of the key from which this key was restored.
        /// </summary>
        public readonly string RestoredFromKeyId;
        /// <summary>
        /// The key's current lifecycle state.  Example: `ENABLED`
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// An optional property indicating when to delete the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeOfDeletion;
        /// <summary>
        /// The OCID of the vault that contains this key.
        /// </summary>
        public readonly string VaultId;

        [OutputConstructor]
        private GetKeyResult(
            ImmutableArray<Outputs.GetKeyAutoKeyRotationDetailResult> autoKeyRotationDetails,

            string compartmentId,

            string currentKeyVersion,

            ImmutableDictionary<string, string> definedTags,

            string desiredState,

            string displayName,

            ImmutableArray<Outputs.GetKeyExternalKeyReferenceDetailResult> externalKeyReferenceDetails,

            ImmutableArray<Outputs.GetKeyExternalKeyReferenceResult> externalKeyReferences,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isAutoRotationEnabled,

            bool isPrimary,

            string keyId,

            ImmutableArray<Outputs.GetKeyKeyShapeResult> keyShapes,

            string managementEndpoint,

            string protectionMode,

            ImmutableArray<Outputs.GetKeyReplicaDetailResult> replicaDetails,

            ImmutableArray<Outputs.GetKeyRestoreFromFileResult> restoreFromFiles,

            ImmutableArray<Outputs.GetKeyRestoreFromObjectStoreResult> restoreFromObjectStores,

            bool restoreTrigger,

            string restoredFromKeyId,

            string state,

            string timeCreated,

            string timeOfDeletion,

            string vaultId)
        {
            AutoKeyRotationDetails = autoKeyRotationDetails;
            CompartmentId = compartmentId;
            CurrentKeyVersion = currentKeyVersion;
            DefinedTags = definedTags;
            DesiredState = desiredState;
            DisplayName = displayName;
            ExternalKeyReferenceDetails = externalKeyReferenceDetails;
            ExternalKeyReferences = externalKeyReferences;
            FreeformTags = freeformTags;
            Id = id;
            IsAutoRotationEnabled = isAutoRotationEnabled;
            IsPrimary = isPrimary;
            KeyId = keyId;
            KeyShapes = keyShapes;
            ManagementEndpoint = managementEndpoint;
            ProtectionMode = protectionMode;
            ReplicaDetails = replicaDetails;
            RestoreFromFiles = restoreFromFiles;
            RestoreFromObjectStores = restoreFromObjectStores;
            RestoreTrigger = restoreTrigger;
            RestoredFromKeyId = restoredFromKeyId;
            State = state;
            TimeCreated = timeCreated;
            TimeOfDeletion = timeOfDeletion;
            VaultId = vaultId;
        }
    }
}
