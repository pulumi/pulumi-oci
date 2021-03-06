// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms
{
    /// <summary>
    /// This resource provides the Key resource in Oracle Cloud Infrastructure Kms service.
    /// 
    /// Creates a new master encryption key.
    /// 
    /// As a management operation, this call is subject to a Key Management limit that applies to the total
    /// number of requests across all management write operations. Key Management might throttle this call
    /// to reject an otherwise valid request when the total rate of management write operations exceeds 10
    /// requests per second for a given tenancy.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testKey = new Oci.Kms.Key("testKey", new Oci.Kms.KeyArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Key_display_name,
    ///             KeyShape = new Oci.Kms.Inputs.KeyKeyShapeArgs
    ///             {
    ///                 Algorithm = @var.Key_key_shape_algorithm,
    ///                 Length = @var.Key_key_shape_length,
    ///                 CurveId = oci_kms_curve.Test_curve.Id,
    ///             },
    ///             ManagementEndpoint = @var.Key_management_endpoint,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             ProtectionMode = @var.Key_protection_mode,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Keys can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Kms/key:Key test_key "managementEndpoint/{managementEndpoint}/keys/{keyId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Kms/key:Key")]
    public partial class Key : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment where you want to create the master encryption key.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
        /// </summary>
        [Output("currentKeyVersion")]
        public Output<string> CurrentKeyVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
        /// </summary>
        [Output("desiredState")]
        public Output<string> DesiredState { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
        /// </summary>
        [Output("isPrimary")]
        public Output<bool> IsPrimary { get; private set; } = null!;

        /// <summary>
        /// The cryptographic properties of a key.
        /// </summary>
        [Output("keyShape")]
        public Output<Outputs.KeyKeyShape> KeyShape { get; private set; } = null!;

        /// <summary>
        /// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
        /// </summary>
        [Output("managementEndpoint")]
        public Output<string> ManagementEndpoint { get; private set; } = null!;

        /// <summary>
        /// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
        /// </summary>
        [Output("protectionMode")]
        public Output<string> ProtectionMode { get; private set; } = null!;

        /// <summary>
        /// Key replica details
        /// </summary>
        [Output("replicaDetails")]
        public Output<ImmutableArray<Outputs.KeyReplicaDetail>> ReplicaDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details where key was backed up.
        /// </summary>
        [Output("restoreFromFile")]
        public Output<Outputs.KeyRestoreFromFile?> RestoreFromFile { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details where key was backed up
        /// </summary>
        [Output("restoreFromObjectStore")]
        public Output<Outputs.KeyRestoreFromObjectStore?> RestoreFromObjectStore { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
        /// </summary>
        [Output("restoreTrigger")]
        public Output<bool?> RestoreTrigger { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key from which this key was restored.
        /// </summary>
        [Output("restoredFromKeyId")]
        public Output<string> RestoredFromKeyId { get; private set; } = null!;

        /// <summary>
        /// The key's current lifecycle state.  Example: `ENABLED`
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        [Output("timeOfDeletion")]
        public Output<string> TimeOfDeletion { get; private set; } = null!;

        /// <summary>
        /// The OCID of the vault that contains this key.
        /// </summary>
        [Output("vaultId")]
        public Output<string> VaultId { get; private set; } = null!;


        /// <summary>
        /// Create a Key resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Key(string name, KeyArgs args, CustomResourceOptions? options = null)
            : base("oci:Kms/key:Key", name, args ?? new KeyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Key(string name, Input<string> id, KeyState? state = null, CustomResourceOptions? options = null)
            : base("oci:Kms/key:Key", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Key resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Key Get(string name, Input<string> id, KeyState? state = null, CustomResourceOptions? options = null)
        {
            return new Key(name, id, state, options);
        }
    }

    public sealed class KeyArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment where you want to create the master encryption key.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
        /// </summary>
        [Input("desiredState")]
        public Input<string>? DesiredState { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The cryptographic properties of a key.
        /// </summary>
        [Input("keyShape", required: true)]
        public Input<Inputs.KeyKeyShapeArgs> KeyShape { get; set; } = null!;

        /// <summary>
        /// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
        /// </summary>
        [Input("managementEndpoint", required: true)]
        public Input<string> ManagementEndpoint { get; set; } = null!;

        /// <summary>
        /// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
        /// </summary>
        [Input("protectionMode")]
        public Input<string>? ProtectionMode { get; set; }

        /// <summary>
        /// (Updatable) Details where key was backed up.
        /// </summary>
        [Input("restoreFromFile")]
        public Input<Inputs.KeyRestoreFromFileArgs>? RestoreFromFile { get; set; }

        /// <summary>
        /// (Updatable) Details where key was backed up
        /// </summary>
        [Input("restoreFromObjectStore")]
        public Input<Inputs.KeyRestoreFromObjectStoreArgs>? RestoreFromObjectStore { get; set; }

        /// <summary>
        /// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
        /// </summary>
        [Input("restoreTrigger")]
        public Input<bool>? RestoreTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        [Input("timeOfDeletion")]
        public Input<string>? TimeOfDeletion { get; set; }

        public KeyArgs()
        {
        }
    }

    public sealed class KeyState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment where you want to create the master encryption key.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
        /// </summary>
        [Input("currentKeyVersion")]
        public Input<string>? CurrentKeyVersion { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
        /// </summary>
        [Input("desiredState")]
        public Input<string>? DesiredState { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
        /// </summary>
        [Input("isPrimary")]
        public Input<bool>? IsPrimary { get; set; }

        /// <summary>
        /// The cryptographic properties of a key.
        /// </summary>
        [Input("keyShape")]
        public Input<Inputs.KeyKeyShapeGetArgs>? KeyShape { get; set; }

        /// <summary>
        /// The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
        /// </summary>
        [Input("managementEndpoint")]
        public Input<string>? ManagementEndpoint { get; set; }

        /// <summary>
        /// The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
        /// </summary>
        [Input("protectionMode")]
        public Input<string>? ProtectionMode { get; set; }

        [Input("replicaDetails")]
        private InputList<Inputs.KeyReplicaDetailGetArgs>? _replicaDetails;

        /// <summary>
        /// Key replica details
        /// </summary>
        public InputList<Inputs.KeyReplicaDetailGetArgs> ReplicaDetails
        {
            get => _replicaDetails ?? (_replicaDetails = new InputList<Inputs.KeyReplicaDetailGetArgs>());
            set => _replicaDetails = value;
        }

        /// <summary>
        /// (Updatable) Details where key was backed up.
        /// </summary>
        [Input("restoreFromFile")]
        public Input<Inputs.KeyRestoreFromFileGetArgs>? RestoreFromFile { get; set; }

        /// <summary>
        /// (Updatable) Details where key was backed up
        /// </summary>
        [Input("restoreFromObjectStore")]
        public Input<Inputs.KeyRestoreFromObjectStoreGetArgs>? RestoreFromObjectStore { get; set; }

        /// <summary>
        /// (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
        /// </summary>
        [Input("restoreTrigger")]
        public Input<bool>? RestoreTrigger { get; set; }

        /// <summary>
        /// The OCID of the key from which this key was restored.
        /// </summary>
        [Input("restoredFromKeyId")]
        public Input<string>? RestoredFromKeyId { get; set; }

        /// <summary>
        /// The key's current lifecycle state.  Example: `ENABLED`
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        [Input("timeOfDeletion")]
        public Input<string>? TimeOfDeletion { get; set; }

        /// <summary>
        /// The OCID of the vault that contains this key.
        /// </summary>
        [Input("vaultId")]
        public Input<string>? VaultId { get; set; }

        public KeyState()
        {
        }
    }
}
