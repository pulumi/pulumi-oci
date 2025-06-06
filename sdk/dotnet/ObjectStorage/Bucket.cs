// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    /// <summary>
    /// This resource provides the Bucket resource in Oracle Cloud Infrastructure Object Storage service.
    /// 
    /// Creates a bucket in the given namespace with a bucket name and optional user-defined metadata. Avoid entering
    /// confidential information in bucket names.
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
    ///     var testBucket = new Oci.ObjectStorage.Bucket("test_bucket", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         Name = bucketName,
    ///         Namespace = bucketNamespace,
    ///         AccessType = bucketAccessType,
    ///         AutoTiering = bucketAutoTiering,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         KmsKeyId = testKey.Id,
    ///         Metadata = bucketMetadata,
    ///         ObjectEventsEnabled = bucketObjectEventsEnabled,
    ///         StorageTier = bucketStorageTier,
    ///         RetentionRules = new[]
    ///         {
    ///             new Oci.ObjectStorage.Inputs.BucketRetentionRuleArgs
    ///             {
    ///                 DisplayName = retentionRuleDisplayName,
    ///                 Duration = new Oci.ObjectStorage.Inputs.BucketRetentionRuleDurationArgs
    ///                 {
    ///                     TimeAmount = retentionRuleDurationTimeAmount,
    ///                     TimeUnit = retentionRuleDurationTimeUnit,
    ///                 },
    ///                 TimeRuleLocked = retentionRuleTimeRuleLocked,
    ///             },
    ///         },
    ///         Versioning = bucketVersioning,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Buckets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:ObjectStorage/bucket:Bucket test_bucket "n/{namespaceName}/b/{bucketName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:ObjectStorage/bucket:Bucket")]
    public partial class Bucket : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
        /// </summary>
        [Output("accessType")]
        public Output<string?> AccessType { get; private set; } = null!;

        /// <summary>
        /// The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
        /// </summary>
        [Output("approximateCount")]
        public Output<string> ApproximateCount { get; private set; } = null!;

        /// <summary>
        /// The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
        /// </summary>
        [Output("approximateSize")]
        public Output<string> ApproximateSize { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the 'Standard' and 'InfrequentAccess' tiers based on the access pattern of the objects.
        /// </summary>
        [Output("autoTiering")]
        public Output<string> AutoTiering { get; private set; } = null!;

        /// <summary>
        /// The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
        /// </summary>
        [Output("bucketId")]
        public Output<string> BucketId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The ID of the compartment in which to create the bucket.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
        /// </summary>
        [Output("createdBy")]
        public Output<string> CreatedBy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The entity tag (ETag) for the bucket.
        /// </summary>
        [Output("etag")]
        public Output<string> Etag { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to 'true' when this bucket is configured as a destination in a replication policy.
        /// </summary>
        [Output("isReadOnly")]
        public Output<bool> IsReadOnly { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
        /// </summary>
        [Output("kmsKeyId")]
        public Output<string> KmsKeyId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
        /// </summary>
        [Output("metadata")]
        public Output<ImmutableDictionary<string, string>?> Metadata { get; private set; } = null!;

        /// <summary>
        /// The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Output("namespace")]
        public Output<string> Namespace { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
        /// </summary>
        [Output("objectEventsEnabled")]
        public Output<bool> ObjectEventsEnabled { get; private set; } = null!;

        /// <summary>
        /// The entity tag (ETag) for the live object lifecycle policy on the bucket.
        /// </summary>
        [Output("objectLifecyclePolicyEtag")]
        public Output<string> ObjectLifecyclePolicyEtag { get; private set; } = null!;

        /// <summary>
        /// Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to 'true' when you create a replication policy for the bucket.
        /// </summary>
        [Output("replicationEnabled")]
        public Output<bool> ReplicationEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
        /// </summary>
        [Output("retentionRules")]
        public Output<ImmutableArray<Outputs.BucketRetentionRule>> RetentionRules { get; private set; } = null!;

        /// <summary>
        /// The type of storage tier of this bucket. A bucket is set to 'Standard' tier by default, which means the bucket will be put in the standard storage tier. When 'Archive' tier type is set explicitly, the bucket is put in the Archive Storage tier. The 'storageTier' property is immutable after bucket is created.
        /// </summary>
        [Output("storageTier")]
        public Output<string> StorageTier { get; private set; } = null!;

        /// <summary>
        /// The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("versioning")]
        public Output<string> Versioning { get; private set; } = null!;


        /// <summary>
        /// Create a Bucket resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Bucket(string name, BucketArgs args, CustomResourceOptions? options = null)
            : base("oci:ObjectStorage/bucket:Bucket", name, args ?? new BucketArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Bucket(string name, Input<string> id, BucketState? state = null, CustomResourceOptions? options = null)
            : base("oci:ObjectStorage/bucket:Bucket", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Bucket resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Bucket Get(string name, Input<string> id, BucketState? state = null, CustomResourceOptions? options = null)
        {
            return new Bucket(name, id, state, options);
        }
    }

    public sealed class BucketArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
        /// </summary>
        [Input("accessType")]
        public Input<string>? AccessType { get; set; }

        /// <summary>
        /// (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the 'Standard' and 'InfrequentAccess' tiers based on the access pattern of the objects.
        /// </summary>
        [Input("autoTiering")]
        public Input<string>? AutoTiering { get; set; }

        /// <summary>
        /// (Updatable) The ID of the compartment in which to create the bucket.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        [Input("metadata")]
        private InputMap<string>? _metadata;

        /// <summary>
        /// (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
        /// </summary>
        public InputMap<string> Metadata
        {
            get => _metadata ?? (_metadata = new InputMap<string>());
            set => _metadata = value;
        }

        /// <summary>
        /// The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
        /// </summary>
        [Input("objectEventsEnabled")]
        public Input<bool>? ObjectEventsEnabled { get; set; }

        [Input("retentionRules")]
        private InputList<Inputs.BucketRetentionRuleArgs>? _retentionRules;

        /// <summary>
        /// (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
        /// </summary>
        public InputList<Inputs.BucketRetentionRuleArgs> RetentionRules
        {
            get => _retentionRules ?? (_retentionRules = new InputList<Inputs.BucketRetentionRuleArgs>());
            set => _retentionRules = value;
        }

        /// <summary>
        /// The type of storage tier of this bucket. A bucket is set to 'Standard' tier by default, which means the bucket will be put in the standard storage tier. When 'Archive' tier type is set explicitly, the bucket is put in the Archive Storage tier. The 'storageTier' property is immutable after bucket is created.
        /// </summary>
        [Input("storageTier")]
        public Input<string>? StorageTier { get; set; }

        /// <summary>
        /// (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("versioning")]
        public Input<string>? Versioning { get; set; }

        public BucketArgs()
        {
        }
        public static new BucketArgs Empty => new BucketArgs();
    }

    public sealed class BucketState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
        /// </summary>
        [Input("accessType")]
        public Input<string>? AccessType { get; set; }

        /// <summary>
        /// The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
        /// </summary>
        [Input("approximateCount")]
        public Input<string>? ApproximateCount { get; set; }

        /// <summary>
        /// The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
        /// </summary>
        [Input("approximateSize")]
        public Input<string>? ApproximateSize { get; set; }

        /// <summary>
        /// (Updatable) Set the auto tiering status on the bucket. By default, a bucket is created with auto tiering `Disabled`. Use this option to enable auto tiering during bucket creation. Objects in a bucket with auto tiering set to `InfrequentAccess` are transitioned automatically between the 'Standard' and 'InfrequentAccess' tiers based on the access pattern of the objects.
        /// </summary>
        [Input("autoTiering")]
        public Input<string>? AutoTiering { get; set; }

        /// <summary>
        /// The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
        /// </summary>
        [Input("bucketId")]
        public Input<string>? BucketId { get; set; }

        /// <summary>
        /// (Updatable) The ID of the compartment in which to create the bucket.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
        /// </summary>
        [Input("createdBy")]
        public Input<string>? CreatedBy { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The entity tag (ETag) for the bucket.
        /// </summary>
        [Input("etag")]
        public Input<string>? Etag { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to 'true' when this bucket is configured as a destination in a replication policy.
        /// </summary>
        [Input("isReadOnly")]
        public Input<bool>? IsReadOnly { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        [Input("metadata")]
        private InputMap<string>? _metadata;

        /// <summary>
        /// (Updatable) Arbitrary string, up to 4KB, of keys and values for user-defined metadata.
        /// </summary>
        public InputMap<string> Metadata
        {
            get => _metadata ?? (_metadata = new InputMap<string>());
            set => _metadata = value;
        }

        /// <summary>
        /// The name of the bucket. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. example: Example: my-new-bucket1
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        /// <summary>
        /// (Updatable) Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
        /// </summary>
        [Input("objectEventsEnabled")]
        public Input<bool>? ObjectEventsEnabled { get; set; }

        /// <summary>
        /// The entity tag (ETag) for the live object lifecycle policy on the bucket.
        /// </summary>
        [Input("objectLifecyclePolicyEtag")]
        public Input<string>? ObjectLifecyclePolicyEtag { get; set; }

        /// <summary>
        /// Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to 'true' when you create a replication policy for the bucket.
        /// </summary>
        [Input("replicationEnabled")]
        public Input<bool>? ReplicationEnabled { get; set; }

        [Input("retentionRules")]
        private InputList<Inputs.BucketRetentionRuleGetArgs>? _retentionRules;

        /// <summary>
        /// (Updatable) Creates a new retention rule in the specified bucket. The new rule will take effect typically within 30 seconds. Note that a maximum of 100 rules are supported on a bucket.
        /// </summary>
        public InputList<Inputs.BucketRetentionRuleGetArgs> RetentionRules
        {
            get => _retentionRules ?? (_retentionRules = new InputList<Inputs.BucketRetentionRuleGetArgs>());
            set => _retentionRules = value;
        }

        /// <summary>
        /// The type of storage tier of this bucket. A bucket is set to 'Standard' tier by default, which means the bucket will be put in the standard storage tier. When 'Archive' tier type is set explicitly, the bucket is put in the Archive Storage tier. The 'storageTier' property is immutable after bucket is created.
        /// </summary>
        [Input("storageTier")]
        public Input<string>? StorageTier { get; set; }

        /// <summary>
        /// The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// (Updatable) Set the versioning status on the bucket. By default, a bucket is created with versioning `Disabled`. Use this option to enable versioning during bucket creation. Objects in a version enabled bucket are protected from overwrites and deletions. Previous versions of the same object will be available in the bucket. Allowed Create values: Enabled, Disabled. Allowed Update values: Enabled, Suspended.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("versioning")]
        public Input<string>? Versioning { get; set; }

        public BucketState()
        {
        }
        public static new BucketState Empty => new BucketState();
    }
}
