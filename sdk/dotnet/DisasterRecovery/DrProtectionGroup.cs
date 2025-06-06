// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery
{
    /// <summary>
    /// This resource provides the Dr Protection Group resource in Oracle Cloud Infrastructure Disaster Recovery service.
    /// 
    /// Create a DR protection group.
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
    ///     var config = new Config();
    ///     var disassociateTrigger = config.GetDouble("disassociateTrigger") ?? 0;
    ///     var testDrProtectionGroup = new Oci.DisasterRecovery.DrProtectionGroup("test_dr_protection_group", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DisplayName = drProtectionGroupDisplayName,
    ///         LogLocation = new Oci.DisasterRecovery.Inputs.DrProtectionGroupLogLocationArgs
    ///         {
    ///             Bucket = drProtectionGroupLogLocationBucket,
    ///             Namespace = drProtectionGroupLogLocationNamespace,
    ///         },
    ///         Association = new Oci.DisasterRecovery.Inputs.DrProtectionGroupAssociationArgs
    ///         {
    ///             Role = drProtectionGroupAssociationRole,
    ///             PeerId = drProtectionGroupAssociationPeerId,
    ///             PeerRegion = drProtectionGroupAssociationPeerRegion,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         DisassociateTrigger = disassociateTrigger,
    ///         Members = new[]
    ///         {
    ///             new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberArgs
    ///             {
    ///                 MemberId = drProtectionGroupMembersMemberId,
    ///                 MemberType = drProtectionGroupMembersMemberType,
    ///                 AutonomousDatabaseStandbyTypeForDrDrills = drProtectionGroupMembersAutonomousDatabaseStandbyTypeForDrDrills,
    ///                 BackendSetMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBackendSetMappingArgs
    ///                     {
    ///                         DestinationBackendSetName = testBackendSet.Name,
    ///                         IsBackendSetForNonMovable = drProtectionGroupMembersBackendSetMappingsIsBackendSetForNonMovable,
    ///                         SourceBackendSetName = testBackendSet.Name,
    ///                     },
    ///                 },
    ///                 BackupConfig = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBackupConfigArgs
    ///                 {
    ///                     BackupSchedule = drProtectionGroupMembersBackupConfigBackupSchedule,
    ///                     ImageReplicationVaultSecretId = testSecret.Id,
    ///                     MaxNumberOfBackupsRetained = drProtectionGroupMembersBackupConfigMaxNumberOfBackupsRetained,
    ///                     Namespaces = drProtectionGroupMembersBackupConfigNamespaces,
    ///                     ReplicateImages = drProtectionGroupMembersBackupConfigReplicateImages,
    ///                 },
    ///                 BackupLocation = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBackupLocationArgs
    ///                 {
    ///                     Bucket = drProtectionGroupMembersBackupLocationBucket,
    ///                     Namespace = drProtectionGroupMembersBackupLocationNamespace,
    ///                 },
    ///                 BlockVolumeAttachAndMountOperations = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsArgs
    ///                 {
    ///                     Attachments = new[]
    ///                     {
    ///                         new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachmentArgs
    ///                         {
    ///                             BlockVolumeId = testVolume.Id,
    ///                             VolumeAttachmentReferenceInstanceId = testInstance.Id,
    ///                         },
    ///                     },
    ///                     Mounts = new[]
    ///                     {
    ///                         new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsMountArgs
    ///                         {
    ///                             MountPoint = drProtectionGroupMembersBlockVolumeAttachAndMountOperationsMountsMountPoint,
    ///                         },
    ///                     },
    ///                 },
    ///                 BlockVolumeOperations = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBlockVolumeOperationArgs
    ///                     {
    ///                         AttachmentDetails = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsArgs
    ///                         {
    ///                             VolumeAttachmentReferenceInstanceId = testInstance.Id,
    ///                         },
    ///                         BlockVolumeId = testVolume.Id,
    ///                         MountDetails = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberBlockVolumeOperationMountDetailsArgs
    ///                         {
    ///                             MountPoint = drProtectionGroupMembersBlockVolumeOperationsMountDetailsMountPoint,
    ///                         },
    ///                     },
    ///                 },
    ///                 Bucket = drProtectionGroupMembersBucket,
    ///                 CommonDestinationKey = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberCommonDestinationKeyArgs
    ///                 {
    ///                     EncryptionKeyId = testKey.Id,
    ///                     VaultId = testVault.Id,
    ///                 },
    ///                 ConnectionStringType = drProtectionGroupMembersConnectionStringType,
    ///                 DestinationAvailabilityDomain = drProtectionGroupMembersDestinationAvailabilityDomain,
    ///                 DestinationBackupPolicyId = testPolicy.Id,
    ///                 DestinationCapacityReservationId = destinationCapacityReservationId,
    ///                 DestinationCompartmentId = testCompartment.Id,
    ///                 DestinationDedicatedVmHostId = testDedicatedVmHost.Id,
    ///                 DestinationEncryptionKey = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberDestinationEncryptionKeyArgs
    ///                 {
    ///                     EncryptionKeyId = testKey.Id,
    ///                     VaultId = testVault.Id,
    ///                 },
    ///                 DestinationLoadBalancerId = testLoadBalancer.Id,
    ///                 DestinationNetworkLoadBalancerId = testNetworkLoadBalancer.Id,
    ///                 DestinationSnapshotPolicyId = testPolicy.Id,
    ///                 ExportMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberExportMappingArgs
    ///                     {
    ///                         DestinationMountTargetId = testMountTarget.Id,
    ///                         ExportId = testExport.Id,
    ///                     },
    ///                 },
    ///                 FileSystemOperations = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberFileSystemOperationArgs
    ///                     {
    ///                         ExportPath = drProtectionGroupMembersFileSystemOperationsExportPath,
    ///                         MountDetails = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberFileSystemOperationMountDetailsArgs
    ///                         {
    ///                             MountTargetId = testMountTarget.Id,
    ///                         },
    ///                         MountPoint = drProtectionGroupMembersFileSystemOperationsMountPoint,
    ///                         MountTargetId = testMountTarget.Id,
    ///                         UnmountDetails = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberFileSystemOperationUnmountDetailsArgs
    ///                         {
    ///                             MountTargetId = testMountTarget.Id,
    ///                         },
    ///                     },
    ///                 },
    ///                 IsMovable = drProtectionGroupMembersIsMovable,
    ///                 IsRetainFaultDomain = drProtectionGroupMembersIsRetainFaultDomain,
    ///                 IsStartStopEnabled = drProtectionGroupMembersIsStartStopEnabled,
    ///                 JumpHostId = testJumpHost.Id,
    ///                 LoadBalancerMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberLoadBalancerMappingArgs
    ///                     {
    ///                         DestinationLoadBalancerId = testLoadBalancer.Id,
    ///                         SourceLoadBalancerId = testLoadBalancer.Id,
    ///                     },
    ///                 },
    ///                 ManagedNodePoolConfigs = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberManagedNodePoolConfigArgs
    ///                     {
    ///                         Id = drProtectionGroupMembersManagedNodePoolConfigsId,
    ///                         Maximum = drProtectionGroupMembersManagedNodePoolConfigsMaximum,
    ///                         Minimum = drProtectionGroupMembersManagedNodePoolConfigsMinimum,
    ///                     },
    ///                 },
    ///                 Namespace = drProtectionGroupMembersNamespace,
    ///                 PasswordVaultSecretId = passwordVaultSecretId,
    ///                 NetworkLoadBalancerMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberNetworkLoadBalancerMappingArgs
    ///                     {
    ///                         DestinationNetworkLoadBalancerId = testNetworkLoadBalancer.Id,
    ///                         SourceNetworkLoadBalancerId = testNetworkLoadBalancer.Id,
    ///                     },
    ///                 },
    ///                 PeerClusterId = testCluster.Id,
    ///                 SourceVolumeToDestinationEncryptionKeyMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberSourceVolumeToDestinationEncryptionKeyMappingArgs
    ///                     {
    ///                         DestinationEncryptionKey = new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberSourceVolumeToDestinationEncryptionKeyMappingDestinationEncryptionKeyArgs
    ///                         {
    ///                             EncryptionKeyId = testKey.Id,
    ///                             VaultId = testVault.Id,
    ///                         },
    ///                         SourceVolumeId = testVolume.Id,
    ///                     },
    ///                 },
    ///                 VaultMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberVaultMappingArgs
    ///                     {
    ///                         DestinationVaultId = testVault.Id,
    ///                         SourceVaultId = testVault.Id,
    ///                     },
    ///                 },
    ///                 VirtualNodePoolConfigs = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberVirtualNodePoolConfigArgs
    ///                     {
    ///                         Id = drProtectionGroupMembersVirtualNodePoolConfigsId,
    ///                         Maximum = drProtectionGroupMembersVirtualNodePoolConfigsMaximum,
    ///                         Minimum = drProtectionGroupMembersVirtualNodePoolConfigsMinimum,
    ///                     },
    ///                 },
    ///                 VnicMappings = new[]
    ///                 {
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberVnicMappingArgs
    ///                     {
    ///                         DestinationNsgIdLists = drProtectionGroupMembersVnicMappingDestinationNsgIdList,
    ///                         DestinationPrimaryPrivateIpAddress = drProtectionGroupMembersVnicMappingDestinationPrimaryPrivateIpAddress,
    ///                         DestinationPrimaryPrivateIpHostnameLabel = drProtectionGroupMembersVnicMappingDestinationPrimaryPrivateIpHostnameLabel,
    ///                         DestinationSubnetId = testSubnet.Id,
    ///                         SourceVnicId = testVnic.Id,
    ///                     },
    ///                     new Oci.DisasterRecovery.Inputs.DrProtectionGroupMemberVnicMappingArgs
    ///                     {
    ///                         DestinationNsgIdLists = drProtectionGroupMembersVnicMappingsDestinationNsgIdList,
    ///                         DestinationPrimaryPrivateIpAddress = drProtectionGroupMembersVnicMappingsDestinationPrimaryPrivateIpAddress,
    ///                         DestinationPrimaryPrivateIpHostnameLabel = drProtectionGroupMembersVnicMappingsDestinationPrimaryPrivateIpHostnameLabel,
    ///                         DestinationReservedPublicIpId = testPublicIp.Id,
    ///                         DestinationSubnetId = testSubnet.Id,
    ///                         SourceVnicId = testVnic.Id,
    ///                     },
    ///                 },
    ///             },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Create
    /// 
    /// Create DR Protection Group resource with a default value of `disassociate_trigger` property, e.g.
    /// 
    /// ## Delete
    /// 
    /// Disassociate DR Protection Group (if associated) before deleting it. Increment value of `disassociate_trigger` property to trigger Disassociate, e.g.
    /// 
    /// ## Import
    /// 
    /// DrProtectionGroups can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DisasterRecovery/drProtectionGroup:DrProtectionGroup test_dr_protection_group "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DisasterRecovery/drProtectionGroup:DrProtectionGroup")]
    public partial class DrProtectionGroup : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The details for associating a DR protection group with a peer DR protection group.
        /// </summary>
        [Output("association")]
        public Output<Outputs.DrProtectionGroupAssociation> Association { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment in which to create the DR protection group.  Example: `ocid1.compartment.oc1..uniqueID`
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("disassociateTrigger")]
        public Output<int?> DisassociateTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The display name of the DR protection group.  Example: `EBS PHX Group`
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the DR protection group's current state in more detail.
        /// </summary>
        [Output("lifeCycleDetails")]
        public Output<string> LifeCycleDetails { get; private set; } = null!;

        /// <summary>
        /// The current sub-state of the DR protection group.
        /// </summary>
        [Output("lifecycleSubState")]
        public Output<string> LifecycleSubState { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The details for creating an object storage log location for a DR protection group.
        /// </summary>
        [Output("logLocation")]
        public Output<Outputs.DrProtectionGroupLogLocation> LogLocation { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A list of DR protection group members.
        /// </summary>
        [Output("members")]
        public Output<ImmutableArray<Outputs.DrProtectionGroupMember>> Members { get; private set; } = null!;

        /// <summary>
        /// The OCID of the peer DR protection group.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
        /// </summary>
        [Output("peerId")]
        public Output<string> PeerId { get; private set; } = null!;

        /// <summary>
        /// The region of the peer DR protection group.  Example: `us-ashburn-1`
        /// </summary>
        [Output("peerRegion")]
        public Output<string> PeerRegion { get; private set; } = null!;

        /// <summary>
        /// The role of the DR protection group.
        /// </summary>
        [Output("role")]
        public Output<string> Role { get; private set; } = null!;

        /// <summary>
        /// The current state of the DR protection group.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the DR protection group was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the DR protection group was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a DrProtectionGroup resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DrProtectionGroup(string name, DrProtectionGroupArgs args, CustomResourceOptions? options = null)
            : base("oci:DisasterRecovery/drProtectionGroup:DrProtectionGroup", name, args ?? new DrProtectionGroupArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DrProtectionGroup(string name, Input<string> id, DrProtectionGroupState? state = null, CustomResourceOptions? options = null)
            : base("oci:DisasterRecovery/drProtectionGroup:DrProtectionGroup", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DrProtectionGroup resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DrProtectionGroup Get(string name, Input<string> id, DrProtectionGroupState? state = null, CustomResourceOptions? options = null)
        {
            return new DrProtectionGroup(name, id, state, options);
        }
    }

    public sealed class DrProtectionGroupArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The details for associating a DR protection group with a peer DR protection group.
        /// </summary>
        [Input("association")]
        public Input<Inputs.DrProtectionGroupAssociationArgs>? Association { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment in which to create the DR protection group.  Example: `ocid1.compartment.oc1..uniqueID`
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("disassociateTrigger")]
        public Input<int>? DisassociateTrigger { get; set; }

        /// <summary>
        /// (Updatable) The display name of the DR protection group.  Example: `EBS PHX Group`
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The details for creating an object storage log location for a DR protection group.
        /// </summary>
        [Input("logLocation", required: true)]
        public Input<Inputs.DrProtectionGroupLogLocationArgs> LogLocation { get; set; } = null!;

        [Input("members")]
        private InputList<Inputs.DrProtectionGroupMemberArgs>? _members;

        /// <summary>
        /// (Updatable) A list of DR protection group members.
        /// </summary>
        public InputList<Inputs.DrProtectionGroupMemberArgs> Members
        {
            get => _members ?? (_members = new InputList<Inputs.DrProtectionGroupMemberArgs>());
            set => _members = value;
        }

        public DrProtectionGroupArgs()
        {
        }
        public static new DrProtectionGroupArgs Empty => new DrProtectionGroupArgs();
    }

    public sealed class DrProtectionGroupState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The details for associating a DR protection group with a peer DR protection group.
        /// </summary>
        [Input("association")]
        public Input<Inputs.DrProtectionGroupAssociationGetArgs>? Association { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment in which to create the DR protection group.  Example: `ocid1.compartment.oc1..uniqueID`
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("disassociateTrigger")]
        public Input<int>? DisassociateTrigger { get; set; }

        /// <summary>
        /// (Updatable) The display name of the DR protection group.  Example: `EBS PHX Group`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the DR protection group's current state in more detail.
        /// </summary>
        [Input("lifeCycleDetails")]
        public Input<string>? LifeCycleDetails { get; set; }

        /// <summary>
        /// The current sub-state of the DR protection group.
        /// </summary>
        [Input("lifecycleSubState")]
        public Input<string>? LifecycleSubState { get; set; }

        /// <summary>
        /// (Updatable) The details for creating an object storage log location for a DR protection group.
        /// </summary>
        [Input("logLocation")]
        public Input<Inputs.DrProtectionGroupLogLocationGetArgs>? LogLocation { get; set; }

        [Input("members")]
        private InputList<Inputs.DrProtectionGroupMemberGetArgs>? _members;

        /// <summary>
        /// (Updatable) A list of DR protection group members.
        /// </summary>
        public InputList<Inputs.DrProtectionGroupMemberGetArgs> Members
        {
            get => _members ?? (_members = new InputList<Inputs.DrProtectionGroupMemberGetArgs>());
            set => _members = value;
        }

        /// <summary>
        /// The OCID of the peer DR protection group.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
        /// </summary>
        [Input("peerId")]
        public Input<string>? PeerId { get; set; }

        /// <summary>
        /// The region of the peer DR protection group.  Example: `us-ashburn-1`
        /// </summary>
        [Input("peerRegion")]
        public Input<string>? PeerRegion { get; set; }

        /// <summary>
        /// The role of the DR protection group.
        /// </summary>
        [Input("role")]
        public Input<string>? Role { get; set; }

        /// <summary>
        /// The current state of the DR protection group.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the DR protection group was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the DR protection group was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DrProtectionGroupState()
        {
        }
        public static new DrProtectionGroupState Empty => new DrProtectionGroupState();
    }
}
