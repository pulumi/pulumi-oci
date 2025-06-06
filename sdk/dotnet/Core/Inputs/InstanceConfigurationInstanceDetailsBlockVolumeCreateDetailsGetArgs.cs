// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("autotunePolicies")]
        private InputList<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyGetArgs>? _autotunePolicies;

        /// <summary>
        /// The list of autotune policies enabled for this volume.
        /// </summary>
        public InputList<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyGetArgs> AutotunePolicies
        {
            get => _autotunePolicies ?? (_autotunePolicies = new InputList<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsAutotunePolicyGetArgs>());
            set => _autotunePolicies = value;
        }

        /// <summary>
        /// The availability domain of the volume.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
        /// </summary>
        [Input("backupPolicyId")]
        public Input<string>? BackupPolicyId { get; set; }

        /// <summary>
        /// The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
        /// </summary>
        [Input("blockVolumeReplicas")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsBlockVolumeReplicasGetArgs>? BlockVolumeReplicas { get; set; }

        /// <summary>
        /// The clusterPlacementGroup Id of the volume for volume placement.
        /// </summary>
        [Input("clusterPlacementGroupId")]
        public Input<string>? ClusterPlacementGroupId { get; set; }

        /// <summary>
        /// The OCID of the compartment that contains the volume.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Specifies whether the auto-tune performance is enabled for this boot volume. This field is deprecated. Use the `InstanceConfigurationDetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
        /// </summary>
        [Input("isAutoTuneEnabled")]
        public Input<bool>? IsAutoTuneEnabled { get; set; }

        /// <summary>
        /// The OCID of the Vault service key to assign as the master encryption key for the volume.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The size of the volume in GBs.
        /// </summary>
        [Input("sizeInGbs")]
        public Input<string>? SizeInGbs { get; set; }

        [Input("sourceDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsGetArgs>? SourceDetails { get; set; }

        /// <summary>
        /// The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
        /// 
        /// Allowed values:
        /// </summary>
        [Input("vpusPerGb")]
        public Input<string>? VpusPerGb { get; set; }

        /// <summary>
        /// The OCID of the Vault service key which is the master encryption key for the block volume cross region backups, which will be used in the destination region to encrypt the backup's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
        /// </summary>
        [Input("xrcKmsKeyId")]
        public Input<string>? XrcKmsKeyId { get; set; }

        public InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsGetArgs()
        {
        }
        public static new InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsGetArgs Empty => new InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsGetArgs();
    }
}
