// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class AssetVmwareVm
    {
        /// <summary>
        /// (Updatable) Cluster name.
        /// </summary>
        public readonly string? Cluster;
        /// <summary>
        /// (Updatable) Customer fields.
        /// </summary>
        public readonly ImmutableArray<string> CustomerFields;
        /// <summary>
        /// (Updatable) Customer defined tags.
        /// </summary>
        public readonly ImmutableArray<Outputs.AssetVmwareVmCustomerTag> CustomerTags;
        /// <summary>
        /// (Updatable) Fault tolerance bandwidth.
        /// </summary>
        public readonly int? FaultToleranceBandwidth;
        /// <summary>
        /// (Updatable) Fault tolerance to secondary latency.
        /// </summary>
        public readonly int? FaultToleranceSecondaryLatency;
        /// <summary>
        /// (Updatable) Fault tolerance state.
        /// </summary>
        public readonly string? FaultToleranceState;
        /// <summary>
        /// (Updatable) vCenter-specific identifier of the virtual machine.
        /// </summary>
        public readonly string? InstanceUuid;
        /// <summary>
        /// (Updatable) Indicates that change tracking is supported for virtual disks of this virtual machine. However, even if change tracking is supported, it might not be available for all disks of the virtual machine.
        /// </summary>
        public readonly bool? IsDisksCbtEnabled;
        /// <summary>
        /// (Updatable) Whether changed block tracking for this VM's disk is active.
        /// </summary>
        public readonly bool? IsDisksUuidEnabled;
        /// <summary>
        /// (Updatable) Path directory of the asset.
        /// </summary>
        public readonly string? Path;
        /// <summary>
        /// (Updatable) VMware tools status.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? VmwareToolsStatus;

        [OutputConstructor]
        private AssetVmwareVm(
            string? cluster,

            ImmutableArray<string> customerFields,

            ImmutableArray<Outputs.AssetVmwareVmCustomerTag> customerTags,

            int? faultToleranceBandwidth,

            int? faultToleranceSecondaryLatency,

            string? faultToleranceState,

            string? instanceUuid,

            bool? isDisksCbtEnabled,

            bool? isDisksUuidEnabled,

            string? path,

            string? vmwareToolsStatus)
        {
            Cluster = cluster;
            CustomerFields = customerFields;
            CustomerTags = customerTags;
            FaultToleranceBandwidth = faultToleranceBandwidth;
            FaultToleranceSecondaryLatency = faultToleranceSecondaryLatency;
            FaultToleranceState = faultToleranceState;
            InstanceUuid = instanceUuid;
            IsDisksCbtEnabled = isDisksCbtEnabled;
            IsDisksUuidEnabled = isDisksUuidEnabled;
            Path = path;
            VmwareToolsStatus = vmwareToolsStatus;
        }
    }
}
