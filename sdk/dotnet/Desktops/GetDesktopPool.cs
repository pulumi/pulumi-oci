// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Desktops
{
    public static class GetDesktopPool
    {
        /// <summary>
        /// This data source provides details about a specific Desktop Pool resource in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns information about the desktop pool including all configuration parameters and the current state.
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
        ///     var testDesktopPool = Oci.Desktops.GetDesktopPool.Invoke(new()
        ///     {
        ///         DesktopPoolId = testDesktopPoolOciDesktopsDesktopPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDesktopPoolResult> InvokeAsync(GetDesktopPoolArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDesktopPoolResult>("oci:Desktops/getDesktopPool:getDesktopPool", args ?? new GetDesktopPoolArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Desktop Pool resource in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns information about the desktop pool including all configuration parameters and the current state.
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
        ///     var testDesktopPool = Oci.Desktops.GetDesktopPool.Invoke(new()
        ///     {
        ///         DesktopPoolId = testDesktopPoolOciDesktopsDesktopPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDesktopPoolResult> Invoke(GetDesktopPoolInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDesktopPoolResult>("oci:Desktops/getDesktopPool:getDesktopPool", args ?? new GetDesktopPoolInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Desktop Pool resource in Oracle Cloud Infrastructure Desktops service.
        /// 
        /// Returns information about the desktop pool including all configuration parameters and the current state.
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
        ///     var testDesktopPool = Oci.Desktops.GetDesktopPool.Invoke(new()
        ///     {
        ///         DesktopPoolId = testDesktopPoolOciDesktopsDesktopPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDesktopPoolResult> Invoke(GetDesktopPoolInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDesktopPoolResult>("oci:Desktops/getDesktopPool:getDesktopPool", args ?? new GetDesktopPoolInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDesktopPoolArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the desktop pool.
        /// </summary>
        [Input("desktopPoolId", required: true)]
        public string DesktopPoolId { get; set; } = null!;

        public GetDesktopPoolArgs()
        {
        }
        public static new GetDesktopPoolArgs Empty => new GetDesktopPoolArgs();
    }

    public sealed class GetDesktopPoolInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the desktop pool.
        /// </summary>
        [Input("desktopPoolId", required: true)]
        public Input<string> DesktopPoolId { get; set; } = null!;

        public GetDesktopPoolInvokeArgs()
        {
        }
        public static new GetDesktopPoolInvokeArgs Empty => new GetDesktopPoolInvokeArgs();
    }


    [OutputType]
    public sealed class GetDesktopPoolResult
    {
        /// <summary>
        /// The number of active desktops in the desktop pool.
        /// </summary>
        public readonly int ActiveDesktops;
        /// <summary>
        /// Indicates whether desktop pool users have administrative privileges on their desktop.
        /// </summary>
        public readonly bool ArePrivilegedUsers;
        public readonly bool AreVolumesPreserved;
        /// <summary>
        /// The availability domain of the desktop pool.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// Provides the start and stop schedule information for desktop availability of the desktop pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolAvailabilityPolicyResult> AvailabilityPolicies;
        /// <summary>
        /// The OCID of the compartment of the desktop pool.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Contact information of the desktop pool administrator. Avoid entering confidential information.
        /// </summary>
        public readonly string ContactDetails;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user friendly description providing additional information about the resource. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        public readonly string DesktopPoolId;
        /// <summary>
        /// Provides the settings for desktop and client device options, such as audio in and out, client drive mapping, and clipboard access.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolDevicePolicyResult> DevicePolicies;
        /// <summary>
        /// A user friendly display name. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the desktop pool.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Provides information about the desktop image.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolImageResult> Images;
        /// <summary>
        /// Indicates whether storage is enabled for the desktop pool.
        /// </summary>
        public readonly bool IsStorageEnabled;
        /// <summary>
        /// The maximum number of desktops permitted in the desktop pool.
        /// </summary>
        public readonly int MaximumSize;
        /// <summary>
        /// Provides information about the network configuration of the desktop pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolNetworkConfigurationResult> NetworkConfigurations;
        /// <summary>
        /// A list of network security groups for the private access.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The details of the desktop's private access network connectivity that were used to create the pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolPrivateAccessDetailResult> PrivateAccessDetails;
        /// <summary>
        /// Action to be triggered on inactivity or disconnect
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolSessionLifecycleActionResult> SessionLifecycleActions;
        /// <summary>
        /// The shape configuration used for each desktop compute instance in the desktop pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolShapeConfigResult> ShapeConfigs;
        /// <summary>
        /// The shape of the desktop pool.
        /// </summary>
        public readonly string ShapeName;
        /// <summary>
        /// The maximum number of standby desktops available in the desktop pool.
        /// </summary>
        public readonly int StandbySize;
        /// <summary>
        /// The current state of the desktop pool.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The backup policy OCID of the storage.
        /// </summary>
        public readonly string StorageBackupPolicyId;
        /// <summary>
        /// The size in GBs of the storage for the desktop pool.
        /// </summary>
        public readonly int StorageSizeInGbs;
        /// <summary>
        /// The date and time the resource was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The start time of the desktop pool.
        /// </summary>
        public readonly string TimeStartScheduled;
        /// <summary>
        /// The stop time of the desktop pool.
        /// </summary>
        public readonly string TimeStopScheduled;
        /// <summary>
        /// Indicates whether the desktop pool uses dedicated virtual machine hosts.
        /// ---
        /// </summary>
        public readonly string UseDedicatedVmHost;

        [OutputConstructor]
        private GetDesktopPoolResult(
            int activeDesktops,

            bool arePrivilegedUsers,

            bool areVolumesPreserved,

            string availabilityDomain,

            ImmutableArray<Outputs.GetDesktopPoolAvailabilityPolicyResult> availabilityPolicies,

            string compartmentId,

            string contactDetails,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string desktopPoolId,

            ImmutableArray<Outputs.GetDesktopPoolDevicePolicyResult> devicePolicies,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetDesktopPoolImageResult> images,

            bool isStorageEnabled,

            int maximumSize,

            ImmutableArray<Outputs.GetDesktopPoolNetworkConfigurationResult> networkConfigurations,

            ImmutableArray<string> nsgIds,

            ImmutableArray<Outputs.GetDesktopPoolPrivateAccessDetailResult> privateAccessDetails,

            ImmutableArray<Outputs.GetDesktopPoolSessionLifecycleActionResult> sessionLifecycleActions,

            ImmutableArray<Outputs.GetDesktopPoolShapeConfigResult> shapeConfigs,

            string shapeName,

            int standbySize,

            string state,

            string storageBackupPolicyId,

            int storageSizeInGbs,

            string timeCreated,

            string timeStartScheduled,

            string timeStopScheduled,

            string useDedicatedVmHost)
        {
            ActiveDesktops = activeDesktops;
            ArePrivilegedUsers = arePrivilegedUsers;
            AreVolumesPreserved = areVolumesPreserved;
            AvailabilityDomain = availabilityDomain;
            AvailabilityPolicies = availabilityPolicies;
            CompartmentId = compartmentId;
            ContactDetails = contactDetails;
            DefinedTags = definedTags;
            Description = description;
            DesktopPoolId = desktopPoolId;
            DevicePolicies = devicePolicies;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            Images = images;
            IsStorageEnabled = isStorageEnabled;
            MaximumSize = maximumSize;
            NetworkConfigurations = networkConfigurations;
            NsgIds = nsgIds;
            PrivateAccessDetails = privateAccessDetails;
            SessionLifecycleActions = sessionLifecycleActions;
            ShapeConfigs = shapeConfigs;
            ShapeName = shapeName;
            StandbySize = standbySize;
            State = state;
            StorageBackupPolicyId = storageBackupPolicyId;
            StorageSizeInGbs = storageSizeInGbs;
            TimeCreated = timeCreated;
            TimeStartScheduled = timeStartScheduled;
            TimeStopScheduled = timeStopScheduled;
            UseDedicatedVmHost = useDedicatedVmHost;
        }
    }
}
