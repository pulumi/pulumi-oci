// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVolumeBackups
    {
        /// <summary>
        /// This data source provides the list of Volume Backups in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the volume backups in the specified compartment. You can filter the results by volume.
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
        ///     var testVolumeBackups = Oci.Core.GetVolumeBackups.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = volumeBackupDisplayName,
        ///         SourceVolumeBackupId = testVolumeBackup.Id,
        ///         State = volumeBackupState,
        ///         VolumeId = testVolume.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetVolumeBackupsResult> InvokeAsync(GetVolumeBackupsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetVolumeBackupsResult>("oci:Core/getVolumeBackups:getVolumeBackups", args ?? new GetVolumeBackupsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Volume Backups in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the volume backups in the specified compartment. You can filter the results by volume.
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
        ///     var testVolumeBackups = Oci.Core.GetVolumeBackups.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = volumeBackupDisplayName,
        ///         SourceVolumeBackupId = testVolumeBackup.Id,
        ///         State = volumeBackupState,
        ///         VolumeId = testVolume.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetVolumeBackupsResult> Invoke(GetVolumeBackupsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetVolumeBackupsResult>("oci:Core/getVolumeBackups:getVolumeBackups", args ?? new GetVolumeBackupsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Volume Backups in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the volume backups in the specified compartment. You can filter the results by volume.
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
        ///     var testVolumeBackups = Oci.Core.GetVolumeBackups.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = volumeBackupDisplayName,
        ///         SourceVolumeBackupId = testVolumeBackup.Id,
        ///         State = volumeBackupState,
        ///         VolumeId = testVolume.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetVolumeBackupsResult> Invoke(GetVolumeBackupsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetVolumeBackupsResult>("oci:Core/getVolumeBackups:getVolumeBackups", args ?? new GetVolumeBackupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVolumeBackupsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetVolumeBackupsFilterArgs>? _filters;
        public List<Inputs.GetVolumeBackupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVolumeBackupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that originated from the given source volume backup.
        /// </summary>
        [Input("sourceVolumeBackupId")]
        public string? SourceVolumeBackupId { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The OCID of the volume.
        /// </summary>
        [Input("volumeId")]
        public string? VolumeId { get; set; }

        public GetVolumeBackupsArgs()
        {
        }
        public static new GetVolumeBackupsArgs Empty => new GetVolumeBackupsArgs();
    }

    public sealed class GetVolumeBackupsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetVolumeBackupsFilterInputArgs>? _filters;
        public InputList<Inputs.GetVolumeBackupsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVolumeBackupsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that originated from the given source volume backup.
        /// </summary>
        [Input("sourceVolumeBackupId")]
        public Input<string>? SourceVolumeBackupId { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of the volume.
        /// </summary>
        [Input("volumeId")]
        public Input<string>? VolumeId { get; set; }

        public GetVolumeBackupsInvokeArgs()
        {
        }
        public static new GetVolumeBackupsInvokeArgs Empty => new GetVolumeBackupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetVolumeBackupsResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the volume backup.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetVolumeBackupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the source volume backup.
        /// </summary>
        public readonly string? SourceVolumeBackupId;
        /// <summary>
        /// The current state of a volume backup.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of volume_backups.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVolumeBackupsVolumeBackupResult> VolumeBackups;
        /// <summary>
        /// The OCID of the volume.
        /// </summary>
        public readonly string? VolumeId;

        [OutputConstructor]
        private GetVolumeBackupsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetVolumeBackupsFilterResult> filters,

            string id,

            string? sourceVolumeBackupId,

            string? state,

            ImmutableArray<Outputs.GetVolumeBackupsVolumeBackupResult> volumeBackups,

            string? volumeId)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            SourceVolumeBackupId = sourceVolumeBackupId;
            State = state;
            VolumeBackups = volumeBackups;
            VolumeId = volumeId;
        }
    }
}
