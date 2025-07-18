// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService
{
    public static class GetBdsInstanceNodeBackupConfigurations
    {
        /// <summary>
        /// This data source provides the list of Bds Instance Node Backup Configurations in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns information about the NodeBackupConfigurations.
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
        ///     var testBdsInstanceNodeBackupConfigurations = Oci.BigDataService.GetBdsInstanceNodeBackupConfigurations.Invoke(new()
        ///     {
        ///         BdsInstanceId = testBdsInstance.Id,
        ///         DisplayName = bdsInstanceNodeBackupConfigurationDisplayName,
        ///         State = bdsInstanceNodeBackupConfigurationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBdsInstanceNodeBackupConfigurationsResult> InvokeAsync(GetBdsInstanceNodeBackupConfigurationsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBdsInstanceNodeBackupConfigurationsResult>("oci:BigDataService/getBdsInstanceNodeBackupConfigurations:getBdsInstanceNodeBackupConfigurations", args ?? new GetBdsInstanceNodeBackupConfigurationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Bds Instance Node Backup Configurations in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns information about the NodeBackupConfigurations.
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
        ///     var testBdsInstanceNodeBackupConfigurations = Oci.BigDataService.GetBdsInstanceNodeBackupConfigurations.Invoke(new()
        ///     {
        ///         BdsInstanceId = testBdsInstance.Id,
        ///         DisplayName = bdsInstanceNodeBackupConfigurationDisplayName,
        ///         State = bdsInstanceNodeBackupConfigurationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBdsInstanceNodeBackupConfigurationsResult> Invoke(GetBdsInstanceNodeBackupConfigurationsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceNodeBackupConfigurationsResult>("oci:BigDataService/getBdsInstanceNodeBackupConfigurations:getBdsInstanceNodeBackupConfigurations", args ?? new GetBdsInstanceNodeBackupConfigurationsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Bds Instance Node Backup Configurations in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns information about the NodeBackupConfigurations.
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
        ///     var testBdsInstanceNodeBackupConfigurations = Oci.BigDataService.GetBdsInstanceNodeBackupConfigurations.Invoke(new()
        ///     {
        ///         BdsInstanceId = testBdsInstance.Id,
        ///         DisplayName = bdsInstanceNodeBackupConfigurationDisplayName,
        ///         State = bdsInstanceNodeBackupConfigurationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBdsInstanceNodeBackupConfigurationsResult> Invoke(GetBdsInstanceNodeBackupConfigurationsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceNodeBackupConfigurationsResult>("oci:BigDataService/getBdsInstanceNodeBackupConfigurations:getBdsInstanceNodeBackupConfigurations", args ?? new GetBdsInstanceNodeBackupConfigurationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBdsInstanceNodeBackupConfigurationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("bdsInstanceId", required: true)]
        public string BdsInstanceId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetBdsInstanceNodeBackupConfigurationsFilterArgs>? _filters;
        public List<Inputs.GetBdsInstanceNodeBackupConfigurationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBdsInstanceNodeBackupConfigurationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The state of the NodeBackupConfiguration configuration.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetBdsInstanceNodeBackupConfigurationsArgs()
        {
        }
        public static new GetBdsInstanceNodeBackupConfigurationsArgs Empty => new GetBdsInstanceNodeBackupConfigurationsArgs();
    }

    public sealed class GetBdsInstanceNodeBackupConfigurationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("bdsInstanceId", required: true)]
        public Input<string> BdsInstanceId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetBdsInstanceNodeBackupConfigurationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetBdsInstanceNodeBackupConfigurationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBdsInstanceNodeBackupConfigurationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The state of the NodeBackupConfiguration configuration.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetBdsInstanceNodeBackupConfigurationsInvokeArgs()
        {
        }
        public static new GetBdsInstanceNodeBackupConfigurationsInvokeArgs Empty => new GetBdsInstanceNodeBackupConfigurationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetBdsInstanceNodeBackupConfigurationsResult
    {
        /// <summary>
        /// The OCID of the bdsInstance which is the parent resource id.
        /// </summary>
        public readonly string BdsInstanceId;
        /// <summary>
        /// A user-friendly name. Only ASCII alphanumeric characters with no spaces allowed. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBdsInstanceNodeBackupConfigurationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of node_backup_configurations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstanceNodeBackupConfigurationsNodeBackupConfigurationResult> NodeBackupConfigurations;
        /// <summary>
        /// The state of the NodeBackupConfiguration.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetBdsInstanceNodeBackupConfigurationsResult(
            string bdsInstanceId,

            string? displayName,

            ImmutableArray<Outputs.GetBdsInstanceNodeBackupConfigurationsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetBdsInstanceNodeBackupConfigurationsNodeBackupConfigurationResult> nodeBackupConfigurations,

            string? state)
        {
            BdsInstanceId = bdsInstanceId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            NodeBackupConfigurations = nodeBackupConfigurations;
            State = state;
        }
    }
}
