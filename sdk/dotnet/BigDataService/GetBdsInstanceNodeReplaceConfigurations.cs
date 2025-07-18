// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService
{
    public static class GetBdsInstanceNodeReplaceConfigurations
    {
        /// <summary>
        /// This data source provides the list of Bds Instance Node Replace Configurations in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns information about the NodeReplaceConfiguration.
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
        ///     var testBdsInstanceNodeReplaceConfigurations = Oci.BigDataService.GetBdsInstanceNodeReplaceConfigurations.Invoke(new()
        ///     {
        ///         BdsInstanceId = testBdsInstance.Id,
        ///         DisplayName = bdsInstanceNodeReplaceConfigurationDisplayName,
        ///         State = bdsInstanceNodeReplaceConfigurationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBdsInstanceNodeReplaceConfigurationsResult> InvokeAsync(GetBdsInstanceNodeReplaceConfigurationsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBdsInstanceNodeReplaceConfigurationsResult>("oci:BigDataService/getBdsInstanceNodeReplaceConfigurations:getBdsInstanceNodeReplaceConfigurations", args ?? new GetBdsInstanceNodeReplaceConfigurationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Bds Instance Node Replace Configurations in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns information about the NodeReplaceConfiguration.
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
        ///     var testBdsInstanceNodeReplaceConfigurations = Oci.BigDataService.GetBdsInstanceNodeReplaceConfigurations.Invoke(new()
        ///     {
        ///         BdsInstanceId = testBdsInstance.Id,
        ///         DisplayName = bdsInstanceNodeReplaceConfigurationDisplayName,
        ///         State = bdsInstanceNodeReplaceConfigurationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBdsInstanceNodeReplaceConfigurationsResult> Invoke(GetBdsInstanceNodeReplaceConfigurationsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceNodeReplaceConfigurationsResult>("oci:BigDataService/getBdsInstanceNodeReplaceConfigurations:getBdsInstanceNodeReplaceConfigurations", args ?? new GetBdsInstanceNodeReplaceConfigurationsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Bds Instance Node Replace Configurations in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns information about the NodeReplaceConfiguration.
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
        ///     var testBdsInstanceNodeReplaceConfigurations = Oci.BigDataService.GetBdsInstanceNodeReplaceConfigurations.Invoke(new()
        ///     {
        ///         BdsInstanceId = testBdsInstance.Id,
        ///         DisplayName = bdsInstanceNodeReplaceConfigurationDisplayName,
        ///         State = bdsInstanceNodeReplaceConfigurationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBdsInstanceNodeReplaceConfigurationsResult> Invoke(GetBdsInstanceNodeReplaceConfigurationsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceNodeReplaceConfigurationsResult>("oci:BigDataService/getBdsInstanceNodeReplaceConfigurations:getBdsInstanceNodeReplaceConfigurations", args ?? new GetBdsInstanceNodeReplaceConfigurationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBdsInstanceNodeReplaceConfigurationsArgs : global::Pulumi.InvokeArgs
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
        private List<Inputs.GetBdsInstanceNodeReplaceConfigurationsFilterArgs>? _filters;
        public List<Inputs.GetBdsInstanceNodeReplaceConfigurationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBdsInstanceNodeReplaceConfigurationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The state of the NodeReplaceConfiguration.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetBdsInstanceNodeReplaceConfigurationsArgs()
        {
        }
        public static new GetBdsInstanceNodeReplaceConfigurationsArgs Empty => new GetBdsInstanceNodeReplaceConfigurationsArgs();
    }

    public sealed class GetBdsInstanceNodeReplaceConfigurationsInvokeArgs : global::Pulumi.InvokeArgs
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
        private InputList<Inputs.GetBdsInstanceNodeReplaceConfigurationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetBdsInstanceNodeReplaceConfigurationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBdsInstanceNodeReplaceConfigurationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The state of the NodeReplaceConfiguration.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetBdsInstanceNodeReplaceConfigurationsInvokeArgs()
        {
        }
        public static new GetBdsInstanceNodeReplaceConfigurationsInvokeArgs Empty => new GetBdsInstanceNodeReplaceConfigurationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetBdsInstanceNodeReplaceConfigurationsResult
    {
        /// <summary>
        /// The OCID of the bdsInstance which is the parent resource id.
        /// </summary>
        public readonly string BdsInstanceId;
        /// <summary>
        /// A user-friendly name. Only ASCII alphanumeric characters with no spaces allowed. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBdsInstanceNodeReplaceConfigurationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of node_replace_configurations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstanceNodeReplaceConfigurationsNodeReplaceConfigurationResult> NodeReplaceConfigurations;
        /// <summary>
        /// The state of the NodeReplaceConfiguration.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetBdsInstanceNodeReplaceConfigurationsResult(
            string bdsInstanceId,

            string? displayName,

            ImmutableArray<Outputs.GetBdsInstanceNodeReplaceConfigurationsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetBdsInstanceNodeReplaceConfigurationsNodeReplaceConfigurationResult> nodeReplaceConfigurations,

            string? state)
        {
            BdsInstanceId = bdsInstanceId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            NodeReplaceConfigurations = nodeReplaceConfigurations;
            State = state;
        }
    }
}
