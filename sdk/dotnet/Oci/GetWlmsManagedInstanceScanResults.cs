// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci
{
    public static class GetWlmsManagedInstanceScanResults
    {
        /// <summary>
        /// This data source provides the list of Managed Instance Scan Results in Oracle Cloud Infrastructure Wlms service.
        /// 
        /// Gets all the scan results for all WebLogic servers in the managed instance.
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
        ///     var testManagedInstanceScanResults = Oci.Oci.GetWlmsManagedInstanceScanResults.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ServerName = managedInstanceScanResultServerName,
        ///         WlsDomainId = testWlsDomain.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetWlmsManagedInstanceScanResultsResult> InvokeAsync(GetWlmsManagedInstanceScanResultsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetWlmsManagedInstanceScanResultsResult>("oci:oci/getWlmsManagedInstanceScanResults:getWlmsManagedInstanceScanResults", args ?? new GetWlmsManagedInstanceScanResultsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Instance Scan Results in Oracle Cloud Infrastructure Wlms service.
        /// 
        /// Gets all the scan results for all WebLogic servers in the managed instance.
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
        ///     var testManagedInstanceScanResults = Oci.Oci.GetWlmsManagedInstanceScanResults.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ServerName = managedInstanceScanResultServerName,
        ///         WlsDomainId = testWlsDomain.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWlmsManagedInstanceScanResultsResult> Invoke(GetWlmsManagedInstanceScanResultsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetWlmsManagedInstanceScanResultsResult>("oci:oci/getWlmsManagedInstanceScanResults:getWlmsManagedInstanceScanResults", args ?? new GetWlmsManagedInstanceScanResultsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Instance Scan Results in Oracle Cloud Infrastructure Wlms service.
        /// 
        /// Gets all the scan results for all WebLogic servers in the managed instance.
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
        ///     var testManagedInstanceScanResults = Oci.Oci.GetWlmsManagedInstanceScanResults.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ServerName = managedInstanceScanResultServerName,
        ///         WlsDomainId = testWlsDomain.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWlmsManagedInstanceScanResultsResult> Invoke(GetWlmsManagedInstanceScanResultsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetWlmsManagedInstanceScanResultsResult>("oci:oci/getWlmsManagedInstanceScanResults:getWlmsManagedInstanceScanResults", args ?? new GetWlmsManagedInstanceScanResultsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWlmsManagedInstanceScanResultsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetWlmsManagedInstanceScanResultsFilterArgs>? _filters;
        public List<Inputs.GetWlmsManagedInstanceScanResultsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetWlmsManagedInstanceScanResultsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public string ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// The name of the server.
        /// </summary>
        [Input("serverName")]
        public string? ServerName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
        /// </summary>
        [Input("wlsDomainId")]
        public string? WlsDomainId { get; set; }

        public GetWlmsManagedInstanceScanResultsArgs()
        {
        }
        public static new GetWlmsManagedInstanceScanResultsArgs Empty => new GetWlmsManagedInstanceScanResultsArgs();
    }

    public sealed class GetWlmsManagedInstanceScanResultsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetWlmsManagedInstanceScanResultsFilterInputArgs>? _filters;
        public InputList<Inputs.GetWlmsManagedInstanceScanResultsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetWlmsManagedInstanceScanResultsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public Input<string> ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// The name of the server.
        /// </summary>
        [Input("serverName")]
        public Input<string>? ServerName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
        /// </summary>
        [Input("wlsDomainId")]
        public Input<string>? WlsDomainId { get; set; }

        public GetWlmsManagedInstanceScanResultsInvokeArgs()
        {
        }
        public static new GetWlmsManagedInstanceScanResultsInvokeArgs Empty => new GetWlmsManagedInstanceScanResultsInvokeArgs();
    }


    [OutputType]
    public sealed class GetWlmsManagedInstanceScanResultsResult
    {
        public readonly ImmutableArray<Outputs.GetWlmsManagedInstanceScanResultsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The list of scan_result_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWlmsManagedInstanceScanResultsScanResultCollectionResult> ScanResultCollections;
        /// <summary>
        /// The name of the WebLogic server to which the server check belongs.
        /// </summary>
        public readonly string? ServerName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
        /// </summary>
        public readonly string? WlsDomainId;

        [OutputConstructor]
        private GetWlmsManagedInstanceScanResultsResult(
            ImmutableArray<Outputs.GetWlmsManagedInstanceScanResultsFilterResult> filters,

            string id,

            string managedInstanceId,

            ImmutableArray<Outputs.GetWlmsManagedInstanceScanResultsScanResultCollectionResult> scanResultCollections,

            string? serverName,

            string? wlsDomainId)
        {
            Filters = filters;
            Id = id;
            ManagedInstanceId = managedInstanceId;
            ScanResultCollections = scanResultCollections;
            ServerName = serverName;
            WlsDomainId = wlsDomainId;
        }
    }
}
