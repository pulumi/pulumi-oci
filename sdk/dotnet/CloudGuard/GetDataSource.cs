// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetDataSource
    {
        /// <summary>
        /// This data source provides details about a specific Data Source resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a data source (DataSource resource) identified by dataSourceId.
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
        ///     var testDataSource = Oci.CloudGuard.GetDataSource.Invoke(new()
        ///     {
        ///         DataSourceId = testDataSourceOciCloudGuardDataSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDataSourceResult> InvokeAsync(GetDataSourceArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDataSourceResult>("oci:CloudGuard/getDataSource:getDataSource", args ?? new GetDataSourceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Data Source resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a data source (DataSource resource) identified by dataSourceId.
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
        ///     var testDataSource = Oci.CloudGuard.GetDataSource.Invoke(new()
        ///     {
        ///         DataSourceId = testDataSourceOciCloudGuardDataSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDataSourceResult> Invoke(GetDataSourceInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataSourceResult>("oci:CloudGuard/getDataSource:getDataSource", args ?? new GetDataSourceInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Data Source resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a data source (DataSource resource) identified by dataSourceId.
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
        ///     var testDataSource = Oci.CloudGuard.GetDataSource.Invoke(new()
        ///     {
        ///         DataSourceId = testDataSourceOciCloudGuardDataSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDataSourceResult> Invoke(GetDataSourceInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataSourceResult>("oci:CloudGuard/getDataSource:getDataSource", args ?? new GetDataSourceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDataSourceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Data source OCID.
        /// </summary>
        [Input("dataSourceId", required: true)]
        public string DataSourceId { get; set; } = null!;

        public GetDataSourceArgs()
        {
        }
        public static new GetDataSourceArgs Empty => new GetDataSourceArgs();
    }

    public sealed class GetDataSourceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Data source OCID.
        /// </summary>
        [Input("dataSourceId", required: true)]
        public Input<string> DataSourceId { get; set; } = null!;

        public GetDataSourceInvokeArgs()
        {
        }
        public static new GetDataSourceInvokeArgs Empty => new GetDataSourceInvokeArgs();
    }


    [OutputType]
    public sealed class GetDataSourceResult
    {
        /// <summary>
        /// Compartment OCID of data source
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Details specific to the data source type.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourceDataSourceDetailResult> DataSourceDetails;
        /// <summary>
        /// Information about the detector recipe and rule attached
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourceDataSourceDetectorMappingInfoResult> DataSourceDetectorMappingInfos;
        /// <summary>
        /// Possible type of dataSourceFeed Provider(LoggingQuery)
        /// </summary>
        public readonly string DataSourceFeedProvider;
        public readonly string DataSourceId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Display name of the data source
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// OCID for the data source
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Information about the region and status of query replication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourceRegionStatusDetailResult> RegionStatusDetails;
        /// <summary>
        /// The current lifecycle state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Enablement status of the data source
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the Data source was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the data source was updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDataSourceResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDataSourceDataSourceDetailResult> dataSourceDetails,

            ImmutableArray<Outputs.GetDataSourceDataSourceDetectorMappingInfoResult> dataSourceDetectorMappingInfos,

            string dataSourceFeedProvider,

            string dataSourceId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetDataSourceRegionStatusDetailResult> regionStatusDetails,

            string state,

            string status,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DataSourceDetails = dataSourceDetails;
            DataSourceDetectorMappingInfos = dataSourceDetectorMappingInfos;
            DataSourceFeedProvider = dataSourceFeedProvider;
            DataSourceId = dataSourceId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            RegionStatusDetails = regionStatusDetails;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
