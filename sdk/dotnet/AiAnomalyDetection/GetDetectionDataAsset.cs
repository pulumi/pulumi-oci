// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection
{
    public static class GetDetectionDataAsset
    {
        /// <summary>
        /// This data source provides details about a specific Data Asset resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Gets a DataAsset by identifier
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
        ///     var testDataAsset = Oci.AiAnomalyDetection.GetDetectionDataAsset.Invoke(new()
        ///     {
        ///         DataAssetId = testDataAssetOciAiAnomalyDetectionDataAsset.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDetectionDataAssetResult> InvokeAsync(GetDetectionDataAssetArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDetectionDataAssetResult>("oci:AiAnomalyDetection/getDetectionDataAsset:getDetectionDataAsset", args ?? new GetDetectionDataAssetArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Data Asset resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Gets a DataAsset by identifier
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
        ///     var testDataAsset = Oci.AiAnomalyDetection.GetDetectionDataAsset.Invoke(new()
        ///     {
        ///         DataAssetId = testDataAssetOciAiAnomalyDetectionDataAsset.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDetectionDataAssetResult> Invoke(GetDetectionDataAssetInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectionDataAssetResult>("oci:AiAnomalyDetection/getDetectionDataAsset:getDetectionDataAsset", args ?? new GetDetectionDataAssetInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Data Asset resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Gets a DataAsset by identifier
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
        ///     var testDataAsset = Oci.AiAnomalyDetection.GetDetectionDataAsset.Invoke(new()
        ///     {
        ///         DataAssetId = testDataAssetOciAiAnomalyDetectionDataAsset.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDetectionDataAssetResult> Invoke(GetDetectionDataAssetInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectionDataAssetResult>("oci:AiAnomalyDetection/getDetectionDataAsset:getDetectionDataAsset", args ?? new GetDetectionDataAssetInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDetectionDataAssetArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the Data Asset.
        /// </summary>
        [Input("dataAssetId", required: true)]
        public string DataAssetId { get; set; } = null!;

        public GetDetectionDataAssetArgs()
        {
        }
        public static new GetDetectionDataAssetArgs Empty => new GetDetectionDataAssetArgs();
    }

    public sealed class GetDetectionDataAssetInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the Data Asset.
        /// </summary>
        [Input("dataAssetId", required: true)]
        public Input<string> DataAssetId { get; set; } = null!;

        public GetDetectionDataAssetInvokeArgs()
        {
        }
        public static new GetDetectionDataAssetInvokeArgs Empty => new GetDetectionDataAssetInvokeArgs();
    }


    [OutputType]
    public sealed class GetDetectionDataAssetResult
    {
        /// <summary>
        /// The OCID of the compartment containing the DataAsset.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string DataAssetId;
        /// <summary>
        /// Possible data sources
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectionDataAssetDataSourceDetailResult> DataSourceDetails;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A short description of the data asset.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The Unique Oracle ID (OCID) that is immutable on creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// OCID of Private Endpoint.
        /// </summary>
        public readonly string PrivateEndpointId;
        /// <summary>
        /// The Unique project id which is created at project creation that is immutable on creation.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// The lifecycle state of the Data Asset.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the the DataAsset was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the the DataAsset was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDetectionDataAssetResult(
            string compartmentId,

            string dataAssetId,

            ImmutableArray<Outputs.GetDetectionDataAssetDataSourceDetailResult> dataSourceDetails,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string privateEndpointId,

            string projectId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DataAssetId = dataAssetId;
            DataSourceDetails = dataSourceDetails;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            PrivateEndpointId = privateEndpointId;
            ProjectId = projectId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
