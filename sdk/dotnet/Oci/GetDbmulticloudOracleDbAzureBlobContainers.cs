// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci
{
    public static class GetDbmulticloudOracleDbAzureBlobContainers
    {
        /// <summary>
        /// This data source provides the list of Oracle Db Azure Blob Containers in Oracle Cloud Infrastructure Dbmulticloud service.
        /// 
        /// Lists the all Oracle DB Azure Blob Container based on filter.
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
        ///     var testOracleDbAzureBlobContainers = Oci.Oci.GetDbmulticloudOracleDbAzureBlobContainers.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AzureStorageAccountName = oracleDbAzureBlobContainerAzureStorageAccountName,
        ///         AzureStorageContainerName = oracleDbAzureBlobContainerAzureStorageContainerName,
        ///         DisplayName = oracleDbAzureBlobContainerDisplayName,
        ///         OracleDbAzureBlobContainerId = testOracleDbAzureBlobContainer.Id,
        ///         State = oracleDbAzureBlobContainerState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDbmulticloudOracleDbAzureBlobContainersResult> InvokeAsync(GetDbmulticloudOracleDbAzureBlobContainersArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDbmulticloudOracleDbAzureBlobContainersResult>("oci:oci/getDbmulticloudOracleDbAzureBlobContainers:getDbmulticloudOracleDbAzureBlobContainers", args ?? new GetDbmulticloudOracleDbAzureBlobContainersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Oracle Db Azure Blob Containers in Oracle Cloud Infrastructure Dbmulticloud service.
        /// 
        /// Lists the all Oracle DB Azure Blob Container based on filter.
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
        ///     var testOracleDbAzureBlobContainers = Oci.Oci.GetDbmulticloudOracleDbAzureBlobContainers.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AzureStorageAccountName = oracleDbAzureBlobContainerAzureStorageAccountName,
        ///         AzureStorageContainerName = oracleDbAzureBlobContainerAzureStorageContainerName,
        ///         DisplayName = oracleDbAzureBlobContainerDisplayName,
        ///         OracleDbAzureBlobContainerId = testOracleDbAzureBlobContainer.Id,
        ///         State = oracleDbAzureBlobContainerState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbmulticloudOracleDbAzureBlobContainersResult> Invoke(GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbmulticloudOracleDbAzureBlobContainersResult>("oci:oci/getDbmulticloudOracleDbAzureBlobContainers:getDbmulticloudOracleDbAzureBlobContainers", args ?? new GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Oracle Db Azure Blob Containers in Oracle Cloud Infrastructure Dbmulticloud service.
        /// 
        /// Lists the all Oracle DB Azure Blob Container based on filter.
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
        ///     var testOracleDbAzureBlobContainers = Oci.Oci.GetDbmulticloudOracleDbAzureBlobContainers.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AzureStorageAccountName = oracleDbAzureBlobContainerAzureStorageAccountName,
        ///         AzureStorageContainerName = oracleDbAzureBlobContainerAzureStorageContainerName,
        ///         DisplayName = oracleDbAzureBlobContainerDisplayName,
        ///         OracleDbAzureBlobContainerId = testOracleDbAzureBlobContainer.Id,
        ///         State = oracleDbAzureBlobContainerState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbmulticloudOracleDbAzureBlobContainersResult> Invoke(GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbmulticloudOracleDbAzureBlobContainersResult>("oci:oci/getDbmulticloudOracleDbAzureBlobContainers:getDbmulticloudOracleDbAzureBlobContainers", args ?? new GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDbmulticloudOracleDbAzureBlobContainersArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return Azure Blob Containers.
        /// </summary>
        [Input("azureStorageAccountName")]
        public string? AzureStorageAccountName { get; set; }

        /// <summary>
        /// A filter to return Azure Blob containers.
        /// </summary>
        [Input("azureStorageContainerName")]
        public string? AzureStorageContainerName { get; set; }

        /// <summary>
        /// The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return Azure Containers.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDbmulticloudOracleDbAzureBlobContainersFilterArgs>? _filters;
        public List<Inputs.GetDbmulticloudOracleDbAzureBlobContainersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDbmulticloudOracleDbAzureBlobContainersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return Oracle DB Azure Blob Mount Resources.
        /// </summary>
        [Input("oracleDbAzureBlobContainerId")]
        public string? OracleDbAzureBlobContainerId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDbmulticloudOracleDbAzureBlobContainersArgs()
        {
        }
        public static new GetDbmulticloudOracleDbAzureBlobContainersArgs Empty => new GetDbmulticloudOracleDbAzureBlobContainersArgs();
    }

    public sealed class GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return Azure Blob Containers.
        /// </summary>
        [Input("azureStorageAccountName")]
        public Input<string>? AzureStorageAccountName { get; set; }

        /// <summary>
        /// A filter to return Azure Blob containers.
        /// </summary>
        [Input("azureStorageContainerName")]
        public Input<string>? AzureStorageContainerName { get; set; }

        /// <summary>
        /// The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return Azure Containers.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDbmulticloudOracleDbAzureBlobContainersFilterInputArgs>? _filters;
        public InputList<Inputs.GetDbmulticloudOracleDbAzureBlobContainersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDbmulticloudOracleDbAzureBlobContainersFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return Oracle DB Azure Blob Mount Resources.
        /// </summary>
        [Input("oracleDbAzureBlobContainerId")]
        public Input<string>? OracleDbAzureBlobContainerId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs()
        {
        }
        public static new GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs Empty => new GetDbmulticloudOracleDbAzureBlobContainersInvokeArgs();
    }


    [OutputType]
    public sealed class GetDbmulticloudOracleDbAzureBlobContainersResult
    {
        /// <summary>
        /// Azure Storage Account Name.
        /// </summary>
        public readonly string? AzureStorageAccountName;
        /// <summary>
        /// Azure Storage Container Name.
        /// </summary>
        public readonly string? AzureStorageContainerName;
        /// <summary>
        /// The ID of the compartment that contains Oracle DB Azure Blob Container Resource.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Display name of Oracle DB Azure Blob Container.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDbmulticloudOracleDbAzureBlobContainersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? OracleDbAzureBlobContainerId;
        /// <summary>
        /// The list of oracle_db_azure_blob_container_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbmulticloudOracleDbAzureBlobContainersOracleDbAzureBlobContainerSummaryCollectionResult> OracleDbAzureBlobContainerSummaryCollections;
        /// <summary>
        /// The current lifecycle state of the Oracle DB Azure Blob Container Resource.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDbmulticloudOracleDbAzureBlobContainersResult(
            string? azureStorageAccountName,

            string? azureStorageContainerName,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetDbmulticloudOracleDbAzureBlobContainersFilterResult> filters,

            string id,

            string? oracleDbAzureBlobContainerId,

            ImmutableArray<Outputs.GetDbmulticloudOracleDbAzureBlobContainersOracleDbAzureBlobContainerSummaryCollectionResult> oracleDbAzureBlobContainerSummaryCollections,

            string? state)
        {
            AzureStorageAccountName = azureStorageAccountName;
            AzureStorageContainerName = azureStorageContainerName;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OracleDbAzureBlobContainerId = oracleDbAzureBlobContainerId;
            OracleDbAzureBlobContainerSummaryCollections = oracleDbAzureBlobContainerSummaryCollections;
            State = state;
        }
    }
}
