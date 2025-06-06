// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration
{
    public static class GetWorkspaceExportRequest
    {
        /// <summary>
        /// This data source provides details about a specific Workspace Export Request resource in Oracle Cloud Infrastructure Data Integration service.
        /// 
        /// This endpoint can be used to get the summary/details of object being exported.
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
        ///     var testWorkspaceExportRequest = Oci.DataIntegration.GetWorkspaceExportRequest.Invoke(new()
        ///     {
        ///         ExportRequestKey = workspaceExportRequestExportRequestKey,
        ///         WorkspaceId = testWorkspace.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetWorkspaceExportRequestResult> InvokeAsync(GetWorkspaceExportRequestArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetWorkspaceExportRequestResult>("oci:DataIntegration/getWorkspaceExportRequest:getWorkspaceExportRequest", args ?? new GetWorkspaceExportRequestArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Workspace Export Request resource in Oracle Cloud Infrastructure Data Integration service.
        /// 
        /// This endpoint can be used to get the summary/details of object being exported.
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
        ///     var testWorkspaceExportRequest = Oci.DataIntegration.GetWorkspaceExportRequest.Invoke(new()
        ///     {
        ///         ExportRequestKey = workspaceExportRequestExportRequestKey,
        ///         WorkspaceId = testWorkspace.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWorkspaceExportRequestResult> Invoke(GetWorkspaceExportRequestInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetWorkspaceExportRequestResult>("oci:DataIntegration/getWorkspaceExportRequest:getWorkspaceExportRequest", args ?? new GetWorkspaceExportRequestInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Workspace Export Request resource in Oracle Cloud Infrastructure Data Integration service.
        /// 
        /// This endpoint can be used to get the summary/details of object being exported.
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
        ///     var testWorkspaceExportRequest = Oci.DataIntegration.GetWorkspaceExportRequest.Invoke(new()
        ///     {
        ///         ExportRequestKey = workspaceExportRequestExportRequestKey,
        ///         WorkspaceId = testWorkspace.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWorkspaceExportRequestResult> Invoke(GetWorkspaceExportRequestInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetWorkspaceExportRequestResult>("oci:DataIntegration/getWorkspaceExportRequest:getWorkspaceExportRequest", args ?? new GetWorkspaceExportRequestInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWorkspaceExportRequestArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The key of the object export object request
        /// </summary>
        [Input("exportRequestKey", required: true)]
        public string ExportRequestKey { get; set; } = null!;

        /// <summary>
        /// The workspace ID.
        /// </summary>
        [Input("workspaceId", required: true)]
        public string WorkspaceId { get; set; } = null!;

        public GetWorkspaceExportRequestArgs()
        {
        }
        public static new GetWorkspaceExportRequestArgs Empty => new GetWorkspaceExportRequestArgs();
    }

    public sealed class GetWorkspaceExportRequestInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The key of the object export object request
        /// </summary>
        [Input("exportRequestKey", required: true)]
        public Input<string> ExportRequestKey { get; set; } = null!;

        /// <summary>
        /// The workspace ID.
        /// </summary>
        [Input("workspaceId", required: true)]
        public Input<string> WorkspaceId { get; set; } = null!;

        public GetWorkspaceExportRequestInvokeArgs()
        {
        }
        public static new GetWorkspaceExportRequestInvokeArgs Empty => new GetWorkspaceExportRequestInvokeArgs();
    }


    [OutputType]
    public sealed class GetWorkspaceExportRequestResult
    {
        /// <summary>
        /// Controls if the references will be exported along with the objects
        /// </summary>
        public readonly bool AreReferencesIncluded;
        /// <summary>
        /// The name of the Object Storage Bucket where the objects will be exported to
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// Name of the user who initiated export request.
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Contains key of the error
        /// </summary>
        public readonly ImmutableDictionary<string, string> ErrorMessages;
        public readonly string ExportRequestKey;
        /// <summary>
        /// The array of exported object details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkspaceExportRequestExportedItemResult> ExportedItems;
        /// <summary>
        /// Name of the exported zip file.
        /// </summary>
        public readonly string FileName;
        /// <summary>
        /// Export multiple objects based on filters.
        /// </summary>
        public readonly ImmutableArray<string> Filters;
        public readonly string Id;
        /// <summary>
        /// Flag to control whether to overwrite the object if it is already present at the provided object storage location.
        /// </summary>
        public readonly bool IsObjectOverwriteEnabled;
        /// <summary>
        /// Export object request key
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Name of the export request.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The list of the objects to be exported
        /// </summary>
        public readonly ImmutableArray<string> ObjectKeys;
        /// <summary>
        /// Region of the object storage (if using object storage of different region)
        /// </summary>
        public readonly string ObjectStorageRegion;
        /// <summary>
        /// Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
        /// </summary>
        public readonly string ObjectStorageTenancyId;
        /// <summary>
        /// The array of exported referenced objects.
        /// </summary>
        public readonly string ReferencedItems;
        /// <summary>
        /// Export Objects request status.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Time at which the request was completely processed.
        /// </summary>
        public readonly string TimeEndedInMillis;
        /// <summary>
        /// Time at which the request started getting processed.
        /// </summary>
        public readonly string TimeStartedInMillis;
        /// <summary>
        /// Number of objects that are exported.
        /// </summary>
        public readonly int TotalExportedObjectCount;
        public readonly string WorkspaceId;

        [OutputConstructor]
        private GetWorkspaceExportRequestResult(
            bool areReferencesIncluded,

            string bucket,

            string createdBy,

            ImmutableDictionary<string, string> errorMessages,

            string exportRequestKey,

            ImmutableArray<Outputs.GetWorkspaceExportRequestExportedItemResult> exportedItems,

            string fileName,

            ImmutableArray<string> filters,

            string id,

            bool isObjectOverwriteEnabled,

            string key,

            string name,

            ImmutableArray<string> objectKeys,

            string objectStorageRegion,

            string objectStorageTenancyId,

            string referencedItems,

            string status,

            string timeEndedInMillis,

            string timeStartedInMillis,

            int totalExportedObjectCount,

            string workspaceId)
        {
            AreReferencesIncluded = areReferencesIncluded;
            Bucket = bucket;
            CreatedBy = createdBy;
            ErrorMessages = errorMessages;
            ExportRequestKey = exportRequestKey;
            ExportedItems = exportedItems;
            FileName = fileName;
            Filters = filters;
            Id = id;
            IsObjectOverwriteEnabled = isObjectOverwriteEnabled;
            Key = key;
            Name = name;
            ObjectKeys = objectKeys;
            ObjectStorageRegion = objectStorageRegion;
            ObjectStorageTenancyId = objectStorageTenancyId;
            ReferencedItems = referencedItems;
            Status = status;
            TimeEndedInMillis = timeEndedInMillis;
            TimeStartedInMillis = timeStartedInMillis;
            TotalExportedObjectCount = totalExportedObjectCount;
            WorkspaceId = workspaceId;
        }
    }
}
