// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Outputs
{

    [OutputType]
    public sealed class GetWorkspaceExportRequestsExportRequestSummaryCollectionItemResult
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
        /// <summary>
        /// The array of exported object details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItemResult> ExportedItems;
        /// <summary>
        /// Name of the exported zip file.
        /// </summary>
        public readonly string FileName;
        /// <summary>
        /// Export multiple objects based on filters.
        /// </summary>
        public readonly ImmutableArray<string> Filters;
        /// <summary>
        /// Flag to control whether to overwrite the object if it is already present at the provided object storage location.
        /// </summary>
        public readonly bool IsObjectOverwriteEnabled;
        /// <summary>
        /// Export object request key
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Used to filter by the name of the object.
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
        /// Specifies end time of a copy object request.
        /// </summary>
        public readonly string TimeEndedInMillis;
        /// <summary>
        /// Specifies start time of a copy object request.
        /// </summary>
        public readonly string TimeStartedInMillis;
        /// <summary>
        /// Number of objects that are exported.
        /// </summary>
        public readonly int TotalExportedObjectCount;
        /// <summary>
        /// The workspace ID.
        /// </summary>
        public readonly string WorkspaceId;

        [OutputConstructor]
        private GetWorkspaceExportRequestsExportRequestSummaryCollectionItemResult(
            bool areReferencesIncluded,

            string bucket,

            string createdBy,

            ImmutableDictionary<string, string> errorMessages,

            ImmutableArray<Outputs.GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItemResult> exportedItems,

            string fileName,

            ImmutableArray<string> filters,

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
            ExportedItems = exportedItems;
            FileName = fileName;
            Filters = filters;
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
