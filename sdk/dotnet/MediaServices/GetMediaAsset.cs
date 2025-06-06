// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices
{
    public static class GetMediaAsset
    {
        /// <summary>
        /// This data source provides details about a specific Media Asset resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Gets a MediaAsset by identifier.
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
        ///     var testMediaAsset = Oci.MediaServices.GetMediaAsset.Invoke(new()
        ///     {
        ///         MediaAssetId = testMediaAssetOciMediaServicesMediaAsset.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMediaAssetResult> InvokeAsync(GetMediaAssetArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMediaAssetResult>("oci:MediaServices/getMediaAsset:getMediaAsset", args ?? new GetMediaAssetArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Media Asset resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Gets a MediaAsset by identifier.
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
        ///     var testMediaAsset = Oci.MediaServices.GetMediaAsset.Invoke(new()
        ///     {
        ///         MediaAssetId = testMediaAssetOciMediaServicesMediaAsset.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMediaAssetResult> Invoke(GetMediaAssetInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMediaAssetResult>("oci:MediaServices/getMediaAsset:getMediaAsset", args ?? new GetMediaAssetInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Media Asset resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Gets a MediaAsset by identifier.
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
        ///     var testMediaAsset = Oci.MediaServices.GetMediaAsset.Invoke(new()
        ///     {
        ///         MediaAssetId = testMediaAssetOciMediaServicesMediaAsset.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMediaAssetResult> Invoke(GetMediaAssetInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMediaAssetResult>("oci:MediaServices/getMediaAsset:getMediaAsset", args ?? new GetMediaAssetInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMediaAssetArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique MediaAsset identifier
        /// </summary>
        [Input("mediaAssetId", required: true)]
        public string MediaAssetId { get; set; } = null!;

        public GetMediaAssetArgs()
        {
        }
        public static new GetMediaAssetArgs Empty => new GetMediaAssetArgs();
    }

    public sealed class GetMediaAssetInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique MediaAsset identifier
        /// </summary>
        [Input("mediaAssetId", required: true)]
        public Input<string> MediaAssetId { get; set; } = null!;

        public GetMediaAssetInvokeArgs()
        {
        }
        public static new GetMediaAssetInvokeArgs Empty => new GetMediaAssetInvokeArgs();
    }


    [OutputType]
    public sealed class GetMediaAssetResult
    {
        /// <summary>
        /// The name of the object storage bucket where this represented asset is located.
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// The compartment ID of the lock.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string Id;
        public readonly bool IsLockOverride;
        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMediaAssetLockResult> Locks;
        /// <summary>
        /// The ID of the senior most asset from which this asset is derived.
        /// </summary>
        public readonly string MasterMediaAssetId;
        public readonly string MediaAssetId;
        /// <summary>
        /// List of tags for the MediaAsset.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMediaAssetMediaAssetTagResult> MediaAssetTags;
        /// <summary>
        /// The ID of the MediaWorkflowJob used to produce this asset.
        /// </summary>
        public readonly string MediaWorkflowJobId;
        /// <summary>
        /// JSON string containing the technial metadata for the media asset.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMediaAssetMetadataResult> Metadatas;
        /// <summary>
        /// The object storage namespace where this asset is located.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The object storage object name that identifies this asset.
        /// </summary>
        public readonly string Object;
        /// <summary>
        /// eTag of the underlying object storage object.
        /// </summary>
        public readonly string ObjectEtag;
        /// <summary>
        /// The ID of the parent asset from which this asset is derived.
        /// </summary>
        public readonly string ParentMediaAssetId;
        /// <summary>
        /// The end index of video segment files.
        /// </summary>
        public readonly string SegmentRangeEndIndex;
        /// <summary>
        /// The start index for video segment files.
        /// </summary>
        public readonly string SegmentRangeStartIndex;
        /// <summary>
        /// The ID of the MediaWorkflow used to produce this asset.
        /// </summary>
        public readonly string SourceMediaWorkflowId;
        /// <summary>
        /// The version of the MediaWorkflow used to produce this asset.
        /// </summary>
        public readonly string SourceMediaWorkflowVersion;
        /// <summary>
        /// The current state of the MediaAsset.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The type of the media asset.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetMediaAssetResult(
            string bucket,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isLockOverride,

            ImmutableArray<Outputs.GetMediaAssetLockResult> locks,

            string masterMediaAssetId,

            string mediaAssetId,

            ImmutableArray<Outputs.GetMediaAssetMediaAssetTagResult> mediaAssetTags,

            string mediaWorkflowJobId,

            ImmutableArray<Outputs.GetMediaAssetMetadataResult> metadatas,

            string @namespace,

            string @object,

            string objectEtag,

            string parentMediaAssetId,

            string segmentRangeEndIndex,

            string segmentRangeStartIndex,

            string sourceMediaWorkflowId,

            string sourceMediaWorkflowVersion,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string type)
        {
            Bucket = bucket;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsLockOverride = isLockOverride;
            Locks = locks;
            MasterMediaAssetId = masterMediaAssetId;
            MediaAssetId = mediaAssetId;
            MediaAssetTags = mediaAssetTags;
            MediaWorkflowJobId = mediaWorkflowJobId;
            Metadatas = metadatas;
            Namespace = @namespace;
            Object = @object;
            ObjectEtag = objectEtag;
            ParentMediaAssetId = parentMediaAssetId;
            SegmentRangeEndIndex = segmentRangeEndIndex;
            SegmentRangeStartIndex = segmentRangeStartIndex;
            SourceMediaWorkflowId = sourceMediaWorkflowId;
            SourceMediaWorkflowVersion = sourceMediaWorkflowVersion;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
        }
    }
}
