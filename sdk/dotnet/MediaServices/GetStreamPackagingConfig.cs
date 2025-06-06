// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices
{
    public static class GetStreamPackagingConfig
    {
        /// <summary>
        /// This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Gets a Stream Packaging Configuration by identifier.
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
        ///     var testStreamPackagingConfig = Oci.MediaServices.GetStreamPackagingConfig.Invoke(new()
        ///     {
        ///         StreamPackagingConfigId = testStreamPackagingConfigOciMediaServicesStreamPackagingConfig.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetStreamPackagingConfigResult> InvokeAsync(GetStreamPackagingConfigArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetStreamPackagingConfigResult>("oci:MediaServices/getStreamPackagingConfig:getStreamPackagingConfig", args ?? new GetStreamPackagingConfigArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Gets a Stream Packaging Configuration by identifier.
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
        ///     var testStreamPackagingConfig = Oci.MediaServices.GetStreamPackagingConfig.Invoke(new()
        ///     {
        ///         StreamPackagingConfigId = testStreamPackagingConfigOciMediaServicesStreamPackagingConfig.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetStreamPackagingConfigResult> Invoke(GetStreamPackagingConfigInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetStreamPackagingConfigResult>("oci:MediaServices/getStreamPackagingConfig:getStreamPackagingConfig", args ?? new GetStreamPackagingConfigInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Gets a Stream Packaging Configuration by identifier.
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
        ///     var testStreamPackagingConfig = Oci.MediaServices.GetStreamPackagingConfig.Invoke(new()
        ///     {
        ///         StreamPackagingConfigId = testStreamPackagingConfigOciMediaServicesStreamPackagingConfig.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetStreamPackagingConfigResult> Invoke(GetStreamPackagingConfigInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetStreamPackagingConfigResult>("oci:MediaServices/getStreamPackagingConfig:getStreamPackagingConfig", args ?? new GetStreamPackagingConfigInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetStreamPackagingConfigArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Stream Packaging Configuration path identifier.
        /// </summary>
        [Input("streamPackagingConfigId", required: true)]
        public string StreamPackagingConfigId { get; set; } = null!;

        public GetStreamPackagingConfigArgs()
        {
        }
        public static new GetStreamPackagingConfigArgs Empty => new GetStreamPackagingConfigArgs();
    }

    public sealed class GetStreamPackagingConfigInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Stream Packaging Configuration path identifier.
        /// </summary>
        [Input("streamPackagingConfigId", required: true)]
        public Input<string> StreamPackagingConfigId { get; set; } = null!;

        public GetStreamPackagingConfigInvokeArgs()
        {
        }
        public static new GetStreamPackagingConfigInvokeArgs Empty => new GetStreamPackagingConfigInvokeArgs();
    }


    [OutputType]
    public sealed class GetStreamPackagingConfigResult
    {
        /// <summary>
        /// The compartment ID of the lock.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The name of the stream packaging configuration. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        /// </summary>
        public readonly string DistributionChannelId;
        /// <summary>
        /// The encryption used by the stream packaging configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetStreamPackagingConfigEncryptionResult> Encryptions;
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
        public readonly ImmutableArray<Outputs.GetStreamPackagingConfigLockResult> Locks;
        /// <summary>
        /// The duration in seconds for each fragment.
        /// </summary>
        public readonly int SegmentTimeInSeconds;
        /// <summary>
        /// The current state of the Packaging Configuration.
        /// </summary>
        public readonly string State;
        public readonly string StreamPackagingConfigId;
        /// <summary>
        /// The output format for the package.
        /// </summary>
        public readonly string StreamPackagingFormat;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetStreamPackagingConfigResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string distributionChannelId,

            ImmutableArray<Outputs.GetStreamPackagingConfigEncryptionResult> encryptions,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isLockOverride,

            ImmutableArray<Outputs.GetStreamPackagingConfigLockResult> locks,

            int segmentTimeInSeconds,

            string state,

            string streamPackagingConfigId,

            string streamPackagingFormat,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DistributionChannelId = distributionChannelId;
            Encryptions = encryptions;
            FreeformTags = freeformTags;
            Id = id;
            IsLockOverride = isLockOverride;
            Locks = locks;
            SegmentTimeInSeconds = segmentTimeInSeconds;
            State = state;
            StreamPackagingConfigId = streamPackagingConfigId;
            StreamPackagingFormat = streamPackagingFormat;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
