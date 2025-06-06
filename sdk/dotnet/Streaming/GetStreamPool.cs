// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Streaming
{
    public static class GetStreamPool
    {
        /// <summary>
        /// This data source provides details about a specific Stream Pool resource in Oracle Cloud Infrastructure Streaming service.
        /// 
        /// Gets detailed information about the stream pool, such as Kafka settings.
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
        ///     var testStreamPool = Oci.Streaming.GetStreamPool.Invoke(new()
        ///     {
        ///         StreamPoolId = testStreamPoolOciStreamingStreamPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetStreamPoolResult> InvokeAsync(GetStreamPoolArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetStreamPoolResult>("oci:Streaming/getStreamPool:getStreamPool", args ?? new GetStreamPoolArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Stream Pool resource in Oracle Cloud Infrastructure Streaming service.
        /// 
        /// Gets detailed information about the stream pool, such as Kafka settings.
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
        ///     var testStreamPool = Oci.Streaming.GetStreamPool.Invoke(new()
        ///     {
        ///         StreamPoolId = testStreamPoolOciStreamingStreamPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetStreamPoolResult> Invoke(GetStreamPoolInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetStreamPoolResult>("oci:Streaming/getStreamPool:getStreamPool", args ?? new GetStreamPoolInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Stream Pool resource in Oracle Cloud Infrastructure Streaming service.
        /// 
        /// Gets detailed information about the stream pool, such as Kafka settings.
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
        ///     var testStreamPool = Oci.Streaming.GetStreamPool.Invoke(new()
        ///     {
        ///         StreamPoolId = testStreamPoolOciStreamingStreamPool.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetStreamPoolResult> Invoke(GetStreamPoolInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetStreamPoolResult>("oci:Streaming/getStreamPool:getStreamPool", args ?? new GetStreamPoolInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetStreamPoolArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the stream pool.
        /// </summary>
        [Input("streamPoolId", required: true)]
        public string StreamPoolId { get; set; } = null!;

        public GetStreamPoolArgs()
        {
        }
        public static new GetStreamPoolArgs Empty => new GetStreamPoolArgs();
    }

    public sealed class GetStreamPoolInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the stream pool.
        /// </summary>
        [Input("streamPoolId", required: true)]
        public Input<string> StreamPoolId { get; set; } = null!;

        public GetStreamPoolInvokeArgs()
        {
        }
        public static new GetStreamPoolInvokeArgs Empty => new GetStreamPoolInvokeArgs();
    }


    [OutputType]
    public sealed class GetStreamPoolResult
    {
        /// <summary>
        /// Compartment OCID that the pool belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Custom Encryption Key which will be used for encryption by all the streams in the pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetStreamPoolCustomEncryptionKeyResult> CustomEncryptionKeys;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations": {"CostCenter": "42"}}'
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
        /// </summary>
        public readonly string EndpointFqdn;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the stream pool.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
        /// </summary>
        public readonly bool IsPrivate;
        /// <summary>
        /// Settings for the Kafka compatibility layer.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetStreamPoolKafkaSettingResult> KafkaSettings;
        /// <summary>
        /// Any additional details about the current state of the stream.
        /// </summary>
        public readonly string LifecycleStateDetails;
        /// <summary>
        /// The name of the stream pool.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Optional settings if the stream pool is private.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetStreamPoolPrivateEndpointSettingResult> PrivateEndpointSettings;
        /// <summary>
        /// The current state of the stream pool.
        /// </summary>
        public readonly string State;
        public readonly string StreamPoolId;
        /// <summary>
        /// The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetStreamPoolResult(
            string compartmentId,

            ImmutableArray<Outputs.GetStreamPoolCustomEncryptionKeyResult> customEncryptionKeys,

            ImmutableDictionary<string, string> definedTags,

            string endpointFqdn,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isPrivate,

            ImmutableArray<Outputs.GetStreamPoolKafkaSettingResult> kafkaSettings,

            string lifecycleStateDetails,

            string name,

            ImmutableArray<Outputs.GetStreamPoolPrivateEndpointSettingResult> privateEndpointSettings,

            string state,

            string streamPoolId,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            CustomEncryptionKeys = customEncryptionKeys;
            DefinedTags = definedTags;
            EndpointFqdn = endpointFqdn;
            FreeformTags = freeformTags;
            Id = id;
            IsPrivate = isPrivate;
            KafkaSettings = kafkaSettings;
            LifecycleStateDetails = lifecycleStateDetails;
            Name = name;
            PrivateEndpointSettings = privateEndpointSettings;
            State = state;
            StreamPoolId = streamPoolId;
            TimeCreated = timeCreated;
        }
    }
}
