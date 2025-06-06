// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    public static class GetObjectHead
    {
        /// <summary>
        /// This data source provides details about metadata of a specific Object resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Gets the metadata of an object.
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
        ///     var testObjectHead = Oci.ObjectStorage.GetObjectHead.Invoke(new()
        ///     {
        ///         Bucket = objectBucket,
        ///         Namespace = objectNamespace,
        ///         Object = objectObject,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetObjectHeadResult> InvokeAsync(GetObjectHeadArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetObjectHeadResult>("oci:ObjectStorage/getObjectHead:getObjectHead", args ?? new GetObjectHeadArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about metadata of a specific Object resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Gets the metadata of an object.
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
        ///     var testObjectHead = Oci.ObjectStorage.GetObjectHead.Invoke(new()
        ///     {
        ///         Bucket = objectBucket,
        ///         Namespace = objectNamespace,
        ///         Object = objectObject,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetObjectHeadResult> Invoke(GetObjectHeadInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetObjectHeadResult>("oci:ObjectStorage/getObjectHead:getObjectHead", args ?? new GetObjectHeadInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about metadata of a specific Object resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Gets the metadata of an object.
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
        ///     var testObjectHead = Oci.ObjectStorage.GetObjectHead.Invoke(new()
        ///     {
        ///         Bucket = objectBucket,
        ///         Namespace = objectNamespace,
        ///         Object = objectObject,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetObjectHeadResult> Invoke(GetObjectHeadInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetObjectHeadResult>("oci:ObjectStorage/getObjectHead:getObjectHead", args ?? new GetObjectHeadInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetObjectHeadArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public string Bucket { get; set; } = null!;

        /// <summary>
        /// The top-level namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// The name of the object. Avoid entering confidential information. Example: `test/object1.log`
        /// </summary>
        [Input("object", required: true)]
        public string Object { get; set; } = null!;

        public GetObjectHeadArgs()
        {
        }
        public static new GetObjectHeadArgs Empty => new GetObjectHeadArgs();
    }

    public sealed class GetObjectHeadInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// The top-level namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// The name of the object. Avoid entering confidential information. Example: `test/object1.log`
        /// </summary>
        [Input("object", required: true)]
        public Input<string> Object { get; set; } = null!;

        public GetObjectHeadInvokeArgs()
        {
        }
        public static new GetObjectHeadInvokeArgs Empty => new GetObjectHeadInvokeArgs();
    }


    [OutputType]
    public sealed class GetObjectHeadResult
    {
        public readonly string ArchivalState;
        public readonly string Bucket;
        /// <summary>
        /// The content-length of the object
        /// </summary>
        public readonly int ContentLength;
        /// <summary>
        /// The content-type of the object
        /// </summary>
        public readonly string ContentType;
        /// <summary>
        /// The etag of the object
        /// </summary>
        public readonly string Etag;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The metadata of the object
        /// </summary>
        public readonly ImmutableDictionary<string, string> Metadata;
        public readonly string Namespace;
        public readonly string Object;
        /// <summary>
        /// The storage tier that the object is stored in.
        /// * `archival-state` - Archival state of an object. This field is set only for objects in Archive tier.
        /// </summary>
        public readonly string StorageTier;

        [OutputConstructor]
        private GetObjectHeadResult(
            string archivalState,

            string bucket,

            int contentLength,

            string contentType,

            string etag,

            string id,

            ImmutableDictionary<string, string> metadata,

            string @namespace,

            string @object,

            string storageTier)
        {
            ArchivalState = archivalState;
            Bucket = bucket;
            ContentLength = contentLength;
            ContentType = contentType;
            Etag = etag;
            Id = id;
            Metadata = metadata;
            Namespace = @namespace;
            Object = @object;
            StorageTier = storageTier;
        }
    }
}
