// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    public static class GetObjectVersions
    {
        /// <summary>
        /// This data source provides the list of Object Versions in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Lists the object versions in a bucket.
        /// 
        /// ListObjectVersions returns an ObjectVersionCollection containing at most 1000 object versions. To paginate through
        /// more object versions, use the returned `opc-next-page` value with the `page` request parameter.
        /// 
        /// To use this and other API operations, you must be authorized in an IAM policy. If you are not authorized,
        /// talk to an administrator. If you are an administrator who needs to write policies to give users access, see
        /// [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testObjectVersions = Oci.ObjectStorage.GetObjectVersions.Invoke(new()
        ///     {
        ///         Bucket = @var.Object_version_bucket,
        ///         Namespace = @var.Object_version_namespace,
        ///         Delimiter = @var.Object_version_delimiter,
        ///         End = @var.Object_version_end,
        ///         Fields = @var.Object_version_fields,
        ///         Prefix = @var.Object_version_prefix,
        ///         Start = @var.Object_version_start,
        ///         StartAfter = @var.Object_version_start_after,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetObjectVersionsResult> InvokeAsync(GetObjectVersionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetObjectVersionsResult>("oci:ObjectStorage/getObjectVersions:getObjectVersions", args ?? new GetObjectVersionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Object Versions in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Lists the object versions in a bucket.
        /// 
        /// ListObjectVersions returns an ObjectVersionCollection containing at most 1000 object versions. To paginate through
        /// more object versions, use the returned `opc-next-page` value with the `page` request parameter.
        /// 
        /// To use this and other API operations, you must be authorized in an IAM policy. If you are not authorized,
        /// talk to an administrator. If you are an administrator who needs to write policies to give users access, see
        /// [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testObjectVersions = Oci.ObjectStorage.GetObjectVersions.Invoke(new()
        ///     {
        ///         Bucket = @var.Object_version_bucket,
        ///         Namespace = @var.Object_version_namespace,
        ///         Delimiter = @var.Object_version_delimiter,
        ///         End = @var.Object_version_end,
        ///         Fields = @var.Object_version_fields,
        ///         Prefix = @var.Object_version_prefix,
        ///         Start = @var.Object_version_start,
        ///         StartAfter = @var.Object_version_start_after,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetObjectVersionsResult> Invoke(GetObjectVersionsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetObjectVersionsResult>("oci:ObjectStorage/getObjectVersions:getObjectVersions", args ?? new GetObjectVersionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetObjectVersionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public string Bucket { get; set; } = null!;

        /// <summary>
        /// When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only '/' is a supported delimiter character at this time.
        /// </summary>
        [Input("delimiter")]
        public string? Delimiter { get; set; }

        /// <summary>
        /// Object names returned by a list query must be strictly less than this parameter.
        /// </summary>
        [Input("end")]
        public string? End { get; set; }

        /// <summary>
        /// Object summary by default includes only the 'name' field. Use this parameter to also include 'size' (object size in bytes), 'etag', 'md5', 'timeCreated' (object creation date and time), 'timeModified' (object modification date and time), 'storageTier' and 'archivalState' fields. Specify the value of this parameter as a comma-separated, case-insensitive list of those field names.  For example 'name,etag,timeCreated,md5,timeModified,storageTier,archivalState'.
        /// </summary>
        [Input("fields")]
        public string? Fields { get; set; }

        [Input("filters")]
        private List<Inputs.GetObjectVersionsFilterArgs>? _filters;
        public List<Inputs.GetObjectVersionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetObjectVersionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// The string to use for matching against the start of object names in a list query.
        /// </summary>
        [Input("prefix")]
        public string? Prefix { get; set; }

        /// <summary>
        /// Object names returned by a list query must be greater or equal to this parameter.
        /// </summary>
        [Input("start")]
        public string? Start { get; set; }

        /// <summary>
        /// Object names returned by a list query must be greater than this parameter.
        /// </summary>
        [Input("startAfter")]
        public string? StartAfter { get; set; }

        public GetObjectVersionsArgs()
        {
        }
        public static new GetObjectVersionsArgs Empty => new GetObjectVersionsArgs();
    }

    public sealed class GetObjectVersionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only '/' is a supported delimiter character at this time.
        /// </summary>
        [Input("delimiter")]
        public Input<string>? Delimiter { get; set; }

        /// <summary>
        /// Object names returned by a list query must be strictly less than this parameter.
        /// </summary>
        [Input("end")]
        public Input<string>? End { get; set; }

        /// <summary>
        /// Object summary by default includes only the 'name' field. Use this parameter to also include 'size' (object size in bytes), 'etag', 'md5', 'timeCreated' (object creation date and time), 'timeModified' (object modification date and time), 'storageTier' and 'archivalState' fields. Specify the value of this parameter as a comma-separated, case-insensitive list of those field names.  For example 'name,etag,timeCreated,md5,timeModified,storageTier,archivalState'.
        /// </summary>
        [Input("fields")]
        public Input<string>? Fields { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetObjectVersionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetObjectVersionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetObjectVersionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// The string to use for matching against the start of object names in a list query.
        /// </summary>
        [Input("prefix")]
        public Input<string>? Prefix { get; set; }

        /// <summary>
        /// Object names returned by a list query must be greater or equal to this parameter.
        /// </summary>
        [Input("start")]
        public Input<string>? Start { get; set; }

        /// <summary>
        /// Object names returned by a list query must be greater than this parameter.
        /// </summary>
        [Input("startAfter")]
        public Input<string>? StartAfter { get; set; }

        public GetObjectVersionsInvokeArgs()
        {
        }
        public static new GetObjectVersionsInvokeArgs Empty => new GetObjectVersionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetObjectVersionsResult
    {
        public readonly string Bucket;
        public readonly string? Delimiter;
        public readonly string? End;
        public readonly string? Fields;
        public readonly ImmutableArray<Outputs.GetObjectVersionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// An array of object version summaries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetObjectVersionsItemResult> Items;
        public readonly string Namespace;
        public readonly string? Prefix;
        /// <summary>
        /// Prefixes that are common to the results returned by the request if the request specified a delimiter.
        /// </summary>
        public readonly ImmutableArray<string> Prefixes;
        public readonly string? Start;
        public readonly string? StartAfter;

        [OutputConstructor]
        private GetObjectVersionsResult(
            string bucket,

            string? delimiter,

            string? end,

            string? fields,

            ImmutableArray<Outputs.GetObjectVersionsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetObjectVersionsItemResult> items,

            string @namespace,

            string? prefix,

            ImmutableArray<string> prefixes,

            string? start,

            string? startAfter)
        {
            Bucket = bucket;
            Delimiter = delimiter;
            End = end;
            Fields = fields;
            Filters = filters;
            Id = id;
            Items = items;
            Namespace = @namespace;
            Prefix = prefix;
            Prefixes = prefixes;
            Start = start;
            StartAfter = startAfter;
        }
    }
}