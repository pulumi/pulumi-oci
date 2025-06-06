// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetNamespaceStorageOverlappingRecalls
    {
        /// <summary>
        /// This data source provides the list of Namespace Storage Overlapping Recalls in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// This API gets the list of overlapping recalls made in the given timeframe
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
        ///     var testNamespaceStorageOverlappingRecalls = Oci.LogAnalytics.GetNamespaceStorageOverlappingRecalls.Invoke(new()
        ///     {
        ///         Namespace = namespaceStorageOverlappingRecallNamespace,
        ///         TimeDataEnded = namespaceStorageOverlappingRecallTimeDataEnded,
        ///         TimeDataStarted = namespaceStorageOverlappingRecallTimeDataStarted,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNamespaceStorageOverlappingRecallsResult> InvokeAsync(GetNamespaceStorageOverlappingRecallsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNamespaceStorageOverlappingRecallsResult>("oci:LogAnalytics/getNamespaceStorageOverlappingRecalls:getNamespaceStorageOverlappingRecalls", args ?? new GetNamespaceStorageOverlappingRecallsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Storage Overlapping Recalls in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// This API gets the list of overlapping recalls made in the given timeframe
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
        ///     var testNamespaceStorageOverlappingRecalls = Oci.LogAnalytics.GetNamespaceStorageOverlappingRecalls.Invoke(new()
        ///     {
        ///         Namespace = namespaceStorageOverlappingRecallNamespace,
        ///         TimeDataEnded = namespaceStorageOverlappingRecallTimeDataEnded,
        ///         TimeDataStarted = namespaceStorageOverlappingRecallTimeDataStarted,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespaceStorageOverlappingRecallsResult> Invoke(GetNamespaceStorageOverlappingRecallsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceStorageOverlappingRecallsResult>("oci:LogAnalytics/getNamespaceStorageOverlappingRecalls:getNamespaceStorageOverlappingRecalls", args ?? new GetNamespaceStorageOverlappingRecallsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Storage Overlapping Recalls in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// This API gets the list of overlapping recalls made in the given timeframe
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
        ///     var testNamespaceStorageOverlappingRecalls = Oci.LogAnalytics.GetNamespaceStorageOverlappingRecalls.Invoke(new()
        ///     {
        ///         Namespace = namespaceStorageOverlappingRecallNamespace,
        ///         TimeDataEnded = namespaceStorageOverlappingRecallTimeDataEnded,
        ///         TimeDataStarted = namespaceStorageOverlappingRecallTimeDataStarted,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespaceStorageOverlappingRecallsResult> Invoke(GetNamespaceStorageOverlappingRecallsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceStorageOverlappingRecallsResult>("oci:LogAnalytics/getNamespaceStorageOverlappingRecalls:getNamespaceStorageOverlappingRecalls", args ?? new GetNamespaceStorageOverlappingRecallsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNamespaceStorageOverlappingRecallsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetNamespaceStorageOverlappingRecallsFilterArgs>? _filters;
        public List<Inputs.GetNamespaceStorageOverlappingRecallsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNamespaceStorageOverlappingRecallsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// This is the end of the time range for recalled data
        /// </summary>
        [Input("timeDataEnded")]
        public string? TimeDataEnded { get; set; }

        /// <summary>
        /// This is the start of the time range for recalled data
        /// </summary>
        [Input("timeDataStarted")]
        public string? TimeDataStarted { get; set; }

        public GetNamespaceStorageOverlappingRecallsArgs()
        {
        }
        public static new GetNamespaceStorageOverlappingRecallsArgs Empty => new GetNamespaceStorageOverlappingRecallsArgs();
    }

    public sealed class GetNamespaceStorageOverlappingRecallsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetNamespaceStorageOverlappingRecallsFilterInputArgs>? _filters;
        public InputList<Inputs.GetNamespaceStorageOverlappingRecallsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNamespaceStorageOverlappingRecallsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// This is the end of the time range for recalled data
        /// </summary>
        [Input("timeDataEnded")]
        public Input<string>? TimeDataEnded { get; set; }

        /// <summary>
        /// This is the start of the time range for recalled data
        /// </summary>
        [Input("timeDataStarted")]
        public Input<string>? TimeDataStarted { get; set; }

        public GetNamespaceStorageOverlappingRecallsInvokeArgs()
        {
        }
        public static new GetNamespaceStorageOverlappingRecallsInvokeArgs Empty => new GetNamespaceStorageOverlappingRecallsInvokeArgs();
    }


    [OutputType]
    public sealed class GetNamespaceStorageOverlappingRecallsResult
    {
        public readonly ImmutableArray<Outputs.GetNamespaceStorageOverlappingRecallsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string Namespace;
        /// <summary>
        /// The list of overlapping_recall_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespaceStorageOverlappingRecallsOverlappingRecallCollectionResult> OverlappingRecallCollections;
        /// <summary>
        /// This is the end of the time range of the archival data
        /// </summary>
        public readonly string? TimeDataEnded;
        /// <summary>
        /// This is the start of the time range of the archival data
        /// </summary>
        public readonly string? TimeDataStarted;

        [OutputConstructor]
        private GetNamespaceStorageOverlappingRecallsResult(
            ImmutableArray<Outputs.GetNamespaceStorageOverlappingRecallsFilterResult> filters,

            string id,

            string @namespace,

            ImmutableArray<Outputs.GetNamespaceStorageOverlappingRecallsOverlappingRecallCollectionResult> overlappingRecallCollections,

            string? timeDataEnded,

            string? timeDataStarted)
        {
            Filters = filters;
            Id = id;
            Namespace = @namespace;
            OverlappingRecallCollections = overlappingRecallCollections;
            TimeDataEnded = timeDataEnded;
            TimeDataStarted = timeDataStarted;
        }
    }
}
