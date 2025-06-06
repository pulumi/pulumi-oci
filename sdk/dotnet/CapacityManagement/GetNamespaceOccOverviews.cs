// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement
{
    public static class GetNamespaceOccOverviews
    {
        /// <summary>
        /// This data source provides the list of Namespace Occ Overviews in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Lists an overview of all resources in that namespace in a given time interval.
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
        ///     var testNamespaceOccOverviews = Oci.CapacityManagement.GetNamespaceOccOverviews.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Namespace = namespaceOccOverviewNamespace,
        ///         From = namespaceOccOverviewFrom,
        ///         To = namespaceOccOverviewTo,
        ///         WorkloadType = namespaceOccOverviewWorkloadType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNamespaceOccOverviewsResult> InvokeAsync(GetNamespaceOccOverviewsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNamespaceOccOverviewsResult>("oci:CapacityManagement/getNamespaceOccOverviews:getNamespaceOccOverviews", args ?? new GetNamespaceOccOverviewsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Occ Overviews in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Lists an overview of all resources in that namespace in a given time interval.
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
        ///     var testNamespaceOccOverviews = Oci.CapacityManagement.GetNamespaceOccOverviews.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Namespace = namespaceOccOverviewNamespace,
        ///         From = namespaceOccOverviewFrom,
        ///         To = namespaceOccOverviewTo,
        ///         WorkloadType = namespaceOccOverviewWorkloadType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespaceOccOverviewsResult> Invoke(GetNamespaceOccOverviewsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceOccOverviewsResult>("oci:CapacityManagement/getNamespaceOccOverviews:getNamespaceOccOverviews", args ?? new GetNamespaceOccOverviewsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Occ Overviews in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Lists an overview of all resources in that namespace in a given time interval.
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
        ///     var testNamespaceOccOverviews = Oci.CapacityManagement.GetNamespaceOccOverviews.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Namespace = namespaceOccOverviewNamespace,
        ///         From = namespaceOccOverviewFrom,
        ///         To = namespaceOccOverviewTo,
        ///         WorkloadType = namespaceOccOverviewWorkloadType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespaceOccOverviewsResult> Invoke(GetNamespaceOccOverviewsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceOccOverviewsResult>("oci:CapacityManagement/getNamespaceOccOverviews:getNamespaceOccOverviews", args ?? new GetNamespaceOccOverviewsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNamespaceOccOverviewsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetNamespaceOccOverviewsFilterArgs>? _filters;
        public List<Inputs.GetNamespaceOccOverviewsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNamespaceOccOverviewsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
        /// </summary>
        [Input("from")]
        public string? From { get; set; }

        /// <summary>
        /// The namespace by which we would filter the list.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
        /// </summary>
        [Input("to")]
        public string? To { get; set; }

        /// <summary>
        /// Workload type using the resources in an availability catalog can be filtered.
        /// </summary>
        [Input("workloadType")]
        public string? WorkloadType { get; set; }

        public GetNamespaceOccOverviewsArgs()
        {
        }
        public static new GetNamespaceOccOverviewsArgs Empty => new GetNamespaceOccOverviewsArgs();
    }

    public sealed class GetNamespaceOccOverviewsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetNamespaceOccOverviewsFilterInputArgs>? _filters;
        public InputList<Inputs.GetNamespaceOccOverviewsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNamespaceOccOverviewsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The month corresponding to this date would be considered as the starting point of the time period against which we would like to perform an aggregation.
        /// </summary>
        [Input("from")]
        public Input<string>? From { get; set; }

        /// <summary>
        /// The namespace by which we would filter the list.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// The month corresponding to this date would be considered as the ending point of the time period against which we would like to perform an aggregation.
        /// </summary>
        [Input("to")]
        public Input<string>? To { get; set; }

        /// <summary>
        /// Workload type using the resources in an availability catalog can be filtered.
        /// </summary>
        [Input("workloadType")]
        public Input<string>? WorkloadType { get; set; }

        public GetNamespaceOccOverviewsInvokeArgs()
        {
        }
        public static new GetNamespaceOccOverviewsInvokeArgs Empty => new GetNamespaceOccOverviewsInvokeArgs();
    }


    [OutputType]
    public sealed class GetNamespaceOccOverviewsResult
    {
        /// <summary>
        /// The OCID of the compartment from which the api call is made. This will be used for authorizing the request.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetNamespaceOccOverviewsFilterResult> Filters;
        public readonly string? From;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string Namespace;
        /// <summary>
        /// The list of occ_overview_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespaceOccOverviewsOccOverviewCollectionResult> OccOverviewCollections;
        public readonly string? To;
        public readonly string? WorkloadType;

        [OutputConstructor]
        private GetNamespaceOccOverviewsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetNamespaceOccOverviewsFilterResult> filters,

            string? from,

            string id,

            string @namespace,

            ImmutableArray<Outputs.GetNamespaceOccOverviewsOccOverviewCollectionResult> occOverviewCollections,

            string? to,

            string? workloadType)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            From = from;
            Id = id;
            Namespace = @namespace;
            OccOverviewCollections = occOverviewCollections;
            To = to;
            WorkloadType = workloadType;
        }
    }
}
