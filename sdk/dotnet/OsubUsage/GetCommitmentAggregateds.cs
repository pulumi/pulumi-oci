// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsubUsage
{
    public static class GetCommitmentAggregateds
    {
        /// <summary>
        /// This data source provides the list of Computed Usage Aggregateds in Oracle Cloud Infrastructure Osub Usage service.
        /// 
        /// This is a collection API which returns a list of aggregated computed usage details (there can be multiple Parent Products under a given SubID each of which is represented under Subscription Service Line # in SPM).
        /// </summary>
        public static Task<GetCommitmentAggregatedsResult> InvokeAsync(GetCommitmentAggregatedsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCommitmentAggregatedsResult>("oci:OsubUsage/getCommitmentAggregateds:getCommitmentAggregateds", args ?? new GetCommitmentAggregatedsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Computed Usage Aggregateds in Oracle Cloud Infrastructure Osub Usage service.
        /// 
        /// This is a collection API which returns a list of aggregated computed usage details (there can be multiple Parent Products under a given SubID each of which is represented under Subscription Service Line # in SPM).
        /// </summary>
        public static Output<GetCommitmentAggregatedsResult> Invoke(GetCommitmentAggregatedsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetCommitmentAggregatedsResult>("oci:OsubUsage/getCommitmentAggregateds:getCommitmentAggregateds", args ?? new GetCommitmentAggregatedsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetCommitmentAggregatedsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the root compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetCommitmentAggregatedsFilterArgs>? _filters;
        public List<Inputs.GetCommitmentAggregatedsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCommitmentAggregatedsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
        /// </summary>
        [Input("grouping")]
        public string? Grouping { get; set; }

        /// <summary>
        /// Product part number for subscribed service line, called parent product.
        /// </summary>
        [Input("parentProduct")]
        public string? ParentProduct { get; set; }

        /// <summary>
        /// Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
        /// </summary>
        [Input("subscriptionId", required: true)]
        public string SubscriptionId { get; set; } = null!;

        /// <summary>
        /// Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeFrom", required: true)]
        public string TimeFrom { get; set; } = null!;

        /// <summary>
        /// Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeTo", required: true)]
        public string TimeTo { get; set; } = null!;

        /// <summary>
        /// The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
        /// </summary>
        [Input("xOneOriginRegion")]
        public string? XOneOriginRegion { get; set; }

        public GetCommitmentAggregatedsArgs()
        {
        }
        public static new GetCommitmentAggregatedsArgs Empty => new GetCommitmentAggregatedsArgs();
    }

    public sealed class GetCommitmentAggregatedsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the root compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetCommitmentAggregatedsFilterInputArgs>? _filters;
        public InputList<Inputs.GetCommitmentAggregatedsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetCommitmentAggregatedsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Grouping criteria to use for aggregate the computed Usage, either hourly (`HOURLY`), daily (`DAILY`), monthly(`MONTHLY`) or none (`NONE`) to not follow a grouping criteria by date.
        /// </summary>
        [Input("grouping")]
        public Input<string>? Grouping { get; set; }

        /// <summary>
        /// Product part number for subscribed service line, called parent product.
        /// </summary>
        [Input("parentProduct")]
        public Input<string>? ParentProduct { get; set; }

        /// <summary>
        /// Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM.
        /// </summary>
        [Input("subscriptionId", required: true)]
        public Input<string> SubscriptionId { get; set; } = null!;

        /// <summary>
        /// Initial date to filter Computed Usage data in SPM. In the case of non aggregated data the time period between of fromDate and toDate , expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeFrom", required: true)]
        public Input<string> TimeFrom { get; set; } = null!;

        /// <summary>
        /// Final date to filter Computed Usage data in SPM, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeTo", required: true)]
        public Input<string> TimeTo { get; set; } = null!;

        /// <summary>
        /// The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
        /// </summary>
        [Input("xOneOriginRegion")]
        public Input<string>? XOneOriginRegion { get; set; }

        public GetCommitmentAggregatedsInvokeArgs()
        {
        }
        public static new GetCommitmentAggregatedsInvokeArgs Empty => new GetCommitmentAggregatedsInvokeArgs();
    }


    [OutputType]
    public sealed class GetCommitmentAggregatedsResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The list of computed_usage_aggregateds.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCommitmentAggregatedsComputedUsageAggregatedResult> ComputedUsageAggregateds;
        public readonly ImmutableArray<Outputs.GetCommitmentAggregatedsFilterResult> Filters;
        public readonly string? Grouping;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Product description
        /// </summary>
        public readonly string? ParentProduct;
        /// <summary>
        /// Subscription Id is an identifier associated to the service used for filter the Computed Usage in SPM
        /// </summary>
        public readonly string SubscriptionId;
        public readonly string TimeFrom;
        public readonly string TimeTo;
        public readonly string? XOneOriginRegion;

        [OutputConstructor]
        private GetCommitmentAggregatedsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetCommitmentAggregatedsComputedUsageAggregatedResult> computedUsageAggregateds,

            ImmutableArray<Outputs.GetCommitmentAggregatedsFilterResult> filters,

            string? grouping,

            string id,

            string? parentProduct,

            string subscriptionId,

            string timeFrom,

            string timeTo,

            string? xOneOriginRegion)
        {
            CompartmentId = compartmentId;
            ComputedUsageAggregateds = computedUsageAggregateds;
            Filters = filters;
            Grouping = grouping;
            Id = id;
            ParentProduct = parentProduct;
            SubscriptionId = subscriptionId;
            TimeFrom = timeFrom;
            TimeTo = timeTo;
            XOneOriginRegion = xOneOriginRegion;
        }
    }
}