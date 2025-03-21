// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Inputs
{

    public sealed class UsageCarbonEmissionsQueryQueryDefinitionReportQueryArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The compartment depth level.
        /// </summary>
        [Input("compartmentDepth")]
        public Input<int>? CompartmentDepth { get; set; }

        /// <summary>
        /// (Updatable) The UI date range, for example, LAST_THREE_MONTHS. It will override timeUsageStarted and timeUsageEnded properties.
        /// </summary>
        [Input("dateRangeName")]
        public Input<string>? DateRangeName { get; set; }

        [Input("groupBies")]
        private InputList<string>? _groupBies;

        /// <summary>
        /// (Updatable) Specifies what to aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "tenantId", "tenantName"]`
        /// </summary>
        public InputList<string> GroupBies
        {
            get => _groupBies ?? (_groupBies = new InputList<string>());
            set => _groupBies = value;
        }

        [Input("groupByTags")]
        private InputList<Inputs.UsageCarbonEmissionsQueryQueryDefinitionReportQueryGroupByTagArgs>? _groupByTags;

        /// <summary>
        /// (Updatable) GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
        /// </summary>
        public InputList<Inputs.UsageCarbonEmissionsQueryQueryDefinitionReportQueryGroupByTagArgs> GroupByTags
        {
            get => _groupByTags ?? (_groupByTags = new InputList<Inputs.UsageCarbonEmissionsQueryQueryDefinitionReportQueryGroupByTagArgs>());
            set => _groupByTags = value;
        }

        /// <summary>
        /// (Updatable) Specifies whether aggregated by time. If isAggregateByTime is true, all usage or cost over the query time period will be added up.
        /// </summary>
        [Input("isAggregateByTime")]
        public Input<bool>? IsAggregateByTime { get; set; }

        /// <summary>
        /// (Updatable) Tenant ID.
        /// </summary>
        [Input("tenantId", required: true)]
        public Input<string> TenantId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The usage end time.
        /// </summary>
        [Input("timeUsageEnded")]
        public Input<string>? TimeUsageEnded { get; set; }

        /// <summary>
        /// (Updatable) The usage start time.
        /// </summary>
        [Input("timeUsageStarted")]
        public Input<string>? TimeUsageStarted { get; set; }

        /// <summary>
        /// (Updatable) The filter object for query usage.
        /// </summary>
        [Input("usageCarbonEmissionsQueryFilter")]
        public Input<string>? UsageCarbonEmissionsQueryFilter { get; set; }

        public UsageCarbonEmissionsQueryQueryDefinitionReportQueryArgs()
        {
        }
        public static new UsageCarbonEmissionsQueryQueryDefinitionReportQueryArgs Empty => new UsageCarbonEmissionsQueryQueryDefinitionReportQueryArgs();
    }
}
