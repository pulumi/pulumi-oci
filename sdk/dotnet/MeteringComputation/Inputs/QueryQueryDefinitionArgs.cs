// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Inputs
{

    public sealed class QueryQueryDefinitionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The common fields for Cost Analysis UI rendering.
        /// </summary>
        [Input("costAnalysisUi", required: true)]
        public Input<Inputs.QueryQueryDefinitionCostAnalysisUiArgs> CostAnalysisUi { get; set; } = null!;

        /// <summary>
        /// (Updatable) The query display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// (Updatable) The request of the generated Cost Analysis report.
        /// </summary>
        [Input("reportQuery", required: true)]
        public Input<Inputs.QueryQueryDefinitionReportQueryArgs> ReportQuery { get; set; } = null!;

        /// <summary>
        /// (Updatable) The saved query version.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("version", required: true)]
        public Input<double> Version { get; set; } = null!;

        public QueryQueryDefinitionArgs()
        {
        }
        public static new QueryQueryDefinitionArgs Empty => new QueryQueryDefinitionArgs();
    }
}
