// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetReportDefinitionsReportDefinitionCollectionItemSummaryResult
    {
        /// <summary>
        /// Name of the key or count of object.
        /// </summary>
        public readonly string CountOf;
        /// <summary>
        /// Specifies the order in which the summary must be displayed.
        /// </summary>
        public readonly int DisplayOrder;
        /// <summary>
        /// A comma-delimited string that specifies the names of the fields by which the records must be aggregated to get the summary.
        /// </summary>
        public readonly string GroupByFieldName;
        /// <summary>
        /// Indicates if the summary is hidden. Values can either be 'true' or 'false'.
        /// </summary>
        public readonly bool IsHidden;
        /// <summary>
        /// Name of the report summary.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Additional scim filters used to get the specific summary.
        /// </summary>
        public readonly string ScimFilter;

        [OutputConstructor]
        private GetReportDefinitionsReportDefinitionCollectionItemSummaryResult(
            string countOf,

            int displayOrder,

            string groupByFieldName,

            bool isHidden,

            string name,

            string scimFilter)
        {
            CountOf = countOf;
            DisplayOrder = displayOrder;
            GroupByFieldName = groupByFieldName;
            IsHidden = isHidden;
            Name = name;
            ScimFilter = scimFilter;
        }
    }
}