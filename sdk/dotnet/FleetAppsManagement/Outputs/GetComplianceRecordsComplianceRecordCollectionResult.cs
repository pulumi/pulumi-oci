// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetComplianceRecordsComplianceRecordCollectionResult
    {
        /// <summary>
        /// List of compliancePolicys.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComplianceRecordsComplianceRecordCollectionItemResult> Items;

        [OutputConstructor]
        private GetComplianceRecordsComplianceRecordCollectionResult(ImmutableArray<Outputs.GetComplianceRecordsComplianceRecordCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
