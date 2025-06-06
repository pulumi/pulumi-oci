// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityAssessmentFindingsChangeAuditLogsFindingsChangeAuditLogCollectionResult
    {
        /// <summary>
        /// An array of finding risk change audit log summary objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentFindingsChangeAuditLogsFindingsChangeAuditLogCollectionItemResult> Items;

        [OutputConstructor]
        private GetSecurityAssessmentFindingsChangeAuditLogsFindingsChangeAuditLogCollectionResult(ImmutableArray<Outputs.GetSecurityAssessmentFindingsChangeAuditLogsFindingsChangeAuditLogCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
