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
    public sealed class GetAuditEventsAuditEventCollectionResult
    {
        /// <summary>
        /// Array of audit event summary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAuditEventsAuditEventCollectionItemResult> Items;

        [OutputConstructor]
        private GetAuditEventsAuditEventCollectionResult(ImmutableArray<Outputs.GetAuditEventsAuditEventCollectionItemResult> items)
        {
            Items = items;
        }
    }
}