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
    public sealed class GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollectionItemResult> Items;

        [OutputConstructor]
        private GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollectionResult(ImmutableArray<Outputs.GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
