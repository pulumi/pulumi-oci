// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Outputs
{

    [OutputType]
    public sealed class GetDrPlanExecutionsDrPlanExecutionCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemResult> Items;

        [OutputConstructor]
        private GetDrPlanExecutionsDrPlanExecutionCollectionResult(ImmutableArray<Outputs.GetDrPlanExecutionsDrPlanExecutionCollectionItemResult> items)
        {
            Items = items;
        }
    }
}