// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class GetNamespaceScheduledTaskScheduleResult
    {
        public readonly ImmutableArray<Outputs.GetNamespaceScheduledTaskScheduleScheduleResult> Schedules;

        [OutputConstructor]
        private GetNamespaceScheduledTaskScheduleResult(ImmutableArray<Outputs.GetNamespaceScheduledTaskScheduleScheduleResult> schedules)
        {
            Schedules = schedules;
        }
    }
}
