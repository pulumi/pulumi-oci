// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Autoscaling.Outputs
{

    [OutputType]
    public sealed class AutoScalingConfigurationPolicyExecutionSchedule
    {
        /// <summary>
        /// A cron expression that represents the time at which to execute the autoscaling policy.
        /// 
        /// Cron expressions have this format: `&lt;second&gt; &lt;minute&gt; &lt;hour&gt; &lt;day of month&gt; &lt;month&gt; &lt;day of week&gt; &lt;year&gt;`
        /// 
        /// You can use special characters that are supported with the Quartz cron implementation.
        /// 
        /// You must specify `0` as the value for seconds.
        /// 
        /// Example: `0 15 10 ? * *`
        /// </summary>
        public readonly string Expression;
        /// <summary>
        /// The time zone for the execution schedule.
        /// </summary>
        public readonly string Timezone;
        /// <summary>
        /// The type of execution schedule.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private AutoScalingConfigurationPolicyExecutionSchedule(
            string expression,

            string timezone,

            string type)
        {
            Expression = expression;
            Timezone = timezone;
            Type = type;
        }
    }
}
