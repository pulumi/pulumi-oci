// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrPlanExecutionExecutionOptionsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A flag indicating whether prechecks should be executed before the plan execution.  Example: `false`
        /// </summary>
        [Input("arePrechecksEnabled")]
        public Input<bool>? ArePrechecksEnabled { get; set; }

        /// <summary>
        /// A flag indicating whether warnings should be ignored during the switchover precheck.  Example: `true`
        /// </summary>
        [Input("areWarningsIgnored")]
        public Input<bool>? AreWarningsIgnored { get; set; }

        /// <summary>
        /// The type of the plan execution.
        /// </summary>
        [Input("planExecutionType", required: true)]
        public Input<string> PlanExecutionType { get; set; } = null!;

        public DrPlanExecutionExecutionOptionsGetArgs()
        {
        }
        public static new DrPlanExecutionExecutionOptionsGetArgs Empty => new DrPlanExecutionExecutionOptionsGetArgs();
    }
}
