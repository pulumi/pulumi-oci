// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmConfig.Inputs
{

    public sealed class ConfigRuleGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A user-friendly name that provides a short description this rule.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) The string that defines the Span Filter expression.
        /// </summary>
        [Input("filterText")]
        public Input<string>? FilterText { get; set; }

        /// <summary>
        /// (Updatable) If true, the rule will compute the actual Apdex score for spans that have been marked as errors. If false, the rule will always set the Apdex for error spans to frustrating, regardless of the configured thresholds. Default is false.
        /// </summary>
        [Input("isApplyToErrorSpans")]
        public Input<bool>? IsApplyToErrorSpans { get; set; }

        /// <summary>
        /// (Updatable) Specifies if the Apdex rule will be computed for spans matching the rule. Can be used to make sure certain spans don't get an Apdex score. The default is "true".
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) The priority controls the order in which multiple rules in a rule set are applied. Lower values indicate higher priorities. Rules with higher priority are applied first, and once a match is found, the rest of the rules are ignored. Rules within the same rule set cannot have the same priority.
        /// </summary>
        [Input("priority")]
        public Input<int>? Priority { get; set; }

        /// <summary>
        /// (Updatable) The maximum response time in milliseconds that will be considered satisfactory for the end user.
        /// </summary>
        [Input("satisfiedResponseTime")]
        public Input<int>? SatisfiedResponseTime { get; set; }

        /// <summary>
        /// (Updatable) The maximum response time in milliseconds that will be considered tolerable for the end user. Response times beyond this threshold will be considered frustrating. This value cannot be lower than "satisfiedResponseTime".
        /// </summary>
        [Input("toleratingResponseTime")]
        public Input<int>? ToleratingResponseTime { get; set; }

        public ConfigRuleGetArgs()
        {
        }
    }
}
