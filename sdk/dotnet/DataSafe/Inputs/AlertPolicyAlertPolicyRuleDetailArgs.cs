// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Inputs
{

    public sealed class AlertPolicyAlertPolicyRuleDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Describes the alert policy rule.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The display name of the alert policy rule.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The conditional expression of the alert policy rule which evaluates to boolean value.
        /// </summary>
        [Input("expression", required: true)]
        public Input<string> Expression { get; set; } = null!;

        public AlertPolicyAlertPolicyRuleDetailArgs()
        {
        }
        public static new AlertPolicyAlertPolicyRuleDetailArgs Empty => new AlertPolicyAlertPolicyRuleDetailArgs();
    }
}
