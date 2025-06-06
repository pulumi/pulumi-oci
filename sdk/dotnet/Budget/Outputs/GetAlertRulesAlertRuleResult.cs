// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Budget.Outputs
{

    [OutputType]
    public sealed class GetAlertRulesAlertRuleResult
    {
        /// <summary>
        /// The unique budget OCID.
        /// </summary>
        public readonly string BudgetId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description of the alert rule.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. This does not have to be unique, and it's changeable.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the alert rule.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The custom message that will be sent when the alert is triggered.
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// The delimited list of email addresses to receive the alert when it triggers. Delimiter characters can be a comma, space, TAB, or semicolon.
        /// </summary>
        public readonly string Recipients;
        /// <summary>
        /// The current state of the resource to filter by.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The threshold for triggering the alert. If the thresholdType is PERCENTAGE, the maximum value is 10000.
        /// </summary>
        public readonly double Threshold;
        /// <summary>
        /// The type of threshold.
        /// </summary>
        public readonly string ThresholdType;
        /// <summary>
        /// The time when the budget was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the budget was updated.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The type of the alert. Valid values are ACTUAL (the alert triggers based on actual usage), or FORECAST (the alert triggers based on predicted usage).
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The version of the alert rule. Starts from 1 and increments by 1.
        /// </summary>
        public readonly int Version;

        [OutputConstructor]
        private GetAlertRulesAlertRuleResult(
            string budgetId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string message,

            string recipients,

            string state,

            double threshold,

            string thresholdType,

            string timeCreated,

            string timeUpdated,

            string type,

            int version)
        {
            BudgetId = budgetId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            Message = message;
            Recipients = recipients;
            State = state;
            Threshold = threshold;
            ThresholdType = thresholdType;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
            Version = version;
        }
    }
}
