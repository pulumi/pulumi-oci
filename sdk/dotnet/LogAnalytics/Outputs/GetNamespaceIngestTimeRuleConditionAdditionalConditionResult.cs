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
    public sealed class GetNamespaceIngestTimeRuleConditionAdditionalConditionResult
    {
        /// <summary>
        /// The additional field name to be evaluated.
        /// </summary>
        public readonly string ConditionField;
        /// <summary>
        /// The operator to be used for evaluating the additional field.
        /// </summary>
        public readonly string ConditionOperator;
        /// <summary>
        /// The additional field value to be evaluated.
        /// </summary>
        public readonly string ConditionValue;

        [OutputConstructor]
        private GetNamespaceIngestTimeRuleConditionAdditionalConditionResult(
            string conditionField,

            string conditionOperator,

            string conditionValue)
        {
            ConditionField = conditionField;
            ConditionOperator = conditionOperator;
            ConditionValue = conditionValue;
        }
    }
}