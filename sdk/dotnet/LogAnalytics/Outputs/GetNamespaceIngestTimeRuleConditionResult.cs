// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class GetNamespaceIngestTimeRuleConditionResult
    {
        /// <summary>
        /// Optional additional condition(s) to be evaluated.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespaceIngestTimeRuleConditionAdditionalConditionResult> AdditionalConditions;
        /// <summary>
        /// The field name to be evaluated.
        /// </summary>
        public readonly string FieldName;
        /// <summary>
        /// The operator to be used for evaluating the field.
        /// </summary>
        public readonly string FieldOperator;
        /// <summary>
        /// The field value to be evaluated.
        /// </summary>
        public readonly string FieldValue;
        /// <summary>
        /// Discriminator.
        /// </summary>
        public readonly string Kind;

        [OutputConstructor]
        private GetNamespaceIngestTimeRuleConditionResult(
            ImmutableArray<Outputs.GetNamespaceIngestTimeRuleConditionAdditionalConditionResult> additionalConditions,

            string fieldName,

            string fieldOperator,

            string fieldValue,

            string kind)
        {
            AdditionalConditions = additionalConditions;
            FieldName = fieldName;
            FieldOperator = fieldOperator;
            FieldValue = fieldValue;
            Kind = kind;
        }
    }
}
