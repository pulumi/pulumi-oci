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
    public sealed class NamespaceIngestTimeRuleConditions
    {
        /// <summary>
        /// (Updatable) Optional additional condition(s) to be evaluated.
        /// </summary>
        public readonly ImmutableArray<Outputs.NamespaceIngestTimeRuleConditionsAdditionalCondition> AdditionalConditions;
        /// <summary>
        /// (Updatable) The field name to be evaluated.
        /// </summary>
        public readonly string FieldName;
        /// <summary>
        /// (Updatable) The operator to be used for evaluating the field.
        /// </summary>
        public readonly string FieldOperator;
        /// <summary>
        /// (Updatable) The field value to be evaluated.
        /// </summary>
        public readonly string FieldValue;
        /// <summary>
        /// (Updatable) Discriminator.
        /// </summary>
        public readonly string Kind;

        [OutputConstructor]
        private NamespaceIngestTimeRuleConditions(
            ImmutableArray<Outputs.NamespaceIngestTimeRuleConditionsAdditionalCondition> additionalConditions,

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