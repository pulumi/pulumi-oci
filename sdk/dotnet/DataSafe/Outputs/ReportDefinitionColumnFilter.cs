// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class ReportDefinitionColumnFilter
    {
        /// <summary>
        /// (Updatable) An array of expressions based on the operator type. A filter may have one or more expressions.
        /// </summary>
        public readonly ImmutableArray<string> Expressions;
        /// <summary>
        /// (Updatable) Name of the column on which the filter must be applied.
        /// </summary>
        public readonly string FieldName;
        /// <summary>
        /// (Updatable) Indicates whether the filter is enabled. Values can either be 'true' or 'false'.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// (Updatable) Indicates whether the filter is hidden. Values can either be 'true' or 'false'.
        /// </summary>
        public readonly bool IsHidden;
        /// <summary>
        /// (Updatable) Specifies the type of operator that must be applied for example in, eq etc.
        /// </summary>
        public readonly string Operator;

        [OutputConstructor]
        private ReportDefinitionColumnFilter(
            ImmutableArray<string> expressions,

            string fieldName,

            bool isEnabled,

            bool isHidden,

            string @operator)
        {
            Expressions = expressions;
            FieldName = fieldName;
            IsEnabled = isEnabled;
            IsHidden = isHidden;
            Operator = @operator;
        }
    }
}
