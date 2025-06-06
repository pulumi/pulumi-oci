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
    public sealed class GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionItemResult
    {
        /// <summary>
        /// maskingPolicyColumnsInfo object has details of column group with schema details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionItemChildResult> Children;
        /// <summary>
        /// The masking format associated with the parent column.
        /// </summary>
        public readonly ImmutableArray<string> MaskingFormats;
        /// <summary>
        /// The OCID of the masking policy.
        /// </summary>
        public readonly string MaskingPolicyId;
        /// <summary>
        /// maskingPolicyColumnsInfo object has details of column group with schema details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionItemParentResult> Parents;
        /// <summary>
        /// A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
        /// </summary>
        public readonly string RelationType;

        [OutputConstructor]
        private GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionItemResult(
            ImmutableArray<Outputs.GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionItemChildResult> children,

            ImmutableArray<string> maskingFormats,

            string maskingPolicyId,

            ImmutableArray<Outputs.GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionItemParentResult> parents,

            string relationType)
        {
            Children = children;
            MaskingFormats = maskingFormats;
            MaskingPolicyId = maskingPolicyId;
            Parents = parents;
            RelationType = relationType;
        }
    }
}
