// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSdmMaskingPolicyDifferencesSdmMaskingPolicyDifferenceCollectionItemResult
    {
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
        /// </summary>
        public readonly string DifferenceType;
        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the SDM masking policy difference.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A filter to return only the resources that match the specified masking policy OCID.
        /// </summary>
        public readonly string MaskingPolicyId;
        /// <summary>
        /// A filter to return only the resources that match the specified sensitive data model OCID.
        /// </summary>
        public readonly string SensitiveDataModelId;
        /// <summary>
        /// A filter to return only the resources that match the specified lifecycle states.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreationStarted;

        [OutputConstructor]
        private GetSdmMaskingPolicyDifferencesSdmMaskingPolicyDifferenceCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string differenceType,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string maskingPolicyId,

            string sensitiveDataModelId,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeCreationStarted)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DifferenceType = differenceType;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            MaskingPolicyId = maskingPolicyId;
            SensitiveDataModelId = sensitiveDataModelId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeCreationStarted = timeCreationStarted;
        }
    }
}