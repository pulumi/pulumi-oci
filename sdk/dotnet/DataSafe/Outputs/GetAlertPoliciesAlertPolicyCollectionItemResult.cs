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
    public sealed class GetAlertPoliciesAlertPolicyCollectionItemResult
    {
        /// <summary>
        /// Indicates the Data Safe feature to which the alert policy belongs.
        /// </summary>
        public readonly string AlertPolicyType;
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The description of the alert policy.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the alert policy.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// An optional filter to return only alert policies that are user-defined or not.
        /// </summary>
        public readonly bool IsUserDefined;
        /// <summary>
        /// Severity level of the alert raised by this policy.
        /// </summary>
        public readonly string Severity;
        /// <summary>
        /// An optional filter to return only alert policies that have the given life-cycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// Creation date and time of the alert policy, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Last date and time the alert policy was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetAlertPoliciesAlertPolicyCollectionItemResult(
            string alertPolicyType,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isUserDefined,

            string severity,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AlertPolicyType = alertPolicyType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsUserDefined = isUserDefined;
            Severity = severity;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}