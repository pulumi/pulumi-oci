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
    public sealed class GetSqlFirewallPoliciesSqlFirewallPolicyCollectionItemResult
    {
        /// <summary>
        /// The list of allowed ip addresses for the SQL firewall policy.
        /// </summary>
        public readonly ImmutableArray<string> AllowedClientIps;
        /// <summary>
        /// The list of allowed operating system user names for the SQL firewall policy.
        /// </summary>
        public readonly ImmutableArray<string> AllowedClientOsUsernames;
        /// <summary>
        /// The list of allowed client programs for the SQL firewall policy.
        /// </summary>
        public readonly ImmutableArray<string> AllowedClientPrograms;
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A filter to return only items that match the specified user name.
        /// </summary>
        public readonly string DbUserName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The description of the SQL firewall policy.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Specifies the SQL firewall policy enforcement option.
        /// </summary>
        public readonly string EnforcementScope;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the SQL firewall policy.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details about the current state of the SQL firewall policy in Data Safe.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// An optional filter to return only resources that match the specified OCID of the security policy resource.
        /// </summary>
        public readonly string SecurityPolicyId;
        /// <summary>
        /// An optional filter to return only resources that match the specified OCID of the SQL firewall policy resource.
        /// </summary>
        public readonly string SqlFirewallPolicyId;
        /// <summary>
        /// Specifies the level of SQL included for this SQL firewall policy. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
        /// </summary>
        public readonly string SqlLevel;
        /// <summary>
        /// The current state of the SQL firewall policy.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Specifies whether the SQL firewall policy is enabled or disabled.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time that the SQL firewall policy was created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the SQL firewall policy was last updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// An optional filter to return only resources that match the specified violation action.
        /// </summary>
        public readonly string ViolationAction;
        /// <summary>
        /// Specifies whether a unified audit policy should be enabled for auditing the SQL firewall policy violations.
        /// </summary>
        public readonly string ViolationAudit;

        [OutputConstructor]
        private GetSqlFirewallPoliciesSqlFirewallPolicyCollectionItemResult(
            ImmutableArray<string> allowedClientIps,

            ImmutableArray<string> allowedClientOsUsernames,

            ImmutableArray<string> allowedClientPrograms,

            string compartmentId,

            string dbUserName,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            string enforcementScope,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string securityPolicyId,

            string sqlFirewallPolicyId,

            string sqlLevel,

            string state,

            string status,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated,

            string violationAction,

            string violationAudit)
        {
            AllowedClientIps = allowedClientIps;
            AllowedClientOsUsernames = allowedClientOsUsernames;
            AllowedClientPrograms = allowedClientPrograms;
            CompartmentId = compartmentId;
            DbUserName = dbUserName;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            EnforcementScope = enforcementScope;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            SecurityPolicyId = securityPolicyId;
            SqlFirewallPolicyId = sqlFirewallPolicyId;
            SqlLevel = sqlLevel;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            ViolationAction = violationAction;
            ViolationAudit = violationAudit;
        }
    }
}