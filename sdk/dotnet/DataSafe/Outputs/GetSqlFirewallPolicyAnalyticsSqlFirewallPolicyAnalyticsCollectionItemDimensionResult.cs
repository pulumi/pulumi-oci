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
    public sealed class GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemDimensionResult
    {
        /// <summary>
        /// Specifies the SQL firewall policy enforcement option.
        /// </summary>
        public readonly string EnforcementScope;
        /// <summary>
        /// An optional filter to return only resources that match the specified OCID of the security policy resource.
        /// </summary>
        public readonly string SecurityPolicyId;
        /// <summary>
        /// The current state of the SQL firewall policy.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Specifies the mode in which the SQL firewall policy is enabled.
        /// </summary>
        public readonly string ViolationAction;

        [OutputConstructor]
        private GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItemDimensionResult(
            string enforcementScope,

            string securityPolicyId,

            string state,

            string violationAction)
        {
            EnforcementScope = enforcementScope;
            SecurityPolicyId = securityPolicyId;
            State = state;
            ViolationAction = violationAction;
        }
    }
}