// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResult
    {
        /// <summary>
        /// Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionResult> Actions;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// A filter to return only the WebAppFirewallPolicy with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControlResult> RequestAccessControls;
        /// <summary>
        /// Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionResult> RequestProtections;
        /// <summary>
        /// Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingResult> RequestRateLimitings;
        /// <summary>
        /// Module that allows inspection of HTTP response properties and to return a defined HTTP response.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControlResult> ResponseAccessControls;
        /// <summary>
        /// Module that allows to enable OCI-managed protection capabilities for HTTP responses.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionResult> ResponseProtections;
        /// <summary>
        /// A filter to return only resources that match the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResult(
            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionResult> actions,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestAccessControlResult> requestAccessControls,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionResult> requestProtections,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingResult> requestRateLimitings,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseAccessControlResult> responseAccessControls,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionResult> responseProtections,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            Actions = actions;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            RequestAccessControls = requestAccessControls;
            RequestProtections = requestProtections;
            RequestRateLimitings = requestRateLimitings;
            ResponseAccessControls = responseAccessControls;
            ResponseProtections = responseProtections;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}