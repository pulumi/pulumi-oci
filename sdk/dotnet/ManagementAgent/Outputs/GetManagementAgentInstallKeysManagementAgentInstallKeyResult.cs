// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent.Outputs
{

    [OutputType]
    public sealed class GetManagementAgentInstallKeysManagementAgentInstallKeyResult
    {
        /// <summary>
        /// Total number of install for this keys
        /// </summary>
        public readonly int AllowedKeyInstallCount;
        /// <summary>
        /// The OCID of the compartment to which a request will be scoped.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Principal id of user who created the Agent Install key
        /// </summary>
        public readonly string CreatedByPrincipalId;
        /// <summary>
        /// Total number of install for this keys
        /// </summary>
        public readonly int CurrentKeyInstallCount;
        /// <summary>
        /// The display name for which the Key needs to be listed.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Agent install Key identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// If set to true, the install key has no expiration date or usage limit. Properties allowedKeyInstallCount and timeExpires are ignored if set to true. Defaults to false.
        /// </summary>
        public readonly bool IsUnlimited;
        /// <summary>
        /// Management Agent Install Key
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time when Management Agent install Key was created. An RFC3339 formatted date time string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// date after which key would expire after creation
        /// </summary>
        public readonly string TimeExpires;
        /// <summary>
        /// The time when Management Agent install Key was updated. An RFC3339 formatted date time string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetManagementAgentInstallKeysManagementAgentInstallKeyResult(
            int allowedKeyInstallCount,

            string compartmentId,

            string createdByPrincipalId,

            int currentKeyInstallCount,

            string displayName,

            string id,

            bool isUnlimited,

            string key,

            string lifecycleDetails,

            string state,

            string timeCreated,

            string timeExpires,

            string timeUpdated)
        {
            AllowedKeyInstallCount = allowedKeyInstallCount;
            CompartmentId = compartmentId;
            CreatedByPrincipalId = createdByPrincipalId;
            CurrentKeyInstallCount = currentKeyInstallCount;
            DisplayName = displayName;
            Id = id;
            IsUnlimited = isUnlimited;
            Key = key;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeCreated = timeCreated;
            TimeExpires = timeExpires;
            TimeUpdated = timeUpdated;
        }
    }
}