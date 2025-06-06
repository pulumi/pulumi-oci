// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Integration.Outputs
{

    [OutputType]
    public sealed class GetIntegrationInstancesIntegrationInstanceResult
    {
        /// <summary>
        /// A list of alternate custom endpoints used for the integration instance URL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointResult> AlternateCustomEndpoints;
        /// <summary>
        /// A list of associated attachments to other services
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceAttachmentResult> Attachments;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The entitlement used for billing purposes.
        /// </summary>
        public readonly string ConsumptionModel;
        /// <summary>
        /// Details for a custom endpoint for the integration instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceCustomEndpointResult> CustomEndpoints;
        /// <summary>
        /// Data retention period set for given integration instance
        /// </summary>
        public readonly string DataRetentionPeriod;
        /// <summary>
        /// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Disaster recovery details for the integration instance created in the region.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceDisasterRecoveryDetailResult> DisasterRecoveryDetails;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        public readonly string DomainId;
        public readonly int EnableProcessAutomationTrigger;
        public readonly int ExtendDataRetentionTrigger;
        public readonly int FailoverTrigger;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The Virtual Cloud Network OCID.
        /// </summary>
        public readonly string Id;
        public readonly string IdcsAt;
        /// <summary>
        /// Information for IDCS access
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceIdcsInfoResult> IdcsInfos;
        public readonly string InstanceDesignTimeUrl;
        /// <summary>
        /// The Integration Instance URL.
        /// </summary>
        public readonly string InstanceUrl;
        /// <summary>
        /// Standard or Enterprise type, Oracle Integration Generation 2 uses ENTERPRISE and STANDARD, Oracle Integration 3 uses ENTERPRISEX and STANDARDX
        /// </summary>
        public readonly string IntegrationInstanceType;
        /// <summary>
        /// Bring your own license.
        /// </summary>
        public readonly bool IsByol;
        /// <summary>
        /// Is Disaster Recovery enabled for the integrationInstance
        /// </summary>
        public readonly bool IsDisasterRecoveryEnabled;
        /// <summary>
        /// The file server is enabled or not.
        /// </summary>
        public readonly bool IsFileServerEnabled;
        /// <summary>
        /// Visual Builder is enabled or not.
        /// </summary>
        public readonly bool IsVisualBuilderEnabled;
        /// <summary>
        /// Additional details of lifecycleState or substates
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The number of configured message packs (if any)
        /// </summary>
        public readonly int MessagePacks;
        /// <summary>
        /// Base representation of a network endpoint.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailResult> NetworkEndpointDetails;
        /// <summary>
        /// Base representation for Outbound Connection (Reverse Connection).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstancePrivateEndpointOutboundConnectionResult> PrivateEndpointOutboundConnections;
        /// <summary>
        /// Shape
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// Life cycle state to query on.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string StateMessage;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the the Integration Instance was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the IntegrationInstance was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetIntegrationInstancesIntegrationInstanceResult(
            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointResult> alternateCustomEndpoints,

            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceAttachmentResult> attachments,

            string compartmentId,

            string consumptionModel,

            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceCustomEndpointResult> customEndpoints,

            string dataRetentionPeriod,

            ImmutableDictionary<string, string> definedTags,

            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceDisasterRecoveryDetailResult> disasterRecoveryDetails,

            string displayName,

            string domainId,

            int enableProcessAutomationTrigger,

            int extendDataRetentionTrigger,

            int failoverTrigger,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string idcsAt,

            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceIdcsInfoResult> idcsInfos,

            string instanceDesignTimeUrl,

            string instanceUrl,

            string integrationInstanceType,

            bool isByol,

            bool isDisasterRecoveryEnabled,

            bool isFileServerEnabled,

            bool isVisualBuilderEnabled,

            string lifecycleDetails,

            int messagePacks,

            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailResult> networkEndpointDetails,

            ImmutableArray<Outputs.GetIntegrationInstancesIntegrationInstancePrivateEndpointOutboundConnectionResult> privateEndpointOutboundConnections,

            string shape,

            string state,

            string stateMessage,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AlternateCustomEndpoints = alternateCustomEndpoints;
            Attachments = attachments;
            CompartmentId = compartmentId;
            ConsumptionModel = consumptionModel;
            CustomEndpoints = customEndpoints;
            DataRetentionPeriod = dataRetentionPeriod;
            DefinedTags = definedTags;
            DisasterRecoveryDetails = disasterRecoveryDetails;
            DisplayName = displayName;
            DomainId = domainId;
            EnableProcessAutomationTrigger = enableProcessAutomationTrigger;
            ExtendDataRetentionTrigger = extendDataRetentionTrigger;
            FailoverTrigger = failoverTrigger;
            FreeformTags = freeformTags;
            Id = id;
            IdcsAt = idcsAt;
            IdcsInfos = idcsInfos;
            InstanceDesignTimeUrl = instanceDesignTimeUrl;
            InstanceUrl = instanceUrl;
            IntegrationInstanceType = integrationInstanceType;
            IsByol = isByol;
            IsDisasterRecoveryEnabled = isDisasterRecoveryEnabled;
            IsFileServerEnabled = isFileServerEnabled;
            IsVisualBuilderEnabled = isVisualBuilderEnabled;
            LifecycleDetails = lifecycleDetails;
            MessagePacks = messagePacks;
            NetworkEndpointDetails = networkEndpointDetails;
            PrivateEndpointOutboundConnections = privateEndpointOutboundConnections;
            Shape = shape;
            State = state;
            StateMessage = stateMessage;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
