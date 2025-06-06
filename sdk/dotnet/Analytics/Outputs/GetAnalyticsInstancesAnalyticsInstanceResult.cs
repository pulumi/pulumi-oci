// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Outputs
{

    [OutputType]
    public sealed class GetAnalyticsInstancesAnalyticsInstanceResult
    {
        public readonly string AdminUser;
        /// <summary>
        /// Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAnalyticsInstancesAnalyticsInstanceCapacityResult> Capacities;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Description of the vanity url.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Identity domain OCID.
        /// </summary>
        public readonly string DomainId;
        /// <summary>
        /// Email address receiving notifications.
        /// </summary>
        public readonly string EmailNotification;
        /// <summary>
        /// The feature set of an Analytics instance.
        /// </summary>
        public readonly string FeatureBundle;
        /// <summary>
        /// A filter to only return resources matching the feature set. Values are case-insensitive.
        /// </summary>
        public readonly string FeatureSet;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The Virtual Cloud Network OCID.
        /// </summary>
        public readonly string Id;
        public readonly string IdcsAccessToken;
        /// <summary>
        /// OCID of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The license used for the service.
        /// </summary>
        public readonly string LicenseType;
        /// <summary>
        /// A filter to return only resources that match the given name exactly.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Base representation of a network endpoint.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailResult> NetworkEndpointDetails;
        /// <summary>
        /// URL of the Analytics service.
        /// </summary>
        public readonly string ServiceUrl;
        /// <summary>
        /// A filter to only return resources matching the lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Analytics instance update channel.
        /// </summary>
        public readonly string UpdateChannel;

        [OutputConstructor]
        private GetAnalyticsInstancesAnalyticsInstanceResult(
            string adminUser,

            ImmutableArray<Outputs.GetAnalyticsInstancesAnalyticsInstanceCapacityResult> capacities,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string domainId,

            string emailNotification,

            string featureBundle,

            string featureSet,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string idcsAccessToken,

            string kmsKeyId,

            string licenseType,

            string name,

            ImmutableArray<Outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetailResult> networkEndpointDetails,

            string serviceUrl,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string updateChannel)
        {
            AdminUser = adminUser;
            Capacities = capacities;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DomainId = domainId;
            EmailNotification = emailNotification;
            FeatureBundle = featureBundle;
            FeatureSet = featureSet;
            FreeformTags = freeformTags;
            Id = id;
            IdcsAccessToken = idcsAccessToken;
            KmsKeyId = kmsKeyId;
            LicenseType = licenseType;
            Name = name;
            NetworkEndpointDetails = networkEndpointDetails;
            ServiceUrl = serviceUrl;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            UpdateChannel = updateChannel;
        }
    }
}
