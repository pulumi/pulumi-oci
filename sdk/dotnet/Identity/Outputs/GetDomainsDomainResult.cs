// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsDomainResult
    {
        public readonly string AdminEmail;
        public readonly string AdminFirstName;
        public readonly string AdminLastName;
        public readonly string AdminUserName;
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The domain descripition
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The mutable display name of the domain
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The home region for the domain. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.  Example: `us-phoenix-1`
        /// </summary>
        public readonly string HomeRegion;
        /// <summary>
        /// The region specific domain URL
        /// </summary>
        public readonly string HomeRegionUrl;
        /// <summary>
        /// The OCID of the domain
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicate if the domain is visible at login screen or not
        /// </summary>
        public readonly bool IsHiddenOnLogin;
        public readonly bool IsNotificationBypassed;
        public readonly bool IsPrimaryEmailRequired;
        /// <summary>
        /// The domain license type
        /// </summary>
        public readonly string LicenseType;
        /// <summary>
        /// Any additional details about the current state of the Domain.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The regions domain is replication to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDomainReplicaRegionResult> ReplicaRegions;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Date and time the domain was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The domain type
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The region agnostic domain URL
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private GetDomainsDomainResult(
            string adminEmail,

            string adminFirstName,

            string adminLastName,

            string adminUserName,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string homeRegion,

            string homeRegionUrl,

            string id,

            bool isHiddenOnLogin,

            bool isNotificationBypassed,

            bool isPrimaryEmailRequired,

            string licenseType,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetDomainsDomainReplicaRegionResult> replicaRegions,

            string state,

            string timeCreated,

            string type,

            string url)
        {
            AdminEmail = adminEmail;
            AdminFirstName = adminFirstName;
            AdminLastName = adminLastName;
            AdminUserName = adminUserName;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            HomeRegion = homeRegion;
            HomeRegionUrl = homeRegionUrl;
            Id = id;
            IsHiddenOnLogin = isHiddenOnLogin;
            IsNotificationBypassed = isNotificationBypassed;
            IsPrimaryEmailRequired = isPrimaryEmailRequired;
            LicenseType = licenseType;
            LifecycleDetails = lifecycleDetails;
            ReplicaRegions = replicaRegions;
            State = state;
            TimeCreated = timeCreated;
            Type = type;
            Url = url;
        }
    }
}
