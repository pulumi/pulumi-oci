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
    public sealed class GetDomainsNotificationSettingsNotificationSettingResult
    {
        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        public readonly ImmutableArray<string> AttributeSets;
        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        public readonly string Attributes;
        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        public readonly string Authorization;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// Event settings
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingEventSettingResult> EventSettings;
        /// <summary>
        /// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
        /// </summary>
        public readonly string ExternalId;
        /// <summary>
        /// From email address to be used in the notification emails
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingFromEmailAddressResult> FromEmailAddresses;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingIdcsCreatedByResult> IdcsCreatedBies;
        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingMetaResult> Metas;
        /// <summary>
        /// Tenant level settings for the notification service
        /// </summary>
        public readonly bool NotificationEnabled;
        public readonly string NotificationSettingId;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        public readonly string ResourceTypeSchemaVersion;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// If true and admin changed user's primary email, send user's profile changed email to old and new primary email address.
        /// </summary>
        public readonly bool SendNotificationToOldAndNewPrimaryEmailsWhenAdminChangesPrimaryEmail;
        /// <summary>
        /// Indicates whether to allow notifications on a secondary email.
        /// </summary>
        public readonly bool SendNotificationsToSecondaryEmail;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;
        /// <summary>
        /// Specify if the notification service is in test mode
        /// </summary>
        public readonly bool TestModeEnabled;
        /// <summary>
        /// List of the test recipient email addresses
        /// </summary>
        public readonly ImmutableArray<string> TestRecipients;

        [OutputConstructor]
        private GetDomainsNotificationSettingsNotificationSettingResult(
            ImmutableArray<string> attributeSets,

            string attributes,

            string authorization,

            string compartmentOcid,

            bool deleteInProgress,

            string domainOcid,

            ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingEventSettingResult> eventSettings,

            string externalId,

            ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingFromEmailAddressResult> fromEmailAddresses,

            string id,

            ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingMetaResult> metas,

            bool notificationEnabled,

            string notificationSettingId,

            string ocid,

            string resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            bool sendNotificationToOldAndNewPrimaryEmailsWhenAdminChangesPrimaryEmail,

            bool sendNotificationsToSecondaryEmail,

            ImmutableArray<Outputs.GetDomainsNotificationSettingsNotificationSettingTagResult> tags,

            string tenancyOcid,

            bool testModeEnabled,

            ImmutableArray<string> testRecipients)
        {
            AttributeSets = attributeSets;
            Attributes = attributes;
            Authorization = authorization;
            CompartmentOcid = compartmentOcid;
            DeleteInProgress = deleteInProgress;
            DomainOcid = domainOcid;
            EventSettings = eventSettings;
            ExternalId = externalId;
            FromEmailAddresses = fromEmailAddresses;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            Metas = metas;
            NotificationEnabled = notificationEnabled;
            NotificationSettingId = notificationSettingId;
            Ocid = ocid;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            SendNotificationToOldAndNewPrimaryEmailsWhenAdminChangesPrimaryEmail = sendNotificationToOldAndNewPrimaryEmailsWhenAdminChangesPrimaryEmail;
            SendNotificationsToSecondaryEmail = sendNotificationsToSecondaryEmail;
            Tags = tags;
            TenancyOcid = tenancyOcid;
            TestModeEnabled = testModeEnabled;
            TestRecipients = testRecipients;
        }
    }
}
