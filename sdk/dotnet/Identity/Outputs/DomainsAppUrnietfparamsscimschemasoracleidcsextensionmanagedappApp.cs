// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappApp
    {
        /// <summary>
        /// (Updatable) If true, then the account form will be displayed in the Oracle Identity Cloud Service UI to interactively create or update an account for this App. If a value is not specified for this attribute, a default value of \"false\" will be assumed as the value for this attribute.
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? AccountFormVisible;
        /// <summary>
        /// (Updatable) If true, admin has granted consent to perform managed app run-time operations.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? AdminConsentGranted;
        /// <summary>
        /// (Updatable) ConnectorBundle configuration properties
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [name]
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundleConfigurationProperty> BundleConfigurationProperties;
        /// <summary>
        /// (Updatable) Configurable options maintaining a pool of ICF connector instances. Values for sub attributes can be set only if the ConnectorBundle referenced in the App has connectorPoolingSupported set to true
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration? BundlePoolConfiguration;
        /// <summary>
        /// (Updatable) If true, the managed app can be authoritative.
        /// 
        /// **Added In:** 17.4.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? CanBeAuthoritative;
        /// <summary>
        /// (Updatable) If true, the accounts of the application are managed through an ICF connector bundle
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? Connected;
        /// <summary>
        /// (Updatable) ConnectorBundle
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle> ConnectorBundles;
        /// <summary>
        /// (Updatable) If true, send activation email to new users created from authoritative sync.
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? EnableAuthSyncNewUserNotification;
        /// <summary>
        /// (Updatable) If true, sync run-time operations are enabled for this App.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? EnableSync;
        /// <summary>
        /// (Updatable) If true, send sync summary as notification upon job completion.
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? EnableSyncSummaryReportNotification;
        /// <summary>
        /// (Updatable) Flat file connector bundle configuration properties
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [name]
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileBundleConfigurationProperty> FlatFileBundleConfigurationProperties;
        /// <summary>
        /// (Updatable) Flat file connector bundle to sync from a flat file.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileConnectorBundle? FlatFileConnectorBundle;
        /// <summary>
        /// (Updatable) IdentityBridges associated with this App
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridge> IdentityBridges;
        /// <summary>
        /// (Updatable) If true, sync from the managed app will be performed as authoritative sync.
        /// 
        /// **Added In:** 17.4.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsAuthoritative;
        /// <summary>
        /// (Updatable) If true, the managed app is a directory.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsDirectory;
        /// <summary>
        /// (Updatable) If true, the managed app is an On-Premise app.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsOnPremiseApp;
        /// <summary>
        /// (Updatable) If true, the managed app supports schema customization.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsSchemaCustomizationSupported;
        /// <summary>
        /// (Updatable) If true, the managed app supports schema discovery.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsSchemaDiscoverySupported;
        /// <summary>
        /// (Updatable) If true, the managed app requires 3-legged OAuth for authorization.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsThreeLeggedOauthEnabled;
        /// <summary>
        /// (Updatable) If true, indicates that Oracle Identity Cloud Service can use two-legged OAuth to connect to this ManagedApp.
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? IsTwoLeggedOauthEnabled;
        /// <summary>
        /// (Updatable) Object classes
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClass> ObjectClasses;
        /// <summary>
        /// (Updatable) The most recent DateTime that the configuration of this App was updated. AppServices updates this timestamp whenever AppServices updates an App's configuration with respect to synchronization.
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        public readonly string? SyncConfigLastModified;
        /// <summary>
        /// (Updatable) The value of this attribute persists any OAuth access token that the system uses to connect to this ManagedApp. The system obtains this access token using an OAuth protocol flow that could be two-legged or three-legged. A two-legged flow involves only the requester and the server. A three-legged flow also requires the consent of a user -- in this case the consent of an administrator.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// </summary>
        public readonly Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential? ThreeLeggedOauthCredential;
        /// <summary>
        /// (Updatable) Three legged OAuth provider name in Oracle Identity Cloud Service.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// </summary>
        public readonly string? ThreeLeggedOauthProviderName;

        [OutputConstructor]
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappApp(
            bool? accountFormVisible,

            bool? adminConsentGranted,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundleConfigurationProperty> bundleConfigurationProperties,

            Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfiguration? bundlePoolConfiguration,

            bool? canBeAuthoritative,

            bool? connected,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle> connectorBundles,

            bool? enableAuthSyncNewUserNotification,

            bool? enableSync,

            bool? enableSyncSummaryReportNotification,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileBundleConfigurationProperty> flatFileBundleConfigurationProperties,

            Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileConnectorBundle? flatFileConnectorBundle,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridge> identityBridges,

            bool? isAuthoritative,

            bool? isDirectory,

            bool? isOnPremiseApp,

            bool? isSchemaCustomizationSupported,

            bool? isSchemaDiscoverySupported,

            bool? isThreeLeggedOauthEnabled,

            bool? isTwoLeggedOauthEnabled,

            ImmutableArray<Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClass> objectClasses,

            string? syncConfigLastModified,

            Outputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential? threeLeggedOauthCredential,

            string? threeLeggedOauthProviderName)
        {
            AccountFormVisible = accountFormVisible;
            AdminConsentGranted = adminConsentGranted;
            BundleConfigurationProperties = bundleConfigurationProperties;
            BundlePoolConfiguration = bundlePoolConfiguration;
            CanBeAuthoritative = canBeAuthoritative;
            Connected = connected;
            ConnectorBundles = connectorBundles;
            EnableAuthSyncNewUserNotification = enableAuthSyncNewUserNotification;
            EnableSync = enableSync;
            EnableSyncSummaryReportNotification = enableSyncSummaryReportNotification;
            FlatFileBundleConfigurationProperties = flatFileBundleConfigurationProperties;
            FlatFileConnectorBundle = flatFileConnectorBundle;
            IdentityBridges = identityBridges;
            IsAuthoritative = isAuthoritative;
            IsDirectory = isDirectory;
            IsOnPremiseApp = isOnPremiseApp;
            IsSchemaCustomizationSupported = isSchemaCustomizationSupported;
            IsSchemaDiscoverySupported = isSchemaDiscoverySupported;
            IsThreeLeggedOauthEnabled = isThreeLeggedOauthEnabled;
            IsTwoLeggedOauthEnabled = isTwoLeggedOauthEnabled;
            ObjectClasses = objectClasses;
            SyncConfigLastModified = syncConfigLastModified;
            ThreeLeggedOauthCredential = threeLeggedOauthCredential;
            ThreeLeggedOauthProviderName = threeLeggedOauthProviderName;
        }
    }
}