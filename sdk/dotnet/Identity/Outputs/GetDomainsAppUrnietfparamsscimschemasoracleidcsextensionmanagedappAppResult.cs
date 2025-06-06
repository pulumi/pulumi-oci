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
    public sealed class GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppResult
    {
        /// <summary>
        /// If true, then the account form will be displayed in the Oracle Identity Cloud Service UI to interactively create or update an account for this App. If a value is not specified for this attribute, a default value of \"false\" will be assumed as the value for this attribute.
        /// </summary>
        public readonly bool AccountFormVisible;
        /// <summary>
        /// If true, admin has granted consent to perform managed app run-time operations.
        /// </summary>
        public readonly bool AdminConsentGranted;
        /// <summary>
        /// ConnectorBundle configuration properties
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundleConfigurationPropertyResult> BundleConfigurationProperties;
        /// <summary>
        /// Configurable options maintaining a pool of ICF connector instances. Values for sub attributes can be set only if the ConnectorBundle referenced in the App has connectorPoolingSupported set to true
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfigurationResult> BundlePoolConfigurations;
        /// <summary>
        /// If true, the managed app can be authoritative.
        /// </summary>
        public readonly bool CanBeAuthoritative;
        /// <summary>
        /// If true, the accounts of the application are managed through an ICF connector bundle
        /// </summary>
        public readonly bool Connected;
        /// <summary>
        /// ConnectorBundle
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundleResult> ConnectorBundles;
        /// <summary>
        /// If true, send activation email to new users created from authoritative sync.
        /// </summary>
        public readonly bool EnableAuthSyncNewUserNotification;
        /// <summary>
        /// If true, sync run-time operations are enabled for this App.
        /// </summary>
        public readonly bool EnableSync;
        /// <summary>
        /// If true, send sync summary as notification upon job completion.
        /// </summary>
        public readonly bool EnableSyncSummaryReportNotification;
        /// <summary>
        /// Flat file connector bundle configuration properties
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileBundleConfigurationPropertyResult> FlatFileBundleConfigurationProperties;
        /// <summary>
        /// Flat file connector bundle to sync from a flat file.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileConnectorBundleResult> FlatFileConnectorBundles;
        /// <summary>
        /// IdentityBridges associated with this App
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridgeResult> IdentityBridges;
        /// <summary>
        /// If true, sync from the managed app will be performed as authoritative sync.
        /// </summary>
        public readonly bool IsAuthoritative;
        /// <summary>
        /// If true, the managed app is a directory.
        /// </summary>
        public readonly bool IsDirectory;
        /// <summary>
        /// If true, the managed app is an On-Premise app.
        /// </summary>
        public readonly bool IsOnPremiseApp;
        /// <summary>
        /// If true, the managed app supports schema customization.
        /// </summary>
        public readonly bool IsSchemaCustomizationSupported;
        /// <summary>
        /// If true, the managed app supports schema discovery.
        /// </summary>
        public readonly bool IsSchemaDiscoverySupported;
        /// <summary>
        /// If true, the managed app requires 3-legged OAuth for authorization.
        /// </summary>
        public readonly bool IsThreeLeggedOauthEnabled;
        /// <summary>
        /// If true, indicates that Oracle Identity Cloud Service can use two-legged OAuth to connect to this ManagedApp.
        /// </summary>
        public readonly bool IsTwoLeggedOauthEnabled;
        /// <summary>
        /// Object classes
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassResult> ObjectClasses;
        /// <summary>
        /// The most recent DateTime that the configuration of this App was updated. AppServices updates this timestamp whenever AppServices updates an App's configuration with respect to synchronization.
        /// </summary>
        public readonly string SyncConfigLastModified;
        /// <summary>
        /// The value of this attribute persists any OAuth access token that the system uses to connect to this ManagedApp. The system obtains this access token using an OAuth protocol flow that could be two-legged or three-legged. A two-legged flow involves only the requester and the server. A three-legged flow also requires the consent of a user -- in this case the consent of an administrator.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredentialResult> ThreeLeggedOauthCredentials;
        /// <summary>
        /// Three legged OAuth provider name in Oracle Identity Cloud Service.
        /// </summary>
        public readonly string ThreeLeggedOauthProviderName;

        [OutputConstructor]
        private GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppResult(
            bool accountFormVisible,

            bool adminConsentGranted,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundleConfigurationPropertyResult> bundleConfigurationProperties,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppBundlePoolConfigurationResult> bundlePoolConfigurations,

            bool canBeAuthoritative,

            bool connected,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundleResult> connectorBundles,

            bool enableAuthSyncNewUserNotification,

            bool enableSync,

            bool enableSyncSummaryReportNotification,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileBundleConfigurationPropertyResult> flatFileBundleConfigurationProperties,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppFlatFileConnectorBundleResult> flatFileConnectorBundles,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridgeResult> identityBridges,

            bool isAuthoritative,

            bool isDirectory,

            bool isOnPremiseApp,

            bool isSchemaCustomizationSupported,

            bool isSchemaDiscoverySupported,

            bool isThreeLeggedOauthEnabled,

            bool isTwoLeggedOauthEnabled,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassResult> objectClasses,

            string syncConfigLastModified,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredentialResult> threeLeggedOauthCredentials,

            string threeLeggedOauthProviderName)
        {
            AccountFormVisible = accountFormVisible;
            AdminConsentGranted = adminConsentGranted;
            BundleConfigurationProperties = bundleConfigurationProperties;
            BundlePoolConfigurations = bundlePoolConfigurations;
            CanBeAuthoritative = canBeAuthoritative;
            Connected = connected;
            ConnectorBundles = connectorBundles;
            EnableAuthSyncNewUserNotification = enableAuthSyncNewUserNotification;
            EnableSync = enableSync;
            EnableSyncSummaryReportNotification = enableSyncSummaryReportNotification;
            FlatFileBundleConfigurationProperties = flatFileBundleConfigurationProperties;
            FlatFileConnectorBundles = flatFileConnectorBundles;
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
            ThreeLeggedOauthCredentials = threeLeggedOauthCredentials;
            ThreeLeggedOauthProviderName = threeLeggedOauthProviderName;
        }
    }
}
