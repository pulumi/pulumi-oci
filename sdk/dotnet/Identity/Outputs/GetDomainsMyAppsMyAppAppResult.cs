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
    public sealed class GetDomainsMyAppsMyAppAppResult
    {
        /// <summary>
        /// If true, this App is able to participate in runtime services, such as automatic-login, OAuth, and SAML. If false, all runtime services are disabled for this App, and only administrative operations can be performed.
        /// </summary>
        public readonly bool Active;
        /// <summary>
        /// Application icon.
        /// </summary>
        public readonly string AppIcon;
        /// <summary>
        /// Application thumbnail.
        /// </summary>
        public readonly string AppThumbnail;
        /// <summary>
        /// Application description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// User display name
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// If true, this App is an AliasApp and it cannot be granted to an end user directly
        /// </summary>
        public readonly bool IsAliasApp;
        /// <summary>
        /// If true, this App allows runtime services to log end users into this App automatically.
        /// </summary>
        public readonly bool IsLoginTarget;
        /// <summary>
        /// If true, this application is an Oracle Public Cloud service-instance.
        /// </summary>
        public readonly bool IsOpcService;
        /// <summary>
        /// The protocol that runtime services will use to log end users in to this App automatically. If 'OIDC', then runtime services use the OpenID Connect protocol. If 'SAML', then runtime services use Security Assertion Markup Language protocol.
        /// </summary>
        public readonly string LoginMechanism;
        /// <summary>
        /// UserWalletArtifact URI
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// This Uniform Resource Name (URN) value identifies the type of Oracle Public Cloud service of which this app is an instance.
        /// </summary>
        public readonly string ServiceTypeUrn;
        /// <summary>
        /// If true, this App will be displayed in the MyApps page of each end-user who has access to this App.
        /// </summary>
        public readonly bool ShowInMyApps;
        /// <summary>
        /// UserWalletArtifact identifier
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsMyAppsMyAppAppResult(
            bool active,

            string appIcon,

            string appThumbnail,

            string description,

            string display,

            bool isAliasApp,

            bool isLoginTarget,

            bool isOpcService,

            string loginMechanism,

            string @ref,

            string serviceTypeUrn,

            bool showInMyApps,

            string value)
        {
            Active = active;
            AppIcon = appIcon;
            AppThumbnail = appThumbnail;
            Description = description;
            Display = display;
            IsAliasApp = isAliasApp;
            IsLoginTarget = isLoginTarget;
            IsOpcService = isOpcService;
            LoginMechanism = loginMechanism;
            Ref = @ref;
            ServiceTypeUrn = serviceTypeUrn;
            ShowInMyApps = showInMyApps;
            Value = value;
        }
    }
}