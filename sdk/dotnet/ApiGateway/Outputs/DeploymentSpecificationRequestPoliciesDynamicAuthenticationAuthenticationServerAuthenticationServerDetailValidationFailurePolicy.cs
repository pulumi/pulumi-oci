// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy
    {
        /// <summary>
        /// (Updatable) Client App Credential details.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyClientDetails? ClientDetails;
        /// <summary>
        /// (Updatable) The path to be used as fallback after OAuth2.
        /// </summary>
        public readonly string? FallbackRedirectPath;
        /// <summary>
        /// (Updatable) The path to be used as logout.
        /// </summary>
        public readonly string? LogoutPath;
        /// <summary>
        /// (Updatable) The duration for which the OAuth2 success token should be cached before it is fetched again.
        /// </summary>
        public readonly int? MaxExpiryDurationInHours;
        /// <summary>
        /// (Updatable) HTTP response code, can include context variables.
        /// </summary>
        public readonly string? ResponseCode;
        /// <summary>
        /// (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformations? ResponseHeaderTransformations;
        /// <summary>
        /// (Updatable) HTTP response message.
        /// </summary>
        public readonly string? ResponseMessage;
        /// <summary>
        /// (Updatable) Response Type.
        /// </summary>
        public readonly string? ResponseType;
        /// <summary>
        /// (Updatable) List of scopes.
        /// </summary>
        public readonly ImmutableArray<string> Scopes;
        /// <summary>
        /// (Updatable) Auth endpoint details.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicySourceUriDetails? SourceUriDetails;
        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (Updatable) Defines whether or not to use cookies for OAuth2 intermediate steps.
        /// </summary>
        public readonly bool? UseCookiesForIntermediateSteps;
        /// <summary>
        /// (Updatable) Defines whether or not to use cookies for session maintenance.
        /// </summary>
        public readonly bool? UseCookiesForSession;
        /// <summary>
        /// (Updatable) Defines whether or not to support PKCE.
        /// </summary>
        public readonly bool? UsePkce;

        [OutputConstructor]
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy(
            Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyClientDetails? clientDetails,

            string? fallbackRedirectPath,

            string? logoutPath,

            int? maxExpiryDurationInHours,

            string? responseCode,

            Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformations? responseHeaderTransformations,

            string? responseMessage,

            string? responseType,

            ImmutableArray<string> scopes,

            Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicySourceUriDetails? sourceUriDetails,

            string type,

            bool? useCookiesForIntermediateSteps,

            bool? useCookiesForSession,

            bool? usePkce)
        {
            ClientDetails = clientDetails;
            FallbackRedirectPath = fallbackRedirectPath;
            LogoutPath = logoutPath;
            MaxExpiryDurationInHours = maxExpiryDurationInHours;
            ResponseCode = responseCode;
            ResponseHeaderTransformations = responseHeaderTransformations;
            ResponseMessage = responseMessage;
            ResponseType = responseType;
            Scopes = scopes;
            SourceUriDetails = sourceUriDetails;
            Type = type;
            UseCookiesForIntermediateSteps = useCookiesForIntermediateSteps;
            UseCookiesForSession = useCookiesForSession;
            UsePkce = usePkce;
        }
    }
}