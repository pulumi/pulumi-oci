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
    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail
    {
        /// <summary>
        /// (Updatable) The list of intended recipients for the token.
        /// </summary>
        public readonly ImmutableArray<string> Audiences;
        /// <summary>
        /// (Updatable) A list of keys from "parameters" attribute value whose values will be added to the cache key.
        /// </summary>
        public readonly ImmutableArray<string> CacheKeys;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
        /// </summary>
        public readonly string? FunctionId;
        /// <summary>
        /// (Updatable) Whether an unauthenticated user may access the API. Must be "true" to enable ANONYMOUS route authorization.
        /// </summary>
        public readonly bool? IsAnonymousAccessAllowed;
        /// <summary>
        /// (Updatable) A list of parties that could have issued the token.
        /// </summary>
        public readonly ImmutableArray<string> Issuers;
        /// <summary>
        /// (Updatable) The maximum expected time difference between the system clocks of the token issuer and the API Gateway.
        /// </summary>
        public readonly double? MaxClockSkewInSeconds;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly ImmutableDictionary<string, object>? Parameters;
        /// <summary>
        /// (Updatable) A set of Public Keys that will be used to verify the JWT signature.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKeys? PublicKeys;
        /// <summary>
        /// (Updatable) The authentication scheme that is to be used when authenticating the token. This must to be provided if "tokenHeader" is specified.
        /// </summary>
        public readonly string? TokenAuthScheme;
        /// <summary>
        /// (Updatable) The name of the header containing the authentication token.
        /// </summary>
        public readonly string? TokenHeader;
        /// <summary>
        /// (Updatable) The name of the query parameter containing the authentication token.
        /// </summary>
        public readonly string? TokenQueryParam;
        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (Updatable) Policy for defining behaviour on validation failure.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy? ValidationFailurePolicy;
        /// <summary>
        /// (Updatable) Authentication Policies for the Token Authentication types.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy? ValidationPolicy;
        /// <summary>
        /// (Updatable) A list of claims which should be validated to consider the token valid.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim> VerifyClaims;

        [OutputConstructor]
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail(
            ImmutableArray<string> audiences,

            ImmutableArray<string> cacheKeys,

            string? functionId,

            bool? isAnonymousAccessAllowed,

            ImmutableArray<string> issuers,

            double? maxClockSkewInSeconds,

            ImmutableDictionary<string, object>? parameters,

            Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKeys? publicKeys,

            string? tokenAuthScheme,

            string? tokenHeader,

            string? tokenQueryParam,

            string type,

            Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy? validationFailurePolicy,

            Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy? validationPolicy,

            ImmutableArray<Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim> verifyClaims)
        {
            Audiences = audiences;
            CacheKeys = cacheKeys;
            FunctionId = functionId;
            IsAnonymousAccessAllowed = isAnonymousAccessAllowed;
            Issuers = issuers;
            MaxClockSkewInSeconds = maxClockSkewInSeconds;
            Parameters = parameters;
            PublicKeys = publicKeys;
            TokenAuthScheme = tokenAuthScheme;
            TokenHeader = tokenHeader;
            TokenQueryParam = tokenQueryParam;
            Type = type;
            ValidationFailurePolicy = validationFailurePolicy;
            ValidationPolicy = validationPolicy;
            VerifyClaims = verifyClaims;
        }
    }
}