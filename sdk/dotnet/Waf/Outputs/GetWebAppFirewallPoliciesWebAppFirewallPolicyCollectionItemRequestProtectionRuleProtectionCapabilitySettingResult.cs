// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilitySettingResult
    {
        /// <summary>
        /// List of allowed HTTP methods. Each value as a RFC7230 formated token string. Used in protection capability 911100: Restrict HTTP Request Methods.
        /// </summary>
        public readonly ImmutableArray<string> AllowedHttpMethods;
        /// <summary>
        /// Maximum allowed length of headers in an HTTP request. Used in protection capability: 9200024: Limit length of request header size.
        /// </summary>
        public readonly int MaxHttpRequestHeaderLength;
        /// <summary>
        /// Maximum number of headers allowed in an HTTP request. Used in protection capability 9200014: Limit Number of Request Headers.
        /// </summary>
        public readonly int MaxHttpRequestHeaders;
        /// <summary>
        /// Maximum number of arguments allowed. Used in protection capability 920380: Number of Arguments Limits.
        /// </summary>
        public readonly int MaxNumberOfArguments;
        /// <summary>
        /// Maximum allowed length of a single argument. Used in protection capability 920370: Limit argument value length.
        /// </summary>
        public readonly int MaxSingleArgumentLength;
        /// <summary>
        /// Maximum allowed total length of all arguments. Used in protection capability 920390: Limit arguments total length.
        /// </summary>
        public readonly int MaxTotalArgumentLength;

        [OutputConstructor]
        private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestProtectionRuleProtectionCapabilitySettingResult(
            ImmutableArray<string> allowedHttpMethods,

            int maxHttpRequestHeaderLength,

            int maxHttpRequestHeaders,

            int maxNumberOfArguments,

            int maxSingleArgumentLength,

            int maxTotalArgumentLength)
        {
            AllowedHttpMethods = allowedHttpMethods;
            MaxHttpRequestHeaderLength = maxHttpRequestHeaderLength;
            MaxHttpRequestHeaders = maxHttpRequestHeaders;
            MaxNumberOfArguments = maxNumberOfArguments;
            MaxSingleArgumentLength = maxSingleArgumentLength;
            MaxTotalArgumentLength = maxTotalArgumentLength;
        }
    }
}
