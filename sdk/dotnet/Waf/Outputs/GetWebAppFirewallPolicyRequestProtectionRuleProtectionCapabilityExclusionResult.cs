// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class GetWebAppFirewallPolicyRequestProtectionRuleProtectionCapabilityExclusionResult
    {
        /// <summary>
        /// List of URL query parameter values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from inspecting. Example: If we have query parameter 'argumentName=argumentValue' and args=['argumentName'], both 'argumentName' and 'argumentValue' will not be inspected.
        /// </summary>
        public readonly ImmutableArray<string> Args;
        /// <summary>
        /// List of HTTP request cookie values (by cookie name) to exclude from inspecting. Example: If we have cookie 'cookieName=cookieValue' and requestCookies=['cookieName'], both 'cookieName' and 'cookieValue' will not be inspected.
        /// </summary>
        public readonly ImmutableArray<string> RequestCookies;

        [OutputConstructor]
        private GetWebAppFirewallPolicyRequestProtectionRuleProtectionCapabilityExclusionResult(
            ImmutableArray<string> args,

            ImmutableArray<string> requestCookies)
        {
            Args = args;
            RequestCookies = requestCookies;
        }
    }
}