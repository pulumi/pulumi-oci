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
    public sealed class GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingBypassCodeSettingResult
    {
        /// <summary>
        /// Expiry (in minutes) of any bypass code that is generated by the help desk
        /// </summary>
        public readonly int HelpDeskCodeExpiryInMins;
        /// <summary>
        /// If true, indicates that help desk bypass code generation is enabled
        /// </summary>
        public readonly bool HelpDeskGenerationEnabled;
        /// <summary>
        /// The maximum number of times that any bypass code that is generated by the help desk can be used
        /// </summary>
        public readonly int HelpDeskMaxUsage;
        /// <summary>
        /// Exact length of the bypass code to be generated
        /// </summary>
        public readonly int Length;
        /// <summary>
        /// The maximum number of bypass codes that can be issued to any user
        /// </summary>
        public readonly int MaxActive;
        /// <summary>
        /// If true, indicates that self-service bypass code generation is enabled
        /// </summary>
        public readonly bool SelfServiceGenerationEnabled;

        [OutputConstructor]
        private GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingBypassCodeSettingResult(
            int helpDeskCodeExpiryInMins,

            bool helpDeskGenerationEnabled,

            int helpDeskMaxUsage,

            int length,

            int maxActive,

            bool selfServiceGenerationEnabled)
        {
            HelpDeskCodeExpiryInMins = helpDeskCodeExpiryInMins;
            HelpDeskGenerationEnabled = helpDeskGenerationEnabled;
            HelpDeskMaxUsage = helpDeskMaxUsage;
            Length = length;
            MaxActive = maxActive;
            SelfServiceGenerationEnabled = selfServiceGenerationEnabled;
        }
    }
}
