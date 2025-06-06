// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAuthenticationFactorSettingEmailSettingsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Custom redirect Url which will be used in email link
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("emailLinkCustomUrl")]
        public Input<string>? EmailLinkCustomUrl { get; set; }

        /// <summary>
        /// (Updatable) Specifies whether Email link is enabled or not.
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("emailLinkEnabled", required: true)]
        public Input<bool> EmailLinkEnabled { get; set; } = null!;

        public DomainsAuthenticationFactorSettingEmailSettingsArgs()
        {
        }
        public static new DomainsAuthenticationFactorSettingEmailSettingsArgs Empty => new DomainsAuthenticationFactorSettingEmailSettingsArgs();
    }
}
