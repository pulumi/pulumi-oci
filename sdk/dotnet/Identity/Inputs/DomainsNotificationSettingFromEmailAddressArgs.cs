// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsNotificationSettingFromEmailAddressArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Display name for the From email address
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) From address verification mode. If postmaster account is available then 'domain' mode is used or entire valid email can be verified using 'email' mode
        /// 
        /// **Added In:** 18.2.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("validate", required: true)]
        public Input<string> Validate { get; set; } = null!;

        /// <summary>
        /// (Updatable) Validation status for the From email address
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// </summary>
        [Input("validationStatus")]
        public Input<string>? ValidationStatus { get; set; }

        /// <summary>
        /// (Updatable) Value of the From email address
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsNotificationSettingFromEmailAddressArgs()
        {
        }
        public static new DomainsNotificationSettingFromEmailAddressArgs Empty => new DomainsNotificationSettingFromEmailAddressArgs();
    }
}
