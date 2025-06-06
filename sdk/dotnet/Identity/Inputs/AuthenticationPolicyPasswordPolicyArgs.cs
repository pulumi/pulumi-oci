// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class AuthenticationPolicyPasswordPolicyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) At least one lower case character required.
        /// </summary>
        [Input("isLowercaseCharactersRequired")]
        public Input<bool>? IsLowercaseCharactersRequired { get; set; }

        /// <summary>
        /// (Updatable) At least one numeric character required.
        /// </summary>
        [Input("isNumericCharactersRequired")]
        public Input<bool>? IsNumericCharactersRequired { get; set; }

        /// <summary>
        /// (Updatable) At least one special character required.
        /// </summary>
        [Input("isSpecialCharactersRequired")]
        public Input<bool>? IsSpecialCharactersRequired { get; set; }

        /// <summary>
        /// (Updatable) At least one uppercase character required.
        /// </summary>
        [Input("isUppercaseCharactersRequired")]
        public Input<bool>? IsUppercaseCharactersRequired { get; set; }

        /// <summary>
        /// (Updatable) User name is allowed to be part of the password.
        /// </summary>
        [Input("isUsernameContainmentAllowed")]
        public Input<bool>? IsUsernameContainmentAllowed { get; set; }

        /// <summary>
        /// (Updatable) Minimum password length required.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("minimumPasswordLength")]
        public Input<int>? MinimumPasswordLength { get; set; }

        public AuthenticationPolicyPasswordPolicyArgs()
        {
        }
        public static new AuthenticationPolicyPasswordPolicyArgs Empty => new AuthenticationPolicyPasswordPolicyArgs();
    }
}
