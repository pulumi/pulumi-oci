// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsSettingDefaultImageArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A human-readable name, primarily used for display purposes
        /// 
        /// **Added In:** 18.2.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// </summary>
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// (Updatable) Indicates the image type
        /// 
        /// **Added In:** 18.2.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: default
        /// * type: string
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable) Image URI
        /// 
        /// **Added In:** 18.2.2
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: default
        /// * type: reference
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsSettingDefaultImageArgs()
        {
        }
        public static new DomainsSettingDefaultImageArgs Empty => new DomainsSettingDefaultImageArgs();
    }
}
