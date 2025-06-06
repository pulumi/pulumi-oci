// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUserRoleArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The description of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Display-name of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// (Updatable) URI of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// (Updatable) ID of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsAppUserRoleArgs()
        {
        }
        public static new DomainsAppUserRoleArgs Empty => new DomainsAppUserRoleArgs();
    }
}
