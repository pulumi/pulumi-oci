// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppScopeGetArgs : global::Pulumi.ResourceArgs
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
        /// (Updatable) Display name of the flatfile bundle configuration property. This attribute maps to \"displayName\" attribute in \"ConfigurationProperty\" in ICF.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) The fully qualified value of this scope within this App. A fully qualified scope combines the 'value' of each scope with the value of 'audience'. Each value of 'fqs' must be unique across the system. Used only when this App acts as an OAuth Resource.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: server
        /// </summary>
        [Input("fqs")]
        public Input<string>? Fqs { get; set; }

        /// <summary>
        /// (Updatable) If true, indicates that this value must be protected.
        /// 
        /// **Added In:** 18.2.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("readOnly")]
        public Input<bool>? ReadOnly { get; set; }

        /// <summary>
        /// (Updatable) If true, indicates that a user must provide consent to access this scope. Note: Used only when this App acts as an OAuth Resource.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("requiresConsent")]
        public Input<bool>? RequiresConsent { get; set; }

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

        public DomainsAppScopeGetArgs()
        {
        }
        public static new DomainsAppScopeGetArgs Empty => new DomainsAppScopeGetArgs();
    }
}