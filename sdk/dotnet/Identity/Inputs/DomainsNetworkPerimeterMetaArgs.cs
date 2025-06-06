// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsNetworkPerimeterMetaArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The DateTime the Resource was added to the Service Provider
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        [Input("created")]
        public Input<string>? Created { get; set; }

        /// <summary>
        /// (Updatable) The most recent DateTime that the details of this Resource were updated at the Service Provider. If this Resource has never been modified since its initial creation, the value MUST be the same as the value of created. The attribute MUST be a DateTime.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        [Input("lastModified")]
        public Input<string>? LastModified { get; set; }

        /// <summary>
        /// (Updatable) The URI of the Resource being returned. This value MUST be the same as the Location HTTP response header.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("location")]
        public Input<string>? Location { get; set; }

        /// <summary>
        /// (Updatable) Name of the resource type of the resource--for example, Users or Groups
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        /// <summary>
        /// (Updatable) The version of the Resource being returned. This value must be the same as the ETag HTTP response header.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        public DomainsNetworkPerimeterMetaArgs()
        {
        }
        public static new DomainsNetworkPerimeterMetaArgs Empty => new DomainsNetworkPerimeterMetaArgs();
    }
}
