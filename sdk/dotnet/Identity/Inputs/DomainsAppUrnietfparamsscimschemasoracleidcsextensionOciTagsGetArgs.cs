// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("definedTags")]
        private InputList<Inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagGetArgs>? _definedTags;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Defined Tags
        /// 
        /// **Added In:** 2011192329
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [namespace, key, value]
        /// * type: complex
        /// * idcsSearchable: true
        /// * required: false
        /// * mutability: readWrite
        /// * multiValued: true
        /// * returned: default
        /// </summary>
        public InputList<Inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagGetArgs> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputList<Inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagGetArgs>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputList<Inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTagGetArgs>? _freeformTags;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Freeform Tags
        /// 
        /// **Added In:** 2011192329
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [key, value]
        /// * idcsSearchable: true
        /// * type: complex
        /// * required: false
        /// * mutability: readWrite
        /// * returned: default
        /// * multiValued: true
        /// </summary>
        public InputList<Inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTagGetArgs> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputList<Inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTagGetArgs>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tag slug
        /// 
        /// **Added In:** 2011192329
        /// 
        /// **SCIM++ Properties:**
        /// * type: binary
        /// * mutability: readOnly
        /// * returned: request
        /// </summary>
        [Input("tagSlug")]
        public Input<string>? TagSlug { get; set; }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs();
    }
}