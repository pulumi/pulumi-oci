// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("definedTags")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagGetArgs>? _definedTags;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Defined Tags
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagGetArgs> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTagGetArgs>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTagGetArgs>? _freeformTags;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Freeform Tags
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTagGetArgs> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsFreeformTagGetArgs>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tag slug
        /// </summary>
        [Input("tagSlug")]
        public Input<string>? TagSlug { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsGetArgs();
    }
}