// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsPasswordPolicyGroupArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The displayName of the User or App who modified this Resource
        /// </summary>
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// (Updatable) Value of the tag.
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsPasswordPolicyGroupArgs()
        {
        }
        public static new DomainsPasswordPolicyGroupArgs Empty => new DomainsPasswordPolicyGroupArgs();
    }
}