// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKeyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) String describing the expression with wildcards.
        /// </summary>
        [Input("expression")]
        public Input<string>? Expression { get; set; }

        /// <summary>
        /// (Updatable) Information regarding whether this is the default branch.
        /// </summary>
        [Input("isDefault")]
        public Input<bool>? IsDefault { get; set; }

        /// <summary>
        /// (Updatable) The case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        [Input("values")]
        private InputList<string>? _values;

        /// <summary>
        /// (Updatable) A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
        /// </summary>
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKeyArgs()
        {
        }
        public static new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKeyArgs Empty => new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKeyArgs();
    }
}