// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class ConnectionLastConnectionValidationResultArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A message describing the result of connection validation in more detail.
        /// </summary>
        [Input("message")]
        public Input<string>? Message { get; set; }

        /// <summary>
        /// The latest result of whether the credentials pass the validation.
        /// </summary>
        [Input("result")]
        public Input<string>? Result { get; set; }

        /// <summary>
        /// The latest timestamp when the connection was validated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeValidated")]
        public Input<string>? TimeValidated { get; set; }

        public ConnectionLastConnectionValidationResultArgs()
        {
        }
        public static new ConnectionLastConnectionValidationResultArgs Empty => new ConnectionLastConnectionValidationResultArgs();
    }
}