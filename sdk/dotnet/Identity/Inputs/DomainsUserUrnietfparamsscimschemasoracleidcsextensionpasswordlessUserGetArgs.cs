// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Factor Identifier ID
        /// </summary>
        [Input("factorIdentifier")]
        public Input<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifierGetArgs>? FactorIdentifier { get; set; }

        /// <summary>
        /// (Updatable) Authentication Factor Method
        /// </summary>
        [Input("factorMethod")]
        public Input<string>? FactorMethod { get; set; }

        /// <summary>
        /// (Updatable) Authentication Factor Type
        /// </summary>
        [Input("factorType")]
        public Input<string>? FactorType { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserGetArgs();
    }
}