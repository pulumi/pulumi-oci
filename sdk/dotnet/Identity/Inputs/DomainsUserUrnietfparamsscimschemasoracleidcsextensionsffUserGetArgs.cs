// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) SFF auth keys clob
        /// </summary>
        [Input("sffAuthKeys")]
        public Input<string>? SffAuthKeys { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUserGetArgs();
    }
}