// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup
    {
        /// <summary>
        /// (Updatable) Flag controlling whether group membership can be request by user through self service console.
        /// </summary>
        public readonly bool? Requestable;

        [OutputConstructor]
        private DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup(bool? requestable)
        {
            Requestable = requestable;
        }
    }
}