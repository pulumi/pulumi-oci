// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetPluggableDatabasesPluggableDatabaseConnectionStringResult
    {
        /// <summary>
        /// All connection strings to use to connect to the pluggable database.
        /// </summary>
        public readonly ImmutableDictionary<string, object> AllConnectionStrings;
        /// <summary>
        /// A host name-based PDB connection string.
        /// </summary>
        public readonly string PdbDefault;
        /// <summary>
        /// An IP-based PDB connection string.
        /// </summary>
        public readonly string PdbIpDefault;

        [OutputConstructor]
        private GetPluggableDatabasesPluggableDatabaseConnectionStringResult(
            ImmutableDictionary<string, object> allConnectionStrings,

            string pdbDefault,

            string pdbIpDefault)
        {
            AllConnectionStrings = allConnectionStrings;
            PdbDefault = pdbDefault;
            PdbIpDefault = pdbIpDefault;
        }
    }
}
