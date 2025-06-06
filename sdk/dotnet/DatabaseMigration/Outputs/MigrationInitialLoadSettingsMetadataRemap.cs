// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class MigrationInitialLoadSettingsMetadataRemap
    {
        /// <summary>
        /// (Updatable) Specifies the new value that oldValue should be translated into.
        /// </summary>
        public readonly string? NewValue;
        /// <summary>
        /// (Updatable) Specifies the value which needs to be reset.
        /// </summary>
        public readonly string? OldValue;
        /// <summary>
        /// (Updatable) Type of remap. Refer to [METADATA_REMAP Procedure ](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-0FC32790-91E6-4781-87A3-229DE024CB3D)
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private MigrationInitialLoadSettingsMetadataRemap(
            string? newValue,

            string? oldValue,

            string? type)
        {
            NewValue = newValue;
            OldValue = oldValue;
            Type = type;
        }
    }
}
