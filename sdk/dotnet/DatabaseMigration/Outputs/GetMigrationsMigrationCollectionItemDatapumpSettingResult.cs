// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationsMigrationCollectionItemDatapumpSettingResult
    {
        /// <summary>
        /// Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameterResult> DataPumpParameters;
        /// <summary>
        /// Directory object details, used to define either import or export directory objects in Data Pump Settings.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObjectResult> ExportDirectoryObjects;
        /// <summary>
        /// Directory object details, used to define either import or export directory objects in Data Pump Settings.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObjectResult> ImportDirectoryObjects;
        /// <summary>
        /// Data Pump job mode. Refer to [Data Pump Export Modes ](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
        /// </summary>
        public readonly string JobMode;
        /// <summary>
        /// Defines remapping to be applied to objects as they are processed. Refer to [METADATA_REMAP Procedure ](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-0FC32790-91E6-4781-87A3-229DE024CB3D)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemapResult> MetadataRemaps;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemDatapumpSettingResult(
            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameterResult> dataPumpParameters,

            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObjectResult> exportDirectoryObjects,

            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObjectResult> importDirectoryObjects,

            string jobMode,

            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemapResult> metadataRemaps)
        {
            DataPumpParameters = dataPumpParameters;
            ExportDirectoryObjects = exportDirectoryObjects;
            ImportDirectoryObjects = importDirectoryObjects;
            JobMode = jobMode;
            MetadataRemaps = metadataRemaps;
        }
    }
}