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
    public sealed class GetMigrationsInitialLoadSettingTablespaceDetailResult
    {
        /// <summary>
        /// Size of Oracle database blocks in KB.
        /// </summary>
        public readonly string BlockSizeInKbs;
        /// <summary>
        /// Size to extend the tablespace in MB.  Note: Only applicable if 'isBigFile' property is set to true.
        /// </summary>
        public readonly int ExtendSizeInMbs;
        /// <summary>
        /// Set this property to true to auto-create tablespaces in the target Database. Note: This is not applicable for Autonomous Database Serverless databases.
        /// </summary>
        public readonly bool IsAutoCreate;
        /// <summary>
        /// Set this property to true to enable tablespace of the type big file.
        /// </summary>
        public readonly bool IsBigFile;
        /// <summary>
        /// Name of the tablespace on the target database to which the source database tablespace is to be remapped.
        /// </summary>
        public readonly string RemapTarget;
        /// <summary>
        /// Type of Database Base Migration Target.
        /// </summary>
        public readonly string TargetType;

        [OutputConstructor]
        private GetMigrationsInitialLoadSettingTablespaceDetailResult(
            string blockSizeInKbs,

            int extendSizeInMbs,

            bool isAutoCreate,

            bool isBigFile,

            string remapTarget,

            string targetType)
        {
            BlockSizeInKbs = blockSizeInKbs;
            ExtendSizeInMbs = extendSizeInMbs;
            IsAutoCreate = isAutoCreate;
            IsBigFile = isBigFile;
            RemapTarget = remapTarget;
            TargetType = targetType;
        }
    }
}
