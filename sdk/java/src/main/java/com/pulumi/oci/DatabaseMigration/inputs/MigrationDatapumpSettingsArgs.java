// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDatapumpSettingsDataPumpParametersArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDatapumpSettingsExportDirectoryObjectArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDatapumpSettingsImportDirectoryObjectArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDatapumpSettingsMetadataRemapArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationDatapumpSettingsArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationDatapumpSettingsArgs Empty = new MigrationDatapumpSettingsArgs();

    /**
     * (Updatable) Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
     * 
     */
    @Import(name="dataPumpParameters")
    private @Nullable Output<MigrationDatapumpSettingsDataPumpParametersArgs> dataPumpParameters;

    /**
     * @return (Updatable) Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
     * 
     */
    public Optional<Output<MigrationDatapumpSettingsDataPumpParametersArgs>> dataPumpParameters() {
        return Optional.ofNullable(this.dataPumpParameters);
    }

    /**
     * (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    @Import(name="exportDirectoryObject")
    private @Nullable Output<MigrationDatapumpSettingsExportDirectoryObjectArgs> exportDirectoryObject;

    /**
     * @return (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    public Optional<Output<MigrationDatapumpSettingsExportDirectoryObjectArgs>> exportDirectoryObject() {
        return Optional.ofNullable(this.exportDirectoryObject);
    }

    /**
     * (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    @Import(name="importDirectoryObject")
    private @Nullable Output<MigrationDatapumpSettingsImportDirectoryObjectArgs> importDirectoryObject;

    /**
     * @return (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    public Optional<Output<MigrationDatapumpSettingsImportDirectoryObjectArgs>> importDirectoryObject() {
        return Optional.ofNullable(this.importDirectoryObject);
    }

    /**
     * (Updatable) Data Pump job mode. Refer to [link text](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
     * 
     */
    @Import(name="jobMode")
    private @Nullable Output<String> jobMode;

    /**
     * @return (Updatable) Data Pump job mode. Refer to [link text](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
     * 
     */
    public Optional<Output<String>> jobMode() {
        return Optional.ofNullable(this.jobMode);
    }

    /**
     * (Updatable) Defines remapping to be applied to objects as they are processed. Refer to [DATA_REMAP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-E75AAE6F-4EA6-4737-A752-6B62F5E9D460)
     * 
     */
    @Import(name="metadataRemaps")
    private @Nullable Output<List<MigrationDatapumpSettingsMetadataRemapArgs>> metadataRemaps;

    /**
     * @return (Updatable) Defines remapping to be applied to objects as they are processed. Refer to [DATA_REMAP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-E75AAE6F-4EA6-4737-A752-6B62F5E9D460)
     * 
     */
    public Optional<Output<List<MigrationDatapumpSettingsMetadataRemapArgs>>> metadataRemaps() {
        return Optional.ofNullable(this.metadataRemaps);
    }

    private MigrationDatapumpSettingsArgs() {}

    private MigrationDatapumpSettingsArgs(MigrationDatapumpSettingsArgs $) {
        this.dataPumpParameters = $.dataPumpParameters;
        this.exportDirectoryObject = $.exportDirectoryObject;
        this.importDirectoryObject = $.importDirectoryObject;
        this.jobMode = $.jobMode;
        this.metadataRemaps = $.metadataRemaps;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationDatapumpSettingsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationDatapumpSettingsArgs $;

        public Builder() {
            $ = new MigrationDatapumpSettingsArgs();
        }

        public Builder(MigrationDatapumpSettingsArgs defaults) {
            $ = new MigrationDatapumpSettingsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataPumpParameters (Updatable) Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
         * 
         * @return builder
         * 
         */
        public Builder dataPumpParameters(@Nullable Output<MigrationDatapumpSettingsDataPumpParametersArgs> dataPumpParameters) {
            $.dataPumpParameters = dataPumpParameters;
            return this;
        }

        /**
         * @param dataPumpParameters (Updatable) Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
         * 
         * @return builder
         * 
         */
        public Builder dataPumpParameters(MigrationDatapumpSettingsDataPumpParametersArgs dataPumpParameters) {
            return dataPumpParameters(Output.of(dataPumpParameters));
        }

        /**
         * @param exportDirectoryObject (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
         * 
         * @return builder
         * 
         */
        public Builder exportDirectoryObject(@Nullable Output<MigrationDatapumpSettingsExportDirectoryObjectArgs> exportDirectoryObject) {
            $.exportDirectoryObject = exportDirectoryObject;
            return this;
        }

        /**
         * @param exportDirectoryObject (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
         * 
         * @return builder
         * 
         */
        public Builder exportDirectoryObject(MigrationDatapumpSettingsExportDirectoryObjectArgs exportDirectoryObject) {
            return exportDirectoryObject(Output.of(exportDirectoryObject));
        }

        /**
         * @param importDirectoryObject (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
         * 
         * @return builder
         * 
         */
        public Builder importDirectoryObject(@Nullable Output<MigrationDatapumpSettingsImportDirectoryObjectArgs> importDirectoryObject) {
            $.importDirectoryObject = importDirectoryObject;
            return this;
        }

        /**
         * @param importDirectoryObject (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
         * 
         * @return builder
         * 
         */
        public Builder importDirectoryObject(MigrationDatapumpSettingsImportDirectoryObjectArgs importDirectoryObject) {
            return importDirectoryObject(Output.of(importDirectoryObject));
        }

        /**
         * @param jobMode (Updatable) Data Pump job mode. Refer to [link text](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
         * 
         * @return builder
         * 
         */
        public Builder jobMode(@Nullable Output<String> jobMode) {
            $.jobMode = jobMode;
            return this;
        }

        /**
         * @param jobMode (Updatable) Data Pump job mode. Refer to [link text](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
         * 
         * @return builder
         * 
         */
        public Builder jobMode(String jobMode) {
            return jobMode(Output.of(jobMode));
        }

        /**
         * @param metadataRemaps (Updatable) Defines remapping to be applied to objects as they are processed. Refer to [DATA_REMAP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-E75AAE6F-4EA6-4737-A752-6B62F5E9D460)
         * 
         * @return builder
         * 
         */
        public Builder metadataRemaps(@Nullable Output<List<MigrationDatapumpSettingsMetadataRemapArgs>> metadataRemaps) {
            $.metadataRemaps = metadataRemaps;
            return this;
        }

        /**
         * @param metadataRemaps (Updatable) Defines remapping to be applied to objects as they are processed. Refer to [DATA_REMAP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-E75AAE6F-4EA6-4737-A752-6B62F5E9D460)
         * 
         * @return builder
         * 
         */
        public Builder metadataRemaps(List<MigrationDatapumpSettingsMetadataRemapArgs> metadataRemaps) {
            return metadataRemaps(Output.of(metadataRemaps));
        }

        /**
         * @param metadataRemaps (Updatable) Defines remapping to be applied to objects as they are processed. Refer to [DATA_REMAP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-E75AAE6F-4EA6-4737-A752-6B62F5E9D460)
         * 
         * @return builder
         * 
         */
        public Builder metadataRemaps(MigrationDatapumpSettingsMetadataRemapArgs... metadataRemaps) {
            return metadataRemaps(List.of(metadataRemaps));
        }

        public MigrationDatapumpSettingsArgs build() {
            return $;
        }
    }

}
