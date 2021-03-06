// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationsMigrationCollectionItemDatapumpSetting {
    /**
     * @return Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
     * 
     */
    private final List<GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter> dataPumpParameters;
    /**
     * @return Directory object details, used to define either import or export directory objects in Data Pump Settings.
     * 
     */
    private final List<GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject> exportDirectoryObjects;
    /**
     * @return Directory object details, used to define either import or export directory objects in Data Pump Settings.
     * 
     */
    private final List<GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject> importDirectoryObjects;
    /**
     * @return Data Pump job mode. Refer to [Data Pump Export Modes ](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
     * 
     */
    private final String jobMode;
    /**
     * @return Defines remapping to be applied to objects as they are processed. Refer to [METADATA_REMAP Procedure ](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-0FC32790-91E6-4781-87A3-229DE024CB3D)
     * 
     */
    private final List<GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap> metadataRemaps;

    @CustomType.Constructor
    private GetMigrationsMigrationCollectionItemDatapumpSetting(
        @CustomType.Parameter("dataPumpParameters") List<GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter> dataPumpParameters,
        @CustomType.Parameter("exportDirectoryObjects") List<GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject> exportDirectoryObjects,
        @CustomType.Parameter("importDirectoryObjects") List<GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject> importDirectoryObjects,
        @CustomType.Parameter("jobMode") String jobMode,
        @CustomType.Parameter("metadataRemaps") List<GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap> metadataRemaps) {
        this.dataPumpParameters = dataPumpParameters;
        this.exportDirectoryObjects = exportDirectoryObjects;
        this.importDirectoryObjects = importDirectoryObjects;
        this.jobMode = jobMode;
        this.metadataRemaps = metadataRemaps;
    }

    /**
     * @return Optional parameters for Data Pump Export and Import. Refer to [Configuring Optional Initial Load Advanced Settings](https://docs.us.oracle.com/en/cloud/paas/database-migration/dmsus/working-migration-resources.html#GUID-24BD3054-FDF8-48FF-8492-636C1D4B71ED)
     * 
     */
    public List<GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter> dataPumpParameters() {
        return this.dataPumpParameters;
    }
    /**
     * @return Directory object details, used to define either import or export directory objects in Data Pump Settings.
     * 
     */
    public List<GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject> exportDirectoryObjects() {
        return this.exportDirectoryObjects;
    }
    /**
     * @return Directory object details, used to define either import or export directory objects in Data Pump Settings.
     * 
     */
    public List<GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject> importDirectoryObjects() {
        return this.importDirectoryObjects;
    }
    /**
     * @return Data Pump job mode. Refer to [Data Pump Export Modes ](https://docs.oracle.com/en/database/oracle/oracle-database/19/sutil/oracle-data-pump-export-utility.html#GUID-8E497131-6B9B-4CC8-AA50-35F480CAC2C4)
     * 
     */
    public String jobMode() {
        return this.jobMode;
    }
    /**
     * @return Defines remapping to be applied to objects as they are processed. Refer to [METADATA_REMAP Procedure ](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/DBMS_DATAPUMP.html#GUID-0FC32790-91E6-4781-87A3-229DE024CB3D)
     * 
     */
    public List<GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap> metadataRemaps() {
        return this.metadataRemaps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsMigrationCollectionItemDatapumpSetting defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter> dataPumpParameters;
        private List<GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject> exportDirectoryObjects;
        private List<GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject> importDirectoryObjects;
        private String jobMode;
        private List<GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap> metadataRemaps;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationsMigrationCollectionItemDatapumpSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataPumpParameters = defaults.dataPumpParameters;
    	      this.exportDirectoryObjects = defaults.exportDirectoryObjects;
    	      this.importDirectoryObjects = defaults.importDirectoryObjects;
    	      this.jobMode = defaults.jobMode;
    	      this.metadataRemaps = defaults.metadataRemaps;
        }

        public Builder dataPumpParameters(List<GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter> dataPumpParameters) {
            this.dataPumpParameters = Objects.requireNonNull(dataPumpParameters);
            return this;
        }
        public Builder dataPumpParameters(GetMigrationsMigrationCollectionItemDatapumpSettingDataPumpParameter... dataPumpParameters) {
            return dataPumpParameters(List.of(dataPumpParameters));
        }
        public Builder exportDirectoryObjects(List<GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject> exportDirectoryObjects) {
            this.exportDirectoryObjects = Objects.requireNonNull(exportDirectoryObjects);
            return this;
        }
        public Builder exportDirectoryObjects(GetMigrationsMigrationCollectionItemDatapumpSettingExportDirectoryObject... exportDirectoryObjects) {
            return exportDirectoryObjects(List.of(exportDirectoryObjects));
        }
        public Builder importDirectoryObjects(List<GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject> importDirectoryObjects) {
            this.importDirectoryObjects = Objects.requireNonNull(importDirectoryObjects);
            return this;
        }
        public Builder importDirectoryObjects(GetMigrationsMigrationCollectionItemDatapumpSettingImportDirectoryObject... importDirectoryObjects) {
            return importDirectoryObjects(List.of(importDirectoryObjects));
        }
        public Builder jobMode(String jobMode) {
            this.jobMode = Objects.requireNonNull(jobMode);
            return this;
        }
        public Builder metadataRemaps(List<GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap> metadataRemaps) {
            this.metadataRemaps = Objects.requireNonNull(metadataRemaps);
            return this;
        }
        public Builder metadataRemaps(GetMigrationsMigrationCollectionItemDatapumpSettingMetadataRemap... metadataRemaps) {
            return metadataRemaps(List.of(metadataRemaps));
        }        public GetMigrationsMigrationCollectionItemDatapumpSetting build() {
            return new GetMigrationsMigrationCollectionItemDatapumpSetting(dataPumpParameters, exportDirectoryObjects, importDirectoryObjects, jobMode, metadataRemaps);
        }
    }
}
