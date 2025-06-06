// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationInitialLoadSettingsDataPumpParameters;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationInitialLoadSettingsExportDirectoryObject;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationInitialLoadSettingsImportDirectoryObject;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationInitialLoadSettingsMetadataRemap;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationInitialLoadSettingsTablespaceDetails;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationInitialLoadSettings {
    /**
     * @return (Updatable) Apply the specified requirements for compatibility with MySQL Database Service for all tables in the dump  output, altering the dump files as necessary.
     * 
     */
    private @Nullable List<String> compatibilities;
    /**
     * @return (Updatable) Optional parameters for Data Pump Export and Import.
     * 
     */
    private @Nullable MigrationInitialLoadSettingsDataPumpParameters dataPumpParameters;
    /**
     * @return (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    private @Nullable MigrationInitialLoadSettingsExportDirectoryObject exportDirectoryObject;
    /**
     * @return (Updatable) The action taken in the event of errors related to GRANT or REVOKE errors.
     * 
     */
    private @Nullable String handleGrantErrors;
    /**
     * @return (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    private @Nullable MigrationInitialLoadSettingsImportDirectoryObject importDirectoryObject;
    /**
     * @return (Updatable) Enable (true) or disable (false) consistent data dumps by locking the instance for backup during the dump.
     * 
     */
    private @Nullable Boolean isConsistent;
    /**
     * @return (Updatable) Import the dump even if it contains objects that already exist in the target schema in the MySQL instance.
     * 
     */
    private @Nullable Boolean isIgnoreExistingObjects;
    /**
     * @return (Updatable) Include a statement at the start of the dump to set the time zone to UTC.
     * 
     */
    private @Nullable Boolean isTzUtc;
    /**
     * @return (Updatable) Oracle Job Mode
     * 
     */
    private String jobMode;
    /**
     * @return (Updatable) Defines remapping to be applied to objects as they are processed.
     * 
     */
    private @Nullable List<MigrationInitialLoadSettingsMetadataRemap> metadataRemaps;
    /**
     * @return (Updatable) Primary key compatibility option
     * 
     */
    private @Nullable String primaryKeyCompatibility;
    /**
     * @return (Updatable) Migration tablespace settings.
     * 
     */
    private @Nullable MigrationInitialLoadSettingsTablespaceDetails tablespaceDetails;

    private MigrationInitialLoadSettings() {}
    /**
     * @return (Updatable) Apply the specified requirements for compatibility with MySQL Database Service for all tables in the dump  output, altering the dump files as necessary.
     * 
     */
    public List<String> compatibilities() {
        return this.compatibilities == null ? List.of() : this.compatibilities;
    }
    /**
     * @return (Updatable) Optional parameters for Data Pump Export and Import.
     * 
     */
    public Optional<MigrationInitialLoadSettingsDataPumpParameters> dataPumpParameters() {
        return Optional.ofNullable(this.dataPumpParameters);
    }
    /**
     * @return (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    public Optional<MigrationInitialLoadSettingsExportDirectoryObject> exportDirectoryObject() {
        return Optional.ofNullable(this.exportDirectoryObject);
    }
    /**
     * @return (Updatable) The action taken in the event of errors related to GRANT or REVOKE errors.
     * 
     */
    public Optional<String> handleGrantErrors() {
        return Optional.ofNullable(this.handleGrantErrors);
    }
    /**
     * @return (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
     * 
     */
    public Optional<MigrationInitialLoadSettingsImportDirectoryObject> importDirectoryObject() {
        return Optional.ofNullable(this.importDirectoryObject);
    }
    /**
     * @return (Updatable) Enable (true) or disable (false) consistent data dumps by locking the instance for backup during the dump.
     * 
     */
    public Optional<Boolean> isConsistent() {
        return Optional.ofNullable(this.isConsistent);
    }
    /**
     * @return (Updatable) Import the dump even if it contains objects that already exist in the target schema in the MySQL instance.
     * 
     */
    public Optional<Boolean> isIgnoreExistingObjects() {
        return Optional.ofNullable(this.isIgnoreExistingObjects);
    }
    /**
     * @return (Updatable) Include a statement at the start of the dump to set the time zone to UTC.
     * 
     */
    public Optional<Boolean> isTzUtc() {
        return Optional.ofNullable(this.isTzUtc);
    }
    /**
     * @return (Updatable) Oracle Job Mode
     * 
     */
    public String jobMode() {
        return this.jobMode;
    }
    /**
     * @return (Updatable) Defines remapping to be applied to objects as they are processed.
     * 
     */
    public List<MigrationInitialLoadSettingsMetadataRemap> metadataRemaps() {
        return this.metadataRemaps == null ? List.of() : this.metadataRemaps;
    }
    /**
     * @return (Updatable) Primary key compatibility option
     * 
     */
    public Optional<String> primaryKeyCompatibility() {
        return Optional.ofNullable(this.primaryKeyCompatibility);
    }
    /**
     * @return (Updatable) Migration tablespace settings.
     * 
     */
    public Optional<MigrationInitialLoadSettingsTablespaceDetails> tablespaceDetails() {
        return Optional.ofNullable(this.tablespaceDetails);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationInitialLoadSettings defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> compatibilities;
        private @Nullable MigrationInitialLoadSettingsDataPumpParameters dataPumpParameters;
        private @Nullable MigrationInitialLoadSettingsExportDirectoryObject exportDirectoryObject;
        private @Nullable String handleGrantErrors;
        private @Nullable MigrationInitialLoadSettingsImportDirectoryObject importDirectoryObject;
        private @Nullable Boolean isConsistent;
        private @Nullable Boolean isIgnoreExistingObjects;
        private @Nullable Boolean isTzUtc;
        private String jobMode;
        private @Nullable List<MigrationInitialLoadSettingsMetadataRemap> metadataRemaps;
        private @Nullable String primaryKeyCompatibility;
        private @Nullable MigrationInitialLoadSettingsTablespaceDetails tablespaceDetails;
        public Builder() {}
        public Builder(MigrationInitialLoadSettings defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compatibilities = defaults.compatibilities;
    	      this.dataPumpParameters = defaults.dataPumpParameters;
    	      this.exportDirectoryObject = defaults.exportDirectoryObject;
    	      this.handleGrantErrors = defaults.handleGrantErrors;
    	      this.importDirectoryObject = defaults.importDirectoryObject;
    	      this.isConsistent = defaults.isConsistent;
    	      this.isIgnoreExistingObjects = defaults.isIgnoreExistingObjects;
    	      this.isTzUtc = defaults.isTzUtc;
    	      this.jobMode = defaults.jobMode;
    	      this.metadataRemaps = defaults.metadataRemaps;
    	      this.primaryKeyCompatibility = defaults.primaryKeyCompatibility;
    	      this.tablespaceDetails = defaults.tablespaceDetails;
        }

        @CustomType.Setter
        public Builder compatibilities(@Nullable List<String> compatibilities) {

            this.compatibilities = compatibilities;
            return this;
        }
        public Builder compatibilities(String... compatibilities) {
            return compatibilities(List.of(compatibilities));
        }
        @CustomType.Setter
        public Builder dataPumpParameters(@Nullable MigrationInitialLoadSettingsDataPumpParameters dataPumpParameters) {

            this.dataPumpParameters = dataPumpParameters;
            return this;
        }
        @CustomType.Setter
        public Builder exportDirectoryObject(@Nullable MigrationInitialLoadSettingsExportDirectoryObject exportDirectoryObject) {

            this.exportDirectoryObject = exportDirectoryObject;
            return this;
        }
        @CustomType.Setter
        public Builder handleGrantErrors(@Nullable String handleGrantErrors) {

            this.handleGrantErrors = handleGrantErrors;
            return this;
        }
        @CustomType.Setter
        public Builder importDirectoryObject(@Nullable MigrationInitialLoadSettingsImportDirectoryObject importDirectoryObject) {

            this.importDirectoryObject = importDirectoryObject;
            return this;
        }
        @CustomType.Setter
        public Builder isConsistent(@Nullable Boolean isConsistent) {

            this.isConsistent = isConsistent;
            return this;
        }
        @CustomType.Setter
        public Builder isIgnoreExistingObjects(@Nullable Boolean isIgnoreExistingObjects) {

            this.isIgnoreExistingObjects = isIgnoreExistingObjects;
            return this;
        }
        @CustomType.Setter
        public Builder isTzUtc(@Nullable Boolean isTzUtc) {

            this.isTzUtc = isTzUtc;
            return this;
        }
        @CustomType.Setter
        public Builder jobMode(String jobMode) {
            if (jobMode == null) {
              throw new MissingRequiredPropertyException("MigrationInitialLoadSettings", "jobMode");
            }
            this.jobMode = jobMode;
            return this;
        }
        @CustomType.Setter
        public Builder metadataRemaps(@Nullable List<MigrationInitialLoadSettingsMetadataRemap> metadataRemaps) {

            this.metadataRemaps = metadataRemaps;
            return this;
        }
        public Builder metadataRemaps(MigrationInitialLoadSettingsMetadataRemap... metadataRemaps) {
            return metadataRemaps(List.of(metadataRemaps));
        }
        @CustomType.Setter
        public Builder primaryKeyCompatibility(@Nullable String primaryKeyCompatibility) {

            this.primaryKeyCompatibility = primaryKeyCompatibility;
            return this;
        }
        @CustomType.Setter
        public Builder tablespaceDetails(@Nullable MigrationInitialLoadSettingsTablespaceDetails tablespaceDetails) {

            this.tablespaceDetails = tablespaceDetails;
            return this;
        }
        public MigrationInitialLoadSettings build() {
            final var _resultValue = new MigrationInitialLoadSettings();
            _resultValue.compatibilities = compatibilities;
            _resultValue.dataPumpParameters = dataPumpParameters;
            _resultValue.exportDirectoryObject = exportDirectoryObject;
            _resultValue.handleGrantErrors = handleGrantErrors;
            _resultValue.importDirectoryObject = importDirectoryObject;
            _resultValue.isConsistent = isConsistent;
            _resultValue.isIgnoreExistingObjects = isIgnoreExistingObjects;
            _resultValue.isTzUtc = isTzUtc;
            _resultValue.jobMode = jobMode;
            _resultValue.metadataRemaps = metadataRemaps;
            _resultValue.primaryKeyCompatibility = primaryKeyCompatibility;
            _resultValue.tablespaceDetails = tablespaceDetails;
            return _resultValue;
        }
    }
}
