// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataLabellingService.outputs.DatasetInitialImportDatasetConfigurationImportFormat;
import com.pulumi.oci.DataLabellingService.outputs.DatasetInitialImportDatasetConfigurationImportMetadataPath;
import java.util.Objects;

@CustomType
public final class DatasetInitialImportDatasetConfiguration {
    /**
     * @return File format details used for importing dataset
     * 
     */
    private DatasetInitialImportDatasetConfigurationImportFormat importFormat;
    /**
     * @return Object storage path for the metadata file
     * 
     */
    private DatasetInitialImportDatasetConfigurationImportMetadataPath importMetadataPath;

    private DatasetInitialImportDatasetConfiguration() {}
    /**
     * @return File format details used for importing dataset
     * 
     */
    public DatasetInitialImportDatasetConfigurationImportFormat importFormat() {
        return this.importFormat;
    }
    /**
     * @return Object storage path for the metadata file
     * 
     */
    public DatasetInitialImportDatasetConfigurationImportMetadataPath importMetadataPath() {
        return this.importMetadataPath;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DatasetInitialImportDatasetConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private DatasetInitialImportDatasetConfigurationImportFormat importFormat;
        private DatasetInitialImportDatasetConfigurationImportMetadataPath importMetadataPath;
        public Builder() {}
        public Builder(DatasetInitialImportDatasetConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.importFormat = defaults.importFormat;
    	      this.importMetadataPath = defaults.importMetadataPath;
        }

        @CustomType.Setter
        public Builder importFormat(DatasetInitialImportDatasetConfigurationImportFormat importFormat) {
            if (importFormat == null) {
              throw new MissingRequiredPropertyException("DatasetInitialImportDatasetConfiguration", "importFormat");
            }
            this.importFormat = importFormat;
            return this;
        }
        @CustomType.Setter
        public Builder importMetadataPath(DatasetInitialImportDatasetConfigurationImportMetadataPath importMetadataPath) {
            if (importMetadataPath == null) {
              throw new MissingRequiredPropertyException("DatasetInitialImportDatasetConfiguration", "importMetadataPath");
            }
            this.importMetadataPath = importMetadataPath;
            return this;
        }
        public DatasetInitialImportDatasetConfiguration build() {
            final var _resultValue = new DatasetInitialImportDatasetConfiguration();
            _resultValue.importFormat = importFormat;
            _resultValue.importMetadataPath = importMetadataPath;
            return _resultValue;
        }
    }
}
