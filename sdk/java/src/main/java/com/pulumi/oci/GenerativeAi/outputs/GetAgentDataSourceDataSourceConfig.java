// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.outputs.GetAgentDataSourceDataSourceConfigObjectStoragePrefix;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAgentDataSourceDataSourceConfig {
    /**
     * @return The type of the tool. The allowed values are:
     * * `OCI_OBJECT_STORAGE`: The data source is Oracle Cloud Infrastructure Object Storage.
     * 
     */
    private String dataSourceConfigType;
    /**
     * @return The locations of data items in Object Storage, can either be an object (File) or a prefix (folder).
     * 
     */
    private List<GetAgentDataSourceDataSourceConfigObjectStoragePrefix> objectStoragePrefixes;

    private GetAgentDataSourceDataSourceConfig() {}
    /**
     * @return The type of the tool. The allowed values are:
     * * `OCI_OBJECT_STORAGE`: The data source is Oracle Cloud Infrastructure Object Storage.
     * 
     */
    public String dataSourceConfigType() {
        return this.dataSourceConfigType;
    }
    /**
     * @return The locations of data items in Object Storage, can either be an object (File) or a prefix (folder).
     * 
     */
    public List<GetAgentDataSourceDataSourceConfigObjectStoragePrefix> objectStoragePrefixes() {
        return this.objectStoragePrefixes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentDataSourceDataSourceConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dataSourceConfigType;
        private List<GetAgentDataSourceDataSourceConfigObjectStoragePrefix> objectStoragePrefixes;
        public Builder() {}
        public Builder(GetAgentDataSourceDataSourceConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataSourceConfigType = defaults.dataSourceConfigType;
    	      this.objectStoragePrefixes = defaults.objectStoragePrefixes;
        }

        @CustomType.Setter
        public Builder dataSourceConfigType(String dataSourceConfigType) {
            if (dataSourceConfigType == null) {
              throw new MissingRequiredPropertyException("GetAgentDataSourceDataSourceConfig", "dataSourceConfigType");
            }
            this.dataSourceConfigType = dataSourceConfigType;
            return this;
        }
        @CustomType.Setter
        public Builder objectStoragePrefixes(List<GetAgentDataSourceDataSourceConfigObjectStoragePrefix> objectStoragePrefixes) {
            if (objectStoragePrefixes == null) {
              throw new MissingRequiredPropertyException("GetAgentDataSourceDataSourceConfig", "objectStoragePrefixes");
            }
            this.objectStoragePrefixes = objectStoragePrefixes;
            return this;
        }
        public Builder objectStoragePrefixes(GetAgentDataSourceDataSourceConfigObjectStoragePrefix... objectStoragePrefixes) {
            return objectStoragePrefixes(List.of(objectStoragePrefixes));
        }
        public GetAgentDataSourceDataSourceConfig build() {
            final var _resultValue = new GetAgentDataSourceDataSourceConfig();
            _resultValue.dataSourceConfigType = dataSourceConfigType;
            _resultValue.objectStoragePrefixes = objectStoragePrefixes;
            return _resultValue;
        }
    }
}
