// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemDataStorage {
    /**
     * @return The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
     * 
     */
    private Integer allocatedStorageSizeInGbs;
    /**
     * @return Initial size of the data volume in GiBs that will be created and attached.
     * 
     */
    private Integer dataStorageSizeInGb;
    /**
     * @return The absolute limit the DB System&#39;s storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
     * 
     */
    private Integer dataStorageSizeLimitInGbs;
    /**
     * @return Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
     * 
     */
    private Boolean isAutoExpandStorageEnabled;
    /**
     * @return Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
     * 
     */
    private Integer maxStorageSizeInGbs;

    private GetMysqlDbSystemDataStorage() {}
    /**
     * @return The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
     * 
     */
    public Integer allocatedStorageSizeInGbs() {
        return this.allocatedStorageSizeInGbs;
    }
    /**
     * @return Initial size of the data volume in GiBs that will be created and attached.
     * 
     */
    public Integer dataStorageSizeInGb() {
        return this.dataStorageSizeInGb;
    }
    /**
     * @return The absolute limit the DB System&#39;s storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
     * 
     */
    public Integer dataStorageSizeLimitInGbs() {
        return this.dataStorageSizeLimitInGbs;
    }
    /**
     * @return Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
     * 
     */
    public Boolean isAutoExpandStorageEnabled() {
        return this.isAutoExpandStorageEnabled;
    }
    /**
     * @return Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
     * 
     */
    public Integer maxStorageSizeInGbs() {
        return this.maxStorageSizeInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemDataStorage defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer allocatedStorageSizeInGbs;
        private Integer dataStorageSizeInGb;
        private Integer dataStorageSizeLimitInGbs;
        private Boolean isAutoExpandStorageEnabled;
        private Integer maxStorageSizeInGbs;
        public Builder() {}
        public Builder(GetMysqlDbSystemDataStorage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allocatedStorageSizeInGbs = defaults.allocatedStorageSizeInGbs;
    	      this.dataStorageSizeInGb = defaults.dataStorageSizeInGb;
    	      this.dataStorageSizeLimitInGbs = defaults.dataStorageSizeLimitInGbs;
    	      this.isAutoExpandStorageEnabled = defaults.isAutoExpandStorageEnabled;
    	      this.maxStorageSizeInGbs = defaults.maxStorageSizeInGbs;
        }

        @CustomType.Setter
        public Builder allocatedStorageSizeInGbs(Integer allocatedStorageSizeInGbs) {
            if (allocatedStorageSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemDataStorage", "allocatedStorageSizeInGbs");
            }
            this.allocatedStorageSizeInGbs = allocatedStorageSizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder dataStorageSizeInGb(Integer dataStorageSizeInGb) {
            if (dataStorageSizeInGb == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemDataStorage", "dataStorageSizeInGb");
            }
            this.dataStorageSizeInGb = dataStorageSizeInGb;
            return this;
        }
        @CustomType.Setter
        public Builder dataStorageSizeLimitInGbs(Integer dataStorageSizeLimitInGbs) {
            if (dataStorageSizeLimitInGbs == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemDataStorage", "dataStorageSizeLimitInGbs");
            }
            this.dataStorageSizeLimitInGbs = dataStorageSizeLimitInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder isAutoExpandStorageEnabled(Boolean isAutoExpandStorageEnabled) {
            if (isAutoExpandStorageEnabled == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemDataStorage", "isAutoExpandStorageEnabled");
            }
            this.isAutoExpandStorageEnabled = isAutoExpandStorageEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder maxStorageSizeInGbs(Integer maxStorageSizeInGbs) {
            if (maxStorageSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemDataStorage", "maxStorageSizeInGbs");
            }
            this.maxStorageSizeInGbs = maxStorageSizeInGbs;
            return this;
        }
        public GetMysqlDbSystemDataStorage build() {
            final var _resultValue = new GetMysqlDbSystemDataStorage();
            _resultValue.allocatedStorageSizeInGbs = allocatedStorageSizeInGbs;
            _resultValue.dataStorageSizeInGb = dataStorageSizeInGb;
            _resultValue.dataStorageSizeLimitInGbs = dataStorageSizeLimitInGbs;
            _resultValue.isAutoExpandStorageEnabled = isAutoExpandStorageEnabled;
            _resultValue.maxStorageSizeInGbs = maxStorageSizeInGbs;
            return _resultValue;
        }
    }
}
