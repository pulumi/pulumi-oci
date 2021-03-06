// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesDatabaseParametersDatabaseParametersCollection {
    /**
     * @return The name of the Managed Database.
     * 
     */
    private final String databaseName;
    /**
     * @return The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, or a Non-container Database.
     * 
     */
    private final String databaseSubType;
    /**
     * @return The type of Oracle Database installation.
     * 
     */
    private final String databaseType;
    /**
     * @return The Oracle Database version.
     * 
     */
    private final String databaseVersion;
    /**
     * @return An array of DatabaseParameterSummary objects.
     * 
     */
    private final List<GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem> items;

    @CustomType.Constructor
    private GetManagedDatabasesDatabaseParametersDatabaseParametersCollection(
        @CustomType.Parameter("databaseName") String databaseName,
        @CustomType.Parameter("databaseSubType") String databaseSubType,
        @CustomType.Parameter("databaseType") String databaseType,
        @CustomType.Parameter("databaseVersion") String databaseVersion,
        @CustomType.Parameter("items") List<GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem> items) {
        this.databaseName = databaseName;
        this.databaseSubType = databaseSubType;
        this.databaseType = databaseType;
        this.databaseVersion = databaseVersion;
        this.items = items;
    }

    /**
     * @return The name of the Managed Database.
     * 
     */
    public String databaseName() {
        return this.databaseName;
    }
    /**
     * @return The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, or a Non-container Database.
     * 
     */
    public String databaseSubType() {
        return this.databaseSubType;
    }
    /**
     * @return The type of Oracle Database installation.
     * 
     */
    public String databaseType() {
        return this.databaseType;
    }
    /**
     * @return The Oracle Database version.
     * 
     */
    public String databaseVersion() {
        return this.databaseVersion;
    }
    /**
     * @return An array of DatabaseParameterSummary objects.
     * 
     */
    public List<GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesDatabaseParametersDatabaseParametersCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String databaseName;
        private String databaseSubType;
        private String databaseType;
        private String databaseVersion;
        private List<GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabasesDatabaseParametersDatabaseParametersCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseName = defaults.databaseName;
    	      this.databaseSubType = defaults.databaseSubType;
    	      this.databaseType = defaults.databaseType;
    	      this.databaseVersion = defaults.databaseVersion;
    	      this.items = defaults.items;
        }

        public Builder databaseName(String databaseName) {
            this.databaseName = Objects.requireNonNull(databaseName);
            return this;
        }
        public Builder databaseSubType(String databaseSubType) {
            this.databaseSubType = Objects.requireNonNull(databaseSubType);
            return this;
        }
        public Builder databaseType(String databaseType) {
            this.databaseType = Objects.requireNonNull(databaseType);
            return this;
        }
        public Builder databaseVersion(String databaseVersion) {
            this.databaseVersion = Objects.requireNonNull(databaseVersion);
            return this;
        }
        public Builder items(List<GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagedDatabasesDatabaseParametersDatabaseParametersCollectionItem... items) {
            return items(List.of(items));
        }        public GetManagedDatabasesDatabaseParametersDatabaseParametersCollection build() {
            return new GetManagedDatabasesDatabaseParametersDatabaseParametersCollection(databaseName, databaseSubType, databaseType, databaseVersion, items);
        }
    }
}
