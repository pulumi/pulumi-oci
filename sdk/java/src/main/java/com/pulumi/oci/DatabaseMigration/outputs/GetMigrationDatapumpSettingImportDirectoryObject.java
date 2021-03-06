// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationDatapumpSettingImportDirectoryObject {
    /**
     * @return Name of directory object in database
     * 
     */
    private final String name;
    /**
     * @return Absolute path of directory on database server
     * 
     */
    private final String path;

    @CustomType.Constructor
    private GetMigrationDatapumpSettingImportDirectoryObject(
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("path") String path) {
        this.name = name;
        this.path = path;
    }

    /**
     * @return Name of directory object in database
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Absolute path of directory on database server
     * 
     */
    public String path() {
        return this.path;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationDatapumpSettingImportDirectoryObject defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String name;
        private String path;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationDatapumpSettingImportDirectoryObject defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.path = defaults.path;
        }

        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder path(String path) {
            this.path = Objects.requireNonNull(path);
            return this;
        }        public GetMigrationDatapumpSettingImportDirectoryObject build() {
            return new GetMigrationDatapumpSettingImportDirectoryObject(name, path);
        }
    }
}
