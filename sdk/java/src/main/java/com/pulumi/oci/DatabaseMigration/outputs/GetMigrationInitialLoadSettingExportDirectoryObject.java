// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationInitialLoadSettingExportDirectoryObject {
    /**
     * @return Name of directory object in database
     * 
     */
    private String name;
    /**
     * @return Absolute path of directory on database server
     * 
     */
    private String path;

    private GetMigrationInitialLoadSettingExportDirectoryObject() {}
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

    public static Builder builder(GetMigrationInitialLoadSettingExportDirectoryObject defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String path;
        public Builder() {}
        public Builder(GetMigrationInitialLoadSettingExportDirectoryObject defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.path = defaults.path;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetMigrationInitialLoadSettingExportDirectoryObject", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetMigrationInitialLoadSettingExportDirectoryObject", "path");
            }
            this.path = path;
            return this;
        }
        public GetMigrationInitialLoadSettingExportDirectoryObject build() {
            final var _resultValue = new GetMigrationInitialLoadSettingExportDirectoryObject();
            _resultValue.name = name;
            _resultValue.path = path;
            return _resultValue;
        }
    }
}
