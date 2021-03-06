// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseUserDataAccessContainersDataAccessContainerCollectionItem {
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    private final String name;

    @CustomType.Constructor
    private GetManagedDatabaseUserDataAccessContainersDataAccessContainerCollectionItem(@CustomType.Parameter("name") String name) {
        this.name = name;
    }

    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseUserDataAccessContainersDataAccessContainerCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabaseUserDataAccessContainersDataAccessContainerCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }        public GetManagedDatabaseUserDataAccessContainersDataAccessContainerCollectionItem build() {
            return new GetManagedDatabaseUserDataAccessContainersDataAccessContainerCollectionItem(name);
        }
    }
}
