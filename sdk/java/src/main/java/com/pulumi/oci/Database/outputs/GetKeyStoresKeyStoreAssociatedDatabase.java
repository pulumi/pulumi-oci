// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetKeyStoresKeyStoreAssociatedDatabase {
    /**
     * @return The name of the database that is associated with the key store.
     * 
     */
    private String dbName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     * 
     */
    private String id;

    private GetKeyStoresKeyStoreAssociatedDatabase() {}
    /**
     * @return The name of the database that is associated with the key store.
     * 
     */
    public String dbName() {
        return this.dbName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeyStoresKeyStoreAssociatedDatabase defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dbName;
        private String id;
        public Builder() {}
        public Builder(GetKeyStoresKeyStoreAssociatedDatabase defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbName = defaults.dbName;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder dbName(String dbName) {
            if (dbName == null) {
              throw new MissingRequiredPropertyException("GetKeyStoresKeyStoreAssociatedDatabase", "dbName");
            }
            this.dbName = dbName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetKeyStoresKeyStoreAssociatedDatabase", "id");
            }
            this.id = id;
            return this;
        }
        public GetKeyStoresKeyStoreAssociatedDatabase build() {
            final var _resultValue = new GetKeyStoresKeyStoreAssociatedDatabase();
            _resultValue.dbName = dbName;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
