// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroup {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The identifier of the resource.
     * 
     */
    private String id;
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    private String name;

    private GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroup() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The identifier of the resource.
     * 
     */
    public String id() {
        return this.id;
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

    public static Builder builder(GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String id;
        private String name;
        public Builder() {}
        public Builder(GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroup build() {
            final var o = new GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroup();
            o.compartmentId = compartmentId;
            o.id = id;
            o.name = name;
            return o;
        }
    }
}