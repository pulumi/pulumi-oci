// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseUserObjectPrivilegesFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabaseUserObjectPrivilegesResult {
    private @Nullable List<GetManagedDatabaseUserObjectPrivilegesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedDatabaseId;
    /**
     * @return The name of the privilege on the object.
     * 
     */
    private @Nullable String name;
    /**
     * @return The list of object_privilege_collection.
     * 
     */
    private List<GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection> objectPrivilegeCollections;
    private String userName;

    private GetManagedDatabaseUserObjectPrivilegesResult() {}
    public List<GetManagedDatabaseUserObjectPrivilegesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * @return The name of the privilege on the object.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The list of object_privilege_collection.
     * 
     */
    public List<GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection> objectPrivilegeCollections() {
        return this.objectPrivilegeCollections;
    }
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseUserObjectPrivilegesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetManagedDatabaseUserObjectPrivilegesFilter> filters;
        private String id;
        private String managedDatabaseId;
        private @Nullable String name;
        private List<GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection> objectPrivilegeCollections;
        private String userName;
        public Builder() {}
        public Builder(GetManagedDatabaseUserObjectPrivilegesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.name = defaults.name;
    	      this.objectPrivilegeCollections = defaults.objectPrivilegeCollections;
    	      this.userName = defaults.userName;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedDatabaseUserObjectPrivilegesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedDatabaseUserObjectPrivilegesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder objectPrivilegeCollections(List<GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection> objectPrivilegeCollections) {
            this.objectPrivilegeCollections = Objects.requireNonNull(objectPrivilegeCollections);
            return this;
        }
        public Builder objectPrivilegeCollections(GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection... objectPrivilegeCollections) {
            return objectPrivilegeCollections(List.of(objectPrivilegeCollections));
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }
        public GetManagedDatabaseUserObjectPrivilegesResult build() {
            final var o = new GetManagedDatabaseUserObjectPrivilegesResult();
            o.filters = filters;
            o.id = id;
            o.managedDatabaseId = managedDatabaseId;
            o.name = name;
            o.objectPrivilegeCollections = objectPrivilegeCollections;
            o.userName = userName;
            return o;
        }
    }
}