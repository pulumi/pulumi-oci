// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesUserSystemPrivilegesFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabasesUserSystemPrivilegesResult {
    private @Nullable List<GetManagedDatabasesUserSystemPrivilegesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedDatabaseId;
    /**
     * @return The name of a system privilege.
     * 
     */
    private @Nullable String name;
    private @Nullable String opcNamedCredentialId;
    /**
     * @return The list of system_privilege_collection.
     * 
     */
    private List<GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollection> systemPrivilegeCollections;
    private String userName;

    private GetManagedDatabasesUserSystemPrivilegesResult() {}
    public List<GetManagedDatabasesUserSystemPrivilegesFilter> filters() {
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
     * @return The name of a system privilege.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> opcNamedCredentialId() {
        return Optional.ofNullable(this.opcNamedCredentialId);
    }
    /**
     * @return The list of system_privilege_collection.
     * 
     */
    public List<GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollection> systemPrivilegeCollections() {
        return this.systemPrivilegeCollections;
    }
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesUserSystemPrivilegesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetManagedDatabasesUserSystemPrivilegesFilter> filters;
        private String id;
        private String managedDatabaseId;
        private @Nullable String name;
        private @Nullable String opcNamedCredentialId;
        private List<GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollection> systemPrivilegeCollections;
        private String userName;
        public Builder() {}
        public Builder(GetManagedDatabasesUserSystemPrivilegesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.name = defaults.name;
    	      this.opcNamedCredentialId = defaults.opcNamedCredentialId;
    	      this.systemPrivilegeCollections = defaults.systemPrivilegeCollections;
    	      this.userName = defaults.userName;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedDatabasesUserSystemPrivilegesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedDatabasesUserSystemPrivilegesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            if (managedDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegesResult", "managedDatabaseId");
            }
            this.managedDatabaseId = managedDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder opcNamedCredentialId(@Nullable String opcNamedCredentialId) {

            this.opcNamedCredentialId = opcNamedCredentialId;
            return this;
        }
        @CustomType.Setter
        public Builder systemPrivilegeCollections(List<GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollection> systemPrivilegeCollections) {
            if (systemPrivilegeCollections == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegesResult", "systemPrivilegeCollections");
            }
            this.systemPrivilegeCollections = systemPrivilegeCollections;
            return this;
        }
        public Builder systemPrivilegeCollections(GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollection... systemPrivilegeCollections) {
            return systemPrivilegeCollections(List.of(systemPrivilegeCollections));
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegesResult", "userName");
            }
            this.userName = userName;
            return this;
        }
        public GetManagedDatabasesUserSystemPrivilegesResult build() {
            final var _resultValue = new GetManagedDatabasesUserSystemPrivilegesResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.managedDatabaseId = managedDatabaseId;
            _resultValue.name = name;
            _resultValue.opcNamedCredentialId = opcNamedCredentialId;
            _resultValue.systemPrivilegeCollections = systemPrivilegeCollections;
            _resultValue.userName = userName;
            return _resultValue;
        }
    }
}
