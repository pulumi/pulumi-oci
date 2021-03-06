// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseUserObjectPrivilegeItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabaseUserObjectPrivilegeResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return An array of object privileges.
     * 
     */
    private final List<GetManagedDatabaseUserObjectPrivilegeItem> items;
    private final String managedDatabaseId;
    /**
     * @return The name of the privilege on the object.
     * 
     */
    private final @Nullable String name;
    private final String userName;

    @CustomType.Constructor
    private GetManagedDatabaseUserObjectPrivilegeResult(
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("items") List<GetManagedDatabaseUserObjectPrivilegeItem> items,
        @CustomType.Parameter("managedDatabaseId") String managedDatabaseId,
        @CustomType.Parameter("name") @Nullable String name,
        @CustomType.Parameter("userName") String userName) {
        this.id = id;
        this.items = items;
        this.managedDatabaseId = managedDatabaseId;
        this.name = name;
        this.userName = userName;
    }

    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An array of object privileges.
     * 
     */
    public List<GetManagedDatabaseUserObjectPrivilegeItem> items() {
        return this.items;
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
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseUserObjectPrivilegeResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String id;
        private List<GetManagedDatabaseUserObjectPrivilegeItem> items;
        private String managedDatabaseId;
        private @Nullable String name;
        private String userName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabaseUserObjectPrivilegeResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.name = defaults.name;
    	      this.userName = defaults.userName;
        }

        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder items(List<GetManagedDatabaseUserObjectPrivilegeItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagedDatabaseUserObjectPrivilegeItem... items) {
            return items(List.of(items));
        }
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }        public GetManagedDatabaseUserObjectPrivilegeResult build() {
            return new GetManagedDatabaseUserObjectPrivilegeResult(id, items, managedDatabaseId, name, userName);
        }
    }
}
