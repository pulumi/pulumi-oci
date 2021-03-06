// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseGroupManagedDatabase;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseGroupResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
     * 
     */
    private final String compartmentId;
    /**
     * @return The information specified by the user about the Managed Database Group.
     * 
     */
    private final String description;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    private final String id;
    private final String managedDatabaseGroupId;
    /**
     * @return A list of Managed Databases in the Managed Database Group.
     * 
     */
    private final List<GetManagedDatabaseGroupManagedDatabase> managedDatabases;
    /**
     * @return The name of the Managed Database Group.
     * 
     */
    private final String name;
    /**
     * @return The current lifecycle state of the Managed Database Group.
     * 
     */
    private final String state;
    /**
     * @return The date and time the Managed Database Group was created.
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the Managed Database Group was last updated.
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetManagedDatabaseGroupResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("managedDatabaseGroupId") String managedDatabaseGroupId,
        @CustomType.Parameter("managedDatabases") List<GetManagedDatabaseGroupManagedDatabase> managedDatabases,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.description = description;
        this.id = id;
        this.managedDatabaseGroupId = managedDatabaseGroupId;
        this.managedDatabases = managedDatabases;
        this.name = name;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The information specified by the user about the Managed Database Group.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public String id() {
        return this.id;
    }
    public String managedDatabaseGroupId() {
        return this.managedDatabaseGroupId;
    }
    /**
     * @return A list of Managed Databases in the Managed Database Group.
     * 
     */
    public List<GetManagedDatabaseGroupManagedDatabase> managedDatabases() {
        return this.managedDatabases;
    }
    /**
     * @return The name of the Managed Database Group.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The current lifecycle state of the Managed Database Group.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the Managed Database Group was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the Managed Database Group was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseGroupResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String description;
        private String id;
        private String managedDatabaseGroupId;
        private List<GetManagedDatabaseGroupManagedDatabase> managedDatabases;
        private String name;
        private String state;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabaseGroupResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.managedDatabaseGroupId = defaults.managedDatabaseGroupId;
    	      this.managedDatabases = defaults.managedDatabases;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder managedDatabaseGroupId(String managedDatabaseGroupId) {
            this.managedDatabaseGroupId = Objects.requireNonNull(managedDatabaseGroupId);
            return this;
        }
        public Builder managedDatabases(List<GetManagedDatabaseGroupManagedDatabase> managedDatabases) {
            this.managedDatabases = Objects.requireNonNull(managedDatabases);
            return this;
        }
        public Builder managedDatabases(GetManagedDatabaseGroupManagedDatabase... managedDatabases) {
            return managedDatabases(List.of(managedDatabases));
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetManagedDatabaseGroupResult build() {
            return new GetManagedDatabaseGroupResult(compartmentId, description, id, managedDatabaseGroupId, managedDatabases, name, state, timeCreated, timeUpdated);
        }
    }
}
