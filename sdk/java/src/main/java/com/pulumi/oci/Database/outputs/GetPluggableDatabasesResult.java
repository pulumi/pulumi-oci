// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetPluggableDatabasesFilter;
import com.pulumi.oci.Database.outputs.GetPluggableDatabasesPluggableDatabase;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPluggableDatabasesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final @Nullable String compartmentId;
    private final @Nullable String databaseId;
    private final @Nullable List<GetPluggableDatabasesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
     * 
     */
    private final @Nullable String pdbName;
    /**
     * @return The list of pluggable_databases.
     * 
     */
    private final List<GetPluggableDatabasesPluggableDatabase> pluggableDatabases;
    /**
     * @return The current state of the pluggable database.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetPluggableDatabasesResult(
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("databaseId") @Nullable String databaseId,
        @CustomType.Parameter("filters") @Nullable List<GetPluggableDatabasesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("pdbName") @Nullable String pdbName,
        @CustomType.Parameter("pluggableDatabases") List<GetPluggableDatabasesPluggableDatabase> pluggableDatabases,
        @CustomType.Parameter("state") @Nullable String state) {
        this.compartmentId = compartmentId;
        this.databaseId = databaseId;
        this.filters = filters;
        this.id = id;
        this.pdbName = pdbName;
        this.pluggableDatabases = pluggableDatabases;
        this.state = state;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public Optional<String> databaseId() {
        return Optional.ofNullable(this.databaseId);
    }
    public List<GetPluggableDatabasesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
     * 
     */
    public Optional<String> pdbName() {
        return Optional.ofNullable(this.pdbName);
    }
    /**
     * @return The list of pluggable_databases.
     * 
     */
    public List<GetPluggableDatabasesPluggableDatabase> pluggableDatabases() {
        return this.pluggableDatabases;
    }
    /**
     * @return The current state of the pluggable database.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPluggableDatabasesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String databaseId;
        private @Nullable List<GetPluggableDatabasesFilter> filters;
        private String id;
        private @Nullable String pdbName;
        private List<GetPluggableDatabasesPluggableDatabase> pluggableDatabases;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetPluggableDatabasesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.databaseId = defaults.databaseId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.pdbName = defaults.pdbName;
    	      this.pluggableDatabases = defaults.pluggableDatabases;
    	      this.state = defaults.state;
        }

        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder databaseId(@Nullable String databaseId) {
            this.databaseId = databaseId;
            return this;
        }
        public Builder filters(@Nullable List<GetPluggableDatabasesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetPluggableDatabasesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder pdbName(@Nullable String pdbName) {
            this.pdbName = pdbName;
            return this;
        }
        public Builder pluggableDatabases(List<GetPluggableDatabasesPluggableDatabase> pluggableDatabases) {
            this.pluggableDatabases = Objects.requireNonNull(pluggableDatabases);
            return this;
        }
        public Builder pluggableDatabases(GetPluggableDatabasesPluggableDatabase... pluggableDatabases) {
            return pluggableDatabases(List.of(pluggableDatabases));
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetPluggableDatabasesResult build() {
            return new GetPluggableDatabasesResult(compartmentId, databaseId, filters, id, pdbName, pluggableDatabases, state);
        }
    }
}
