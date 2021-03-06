// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetBackupsBackup;
import com.pulumi.oci.Database.outputs.GetBackupsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBackupsResult {
    /**
     * @return The list of backups.
     * 
     */
    private final List<GetBackupsBackup> backups;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final @Nullable String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    private final @Nullable String databaseId;
    private final @Nullable List<GetBackupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetBackupsResult(
        @CustomType.Parameter("backups") List<GetBackupsBackup> backups,
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("databaseId") @Nullable String databaseId,
        @CustomType.Parameter("filters") @Nullable List<GetBackupsFilter> filters,
        @CustomType.Parameter("id") String id) {
        this.backups = backups;
        this.compartmentId = compartmentId;
        this.databaseId = databaseId;
        this.filters = filters;
        this.id = id;
    }

    /**
     * @return The list of backups.
     * 
     */
    public List<GetBackupsBackup> backups() {
        return this.backups;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    public Optional<String> databaseId() {
        return Optional.ofNullable(this.databaseId);
    }
    public List<GetBackupsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackupsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBackupsBackup> backups;
        private @Nullable String compartmentId;
        private @Nullable String databaseId;
        private @Nullable List<GetBackupsFilter> filters;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBackupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backups = defaults.backups;
    	      this.compartmentId = defaults.compartmentId;
    	      this.databaseId = defaults.databaseId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        public Builder backups(List<GetBackupsBackup> backups) {
            this.backups = Objects.requireNonNull(backups);
            return this;
        }
        public Builder backups(GetBackupsBackup... backups) {
            return backups(List.of(backups));
        }
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder databaseId(@Nullable String databaseId) {
            this.databaseId = databaseId;
            return this;
        }
        public Builder filters(@Nullable List<GetBackupsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBackupsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetBackupsResult build() {
            return new GetBackupsResult(backups, compartmentId, databaseId, filters, id);
        }
    }
}
